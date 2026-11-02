"""Private SQLite cleanup faults; no production database or lock operations."""
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_client import HostClientError, _Reply, request_host
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.store import HostStore, StoreError


PRIVATE = "PRIVATE_CLEANUP_SENTINEL"
EMPTY = 'schema=1\ncomponents=[]\nresources=[]\n'


class ConnectionFault:
    def __init__(self, database, *, close_before=False, close_after=False, persistent=False,
                 rollback=False, uninspectable=False):
        self.database = database
        self.close_before, self.close_after = close_before, close_after
        self.persistent, self.rollback = persistent, rollback
        self.uninspectable = uninspectable
        self.close_calls = 0

    def __getattr__(self, name):
        return getattr(self.database, name)

    @property
    def in_transaction(self):
        if self.uninspectable:
            raise sqlite3.OperationalError(PRIVATE)
        return self.database.in_transaction

    def execute(self, sql, *args):
        if sql == "ROLLBACK" and self.rollback:
            raise sqlite3.OperationalError(PRIVATE)
        return self.database.execute(sql, *args)

    def close(self):
        self.close_calls += 1
        fail = self.close_calls == 1 or self.persistent
        if fail and self.close_before:
            raise OSError(PRIVATE)
        self.database.close()
        if fail and self.close_after:
            raise OSError(PRIVATE)


class StoreCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.host = str(uuid.uuid4())
        self.declaration = load_declaration(EMPTY.encode())

    def create(self, name="store"):
        store = HostStore.create(self.root / name, self.host, owner_uid=os.geteuid())
        self.addCleanup(store.close)
        return store

    def revision(self, store):
        with HostStore.open_readonly(store.directory, self.host, owner_uid=os.geteuid()) as reader:
            return reader.current()["revision"]

    def assert_error(self, code, callback):
        with self.assertRaises(StoreError) as caught:
            callback()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)
        self.assertNotIn(PRIVATE, repr(caught.exception))

    def assert_closed(self, store):
        self.assertTrue(store._closed)
        self.assertIsNone(store._db)
        self.assertIsNone(store._lockfd)
        self.assertIsNone(store._dirfd)
        self.assert_error("store_closed", store.current)

    def unlock_fault(self, store, *, after=False, error=None, observations=None):
        real, descriptor = fcntl.flock, store._lockfd
        error = OSError(PRIVATE) if error is None else error
        database = store._db
        def flock(fd, operation):
            if fd == descriptor and operation == fcntl.LOCK_UN:
                if observations is not None:
                    try:
                        active = database.in_transaction
                    except sqlite3.ProgrammingError:
                        active = False
                    observations.append(active)
                if after:
                    real(fd, operation)
                raise error
            return real(fd, operation)
        return patch("mpkg_manager.store.fcntl.flock", flock)

    def test_successful_commit_with_unlock_failure_is_unknown_and_durable(self):
        for after in (False, True):
            with self.subTest(after=after):
                store = self.create(str(after))
                with self.unlock_fault(store, after=after):
                    self.assert_error("commit_outcome_unknown", lambda:
                                      store.record_intent(self.declaration, 0))
                self.assert_closed(store)
                self.assertEqual(self.revision(store), 1)

    def test_failed_commit_and_close_fault_end_transaction_before_failed_unlock(self):
        for committed in (False, True):
            for after in (False, True):
                with self.subTest(committed=committed, close_after=after):
                    store = self.create(str(committed) + str(after))
                    store._db = ConnectionFault(store._db, close_before=not after, close_after=after)
                    connection, commit = store._db, store._commit
                    observations = []
                    def fail():
                        if committed:
                            commit()
                        raise sqlite3.OperationalError(PRIVATE)
                    with patch.object(store, "_commit", fail), self.unlock_fault(store, observations=observations):
                        self.assert_error("commit_outcome_unknown", lambda:
                                          store.record_intent(self.declaration, 0))
                    self.assertEqual(observations, [False])
                    self.assertGreaterEqual(connection.close_calls, 2)
                    self.assert_closed(store)
                    self.assertEqual(self.revision(store), int(committed))

    def test_commit_cancellation_survives_close_and_unlock_failures(self):
        for kind in (KeyboardInterrupt, SystemExit):
            for committed in (False, True):
                with self.subTest(kind=kind, committed=committed):
                    store = self.create(kind.__name__ + str(committed))
                    store._db = ConnectionFault(store._db, close_before=True)
                    failure, commit, observations = kind(PRIVATE), store._commit, []
                    def interrupt():
                        if committed:
                            commit()
                        raise failure
                    with patch.object(store, "_commit", interrupt), self.unlock_fault(store, observations=observations):
                        with self.assertRaises(kind) as caught:
                            store.record_intent(self.declaration, 0)
                    self.assertIs(caught.exception, failure)
                    self.assertEqual(observations, [False])
                    self.assert_closed(store)
                    self.assertEqual(self.revision(store), int(committed))

    def test_cancellation_during_successful_commit_unlock_remains_cancellation(self):
        store = self.create()
        failure = KeyboardInterrupt(PRIVATE)
        with self.unlock_fault(store, error=failure):
            with self.assertRaises(KeyboardInterrupt) as caught:
                store.record_intent(self.declaration, 0)
        self.assertIs(caught.exception, failure)
        self.assert_closed(store)
        self.assertEqual(self.revision(store), 1)

    def test_persistent_transaction_cleanup_failure_retains_manager_lock(self):
        store = self.create()
        connection = ConnectionFault(store._db, close_before=True, persistent=True, rollback=True)
        store._db = connection
        descriptor, real_flock, unlocked = store._lockfd, fcntl.flock, []
        def flock(fd, operation):
            if fd == descriptor and operation == fcntl.LOCK_UN:
                unlocked.append(True)
            return real_flock(fd, operation)
        try:
            with patch.object(store, "_commit", side_effect=sqlite3.OperationalError(PRIVATE)), \
                    patch("mpkg_manager.store.fcntl.flock", flock):
                self.assert_error("commit_outcome_unknown", lambda:
                                  store.record_intent(self.declaration, 0))
            self.assertEqual(unlocked, [])
            self.assertTrue(store._closed)
            self.assertTrue(connection.in_transaction)
            self.assertEqual(store._lockfd, descriptor)
            self.assert_error("store_closed", store.current)
            self.assert_error("store_busy", lambda: HostStore.open_readonly(
                store.directory, self.host, owner_uid=os.geteuid()))
        finally:
            connection.close_before = connection.rollback = False
            store.close()
        self.assert_closed(store)
        self.assertEqual(self.revision(store), 0)

    def test_precommit_failure_and_failed_unlock_remain_known_no_commit(self):
        store = self.create()
        save = store._save_snapshot
        def fail(declaration):
            save(declaration)
            raise OSError(PRIVATE)
        with patch.object(store, "_save_snapshot", fail), patch.object(store, "_commit") as commit, \
                self.unlock_fault(store):
            self.assert_error("store_write_failed", lambda: store.record_intent(self.declaration, 0))
        commit.assert_not_called()
        self.assert_closed(store)
        self.assertEqual(self.revision(store), 0)

    def test_uninspectable_transaction_also_retains_lock_until_cleanup(self):
        store = self.create()
        connection = ConnectionFault(store._db, close_before=True, persistent=True, uninspectable=True)
        store._db = connection
        descriptor, real_flock, unlocked = store._lockfd, fcntl.flock, []
        def flock(fd, operation):
            if fd == descriptor and operation == fcntl.LOCK_UN:
                unlocked.append(True)
            return real_flock(fd, operation)
        try:
            with patch.object(store, "_commit", side_effect=sqlite3.OperationalError(PRIVATE)), \
                    patch("mpkg_manager.store.fcntl.flock", flock):
                self.assert_error("commit_outcome_unknown", lambda:
                                  store.record_intent(self.declaration, 0))
            self.assertEqual(unlocked, [])
            self.assertTrue(connection.database.in_transaction)
            self.assertTrue(store._closed)
            self.assertEqual(store._lockfd, descriptor)
            self.assert_error("store_busy", lambda: HostStore.open_readonly(
                store.directory, self.host, owner_uid=os.geteuid()))
        finally:
            connection.close_before = connection.uninspectable = False
            store.close()
        self.assert_closed(store)
        self.assertEqual(self.revision(store), 0)

    def test_failed_precommit_rollback_closes_before_unlock_without_commit_uncertainty(self):
        store = self.create()
        store._db = ConnectionFault(store._db, rollback=True)
        observations = []
        with patch.object(store, "_save_snapshot", side_effect=OSError(PRIVATE)), \
                patch.object(store, "_commit") as commit, self.unlock_fault(store, observations=observations):
            self.assert_error("store_write_failed", lambda: store.record_intent(self.declaration, 0))
        commit.assert_not_called()
        self.assertEqual(observations, [False])
        self.assert_closed(store)
        self.assertEqual(self.revision(store), 0)

    def test_precommit_cancellation_survives_rollback_close_and_unlock_faults(self):
        store = self.create()
        store._db = ConnectionFault(store._db, rollback=True, close_before=True)
        failure, observations = SystemExit(PRIVATE), []
        with patch.object(store, "_save_snapshot", side_effect=failure), \
                self.unlock_fault(store, observations=observations):
            with self.assertRaises(SystemExit) as caught:
                store.record_intent(self.declaration, 0)
        self.assertIs(caught.exception, failure)
        self.assertEqual(observations, [False])
        self.assert_closed(store)
        self.assertEqual(self.revision(store), 0)

    def test_pre_yield_cancellation_survives_unlock_failure(self):
        store = self.create()
        failure = KeyboardInterrupt(PRIVATE)
        with patch("mpkg_manager.store._directory", side_effect=failure), self.unlock_fault(store):
            with self.assertRaises(KeyboardInterrupt) as caught:
                store.record_intent(self.declaration, 0)
        self.assertIs(caught.exception, failure)
        self.assert_closed(store)
        self.assertEqual(self.revision(store), 0)

    def test_read_failure_is_preserved_when_unlock_also_fails(self):
        store = self.create()
        with patch.object(store, "_verify_schema", side_effect=StoreError("store_corrupt")), self.unlock_fault(store):
            self.assert_error("store_corrupt", store.current)
        self.assert_closed(store)
        self.assertEqual(self.revision(store), 0)

    def test_successful_read_unlock_failure_closes_handle_without_changing_history(self):
        store = self.create()
        before = (store.directory / "state.sqlite3").read_bytes()
        with self.unlock_fault(store):
            self.assert_error("store_read_failed", store.current)
        self.assert_closed(store)
        self.assertEqual((store.directory / "state.sqlite3").read_bytes(), before)

    def test_close_attempts_all_descriptors_and_never_recloses_reused_number(self):
        store = self.create()
        descriptor, directory, real_close = store._lockfd, store._dirfd, os.close
        replacement = os.open("/dev/null", os.O_RDONLY)
        calls = []
        def fail(fd):
            calls.append(fd)
            real_close(fd)
            if fd == descriptor:
                os.dup2(replacement, descriptor)
                raise OSError(PRIVATE)
        try:
            with patch("mpkg_manager.store.os.close", fail):
                self.assert_error("store_close_failed", store.close)
            self.assertIn(directory, calls)
            self.assert_closed(store)
            store.close()
            os.fstat(descriptor)
        finally:
            real_close(descriptor)
            real_close(replacement)

    def test_close_database_fault_still_attempts_descriptor_cleanup_and_is_idempotent(self):
        for after in (False, True):
            with self.subTest(after=after):
                store = self.create(str(after))
                store._db = ConnectionFault(store._db, close_before=not after, close_after=after)
                self.assert_error("store_close_failed", store.close)
                self.assert_closed(store)
                store.close()

    def test_context_cleanup_does_not_mask_body_exception_or_cancellation(self):
        for kind in (ValueError, KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind):
                store = self.create(kind.__name__)
                failure = kind(PRIVATE)
                store._db = ConnectionFault(store._db, close_before=True)
                with self.assertRaises(kind) as caught:
                    with store:
                        raise failure
                self.assertIs(caught.exception, failure)
                self.assert_closed(store)

    def test_successful_body_close_failure_does_not_mean_rollback(self):
        store = self.create()
        with self.assertRaises(StoreError) as caught:
            with store:
                result = store.record_intent(self.declaration, 0)
                store._db = ConnectionFault(store._db, close_after=True)
        self.assertEqual(caught.exception.code, "store_close_failed")
        self.assertEqual(result["revision"], 1)
        self.assert_closed(store)
        self.assertEqual(self.revision(store), 1)

    def test_open_and_existing_create_errors_survive_cleanup_faults(self):
        store = self.create()
        close = HostStore.close
        def fail(handle):
            close(handle)
            raise OSError(PRIVATE)
        with patch.object(HostStore, "close", fail):
            self.assert_error("store_exists", lambda: HostStore.create(
                store.directory, self.host, owner_uid=os.geteuid()))
            with patch.object(HostStore, "_verify_schema", side_effect=StoreError("store_corrupt")):
                self.assert_error("store_corrupt", lambda: HostStore.open_readonly(
                    store.directory, self.host, owner_uid=os.geteuid()))

    def boundary(self, store):
        policy = self.root / "policy.toml"
        policy.write_text(f'schema=1\nhost_id="{self.host}"\nengine_aliases={{}}\n'
                          f'allowed_input_roots={json.dumps([str(self.root)])}\n')
        policy.chmod(0o600)
        runtime = self.root / "run"
        runtime.mkdir(mode=0o700)
        lock = runtime / "apply.lock"
        lock.touch(mode=0o600)
        return HostBoundary(policy_path=policy, store_directory=store.directory,
                            mutation_lock=lock, owner_uid=os.geteuid())

    def test_request_final_close_failure_after_saved_record_is_uncertain(self):
        store = self.create()
        boundary = self.boundary(store)
        store.close()
        raw = json.dumps({"version": 1, "verb": "record", "arguments": {
            "operation": "intent", "expected_revision": 0, "source": EMPTY,
            "source_is_nonsecret": True}}).encode()
        close = HostStore._close_database
        def fail(handle):
            owned = handle._db is not None
            close(handle)
            if owned:
                raise OSError(PRIVATE)
        replies = []
        def sender(value):
            reply = handle_request(value, boundary=boundary)
            replies.append(reply)
            return _Reply(reply, 2)
        with patch.object(HostStore, "_close_database", fail):
            with self.assertRaises(HostClientError) as caught:
                request_host(raw, _sender=sender)
        self.assertEqual((caught.exception.code, caught.exception.category, caught.exception.exit_status),
                         ("record_outcome_unknown", "uncertain", 7))
        self.assertEqual(len(replies), 1)
        self.assertNotIn(PRIVATE.encode(), replies[0])
        self.assertEqual(self.revision(store), 1)

    def test_request_final_read_close_failure_is_internal_not_a_record_rejection(self):
        store = self.create()
        boundary = self.boundary(store)
        store.close()
        raw = json.dumps({"version": 1, "verb": "export", "arguments": {"operation": "current"}}).encode()
        close = HostStore._close_database
        def fail(handle):
            owned = handle._db is not None
            close(handle)
            if owned:
                raise OSError(PRIVATE)
        with patch.object(HostStore, "_close_database", fail):
            result = json.loads(handle_request(raw, boundary=boundary))
        self.assertEqual(result["error"]["code"], "internal_error")
        self.assertEqual(self.revision(store), 0)


if __name__ == "__main__":
    unittest.main()
