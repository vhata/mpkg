"""Read cleanup fault injection around real private SQLite transactions."""
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
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.store import HostStore, StoreError


PRIVATE = "PRIVATE_READ_CLEANUP_SENTINEL"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


class ReadFaults:
    def __init__(self, database, *, rollback=True, close_failures=0,
                 uninspectable=False, begin_after=False, rollback_error=None):
        self.database = database
        self.rollback = rollback
        self.close_failures = close_failures
        self.uninspectable = uninspectable
        self.begin_after = begin_after
        self.rollback_error = rollback_error
        self.close_calls = self.rollback_calls = 0

    def __getattr__(self, name):
        return getattr(self.database, name)

    @property
    def in_transaction(self):
        if self.uninspectable:
            raise sqlite3.OperationalError(PRIVATE)
        return self.database.in_transaction

    def execute(self, statement, *args):
        if statement == "ROLLBACK":
            self.rollback_calls += 1
            if self.rollback:
                raise self.rollback_error or sqlite3.OperationalError(PRIVATE)
        result = self.database.execute(statement, *args)
        if statement == "BEGIN" and self.begin_after:
            raise sqlite3.OperationalError(PRIVATE)
        return result

    def close(self):
        self.close_calls += 1
        if self.close_failures is None or self.close_calls <= self.close_failures:
            raise OSError(PRIVATE)
        self.database.close()

    def recover(self):
        self.rollback = self.uninspectable = self.begin_after = False
        self.close_failures = 0


class ReadCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.host = str(uuid.uuid4())
        self.path = self.root / "store"
        with HostStore.create(self.path, self.host, owner_uid=os.geteuid()) as store:
            store.record_intent(EMPTY, 0)
        self.before = (self.path / "state.sqlite3").read_bytes()

    def reader(self, **faults):
        store = HostStore.open_readonly(self.path, self.host, owner_uid=os.geteuid())
        fault = ReadFaults(store._db, **faults)
        store._db = fault
        self.addCleanup(store.close)
        self.addCleanup(fault.recover)
        return store, fault

    def observed_unlock(self, store, fault, *, failure=None):
        descriptor, real, observed = store._lockfd, fcntl.flock, []
        def flock(fd, operation):
            if fd == descriptor and operation == fcntl.LOCK_UN:
                try:
                    active = fault.database.in_transaction
                except sqlite3.ProgrammingError:
                    active = False
                observed.append(active)
                if failure is not None:
                    raise failure
            return real(fd, operation)
        return observed, patch("mpkg_manager.store.fcntl.flock", flock)

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

    def unchanged(self):
        self.assertEqual((self.path / "state.sqlite3").read_bytes(), self.before)
        with HostStore.open_readonly(self.path, self.host, owner_uid=os.geteuid()) as store:
            self.assertEqual(store.current()["revision"], 1)

    def test_schema_cancellation_survives_rollback_and_initial_close_failure(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(kind=kind):
                store, fault = self.reader(close_failures=1)
                original = kind(PRIVATE)
                observed, spy = self.observed_unlock(store, fault)
                with patch.object(store, "_verify_schema", side_effect=original), spy:
                    with self.assertRaises(kind) as caught:
                        store.current()
                self.assertIs(caught.exception, original)
                self.assertEqual(observed, [False])
                self.assertGreaterEqual(fault.close_calls, 2)
                self.assert_closed(store)
        self.unchanged()

    def test_body_cancellation_keeps_identity_through_rollback_close_and_unlock_errors(self):
        store, fault = self.reader(close_failures=1)
        original = KeyboardInterrupt(PRIVATE)
        observed, spy = self.observed_unlock(store, fault, failure=OSError(PRIVATE))
        with spy:
            with self.assertRaises(KeyboardInterrupt) as caught:
                with store._read():
                    raise original
        self.assertIs(caught.exception, original)
        self.assertEqual(observed, [False])
        self.assert_closed(store)
        self.unchanged()

    def test_original_store_error_survives_failed_read_cleanup(self):
        store, fault = self.reader(close_failures=1)
        original = StoreError("store_corrupt")
        with patch.object(store, "_verify_schema", side_effect=original):
            with self.assertRaises(StoreError) as caught:
                store.current()
        self.assertIs(caught.exception, original)
        self.assert_closed(store)
        self.unchanged()

    def test_ordinary_read_failure_remains_fixed_read_error_without_commit_uncertainty(self):
        store, fault = self.reader(close_failures=1)
        observed, spy = self.observed_unlock(store, fault)
        with patch.object(store, "_verify_schema", side_effect=sqlite3.OperationalError(PRIVATE)), spy:
            self.assert_error("store_read_failed", store.current)
        self.assertEqual(observed, [False])
        self.assert_closed(store)
        self.unchanged()

    def test_successful_read_with_failed_final_rollback_refuses_result_and_closes(self):
        store, fault = self.reader()
        observed, spy = self.observed_unlock(store, fault)
        with spy:
            self.assert_error("store_read_failed", store.current)
        self.assertEqual(observed, [False])
        self.assert_closed(store)
        self.unchanged()

    def test_rollback_cancellation_after_successful_read_is_preserved(self):
        original = SystemExit(PRIVATE)
        store, fault = self.reader(rollback_error=original)
        observed, spy = self.observed_unlock(store, fault)
        with spy:
            with self.assertRaises(SystemExit) as caught:
                store.current()
        self.assertIs(caught.exception, original)
        self.assertEqual(observed, [False])
        self.assert_closed(store)
        self.unchanged()

    def test_begin_failure_after_opening_transaction_rolls_back_before_unlock(self):
        store, fault = self.reader(rollback=False, begin_after=True)
        observed, spy = self.observed_unlock(store, fault)
        with spy:
            self.assert_error("store_read_failed", store.current)
        self.assertEqual(observed, [False])
        self.assertEqual(fault.rollback_calls, 1)
        self.assertFalse(store._closed)
        fault.recover()
        self.assertEqual(store.current()["revision"], 1)
        store.close()
        self.unchanged()

    def test_transaction_inspection_failure_poisons_and_closes_under_lock(self):
        store, fault = self.reader(uninspectable=True)
        observed, spy = self.observed_unlock(store, fault)
        with spy:
            self.assert_error("store_read_failed", store.current)
        self.assertEqual(observed, [False])
        self.assert_closed(store)
        self.unchanged()

    def test_persistent_live_or_uninspectable_transaction_keeps_lock_until_explicit_close(self):
        for uninspectable in (False, True):
            with self.subTest(uninspectable=uninspectable):
                store, fault = self.reader(close_failures=None, uninspectable=uninspectable)
                original = KeyboardInterrupt(PRIVATE)
                observed, spy = self.observed_unlock(store, fault)
                with patch.object(store, "_verify_schema", side_effect=original), spy:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        store.current()
                self.assertIs(caught.exception, original)
                self.assertEqual(observed, [])
                self.assertTrue(fault.database.in_transaction)
                self.assertTrue(store._closed)
                self.assertIsNotNone(store._lockfd)
                self.assert_error("store_closed", store.current)
                with open(self.path / "state.lock", "rb") as competing:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(competing.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with HostStore.open_readonly(self.path, self.host, owner_uid=os.geteuid()) as reader:
                    self.assertEqual(reader.current()["revision"], 1)
                fault.recover()
                store.close()
                self.assert_closed(store)
                with open(self.path / "state.lock", "rb") as competing:
                    fcntl.flock(competing.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.unchanged()

    def test_clean_rollback_preserves_usable_handle_after_original_failure(self):
        store, fault = self.reader(rollback=False)
        original = KeyboardInterrupt(PRIVATE)
        with patch.object(store, "_verify_schema", side_effect=original):
            with self.assertRaises(KeyboardInterrupt) as caught:
                store.current()
        self.assertIs(caught.exception, original)
        self.assertFalse(store._closed)
        self.assertFalse(fault.database.in_transaction)
        self.assertEqual(store.current()["revision"], 1)
        store.close()
        self.unchanged()

    def test_helper_export_rollback_error_is_redacted_read_failure_with_unchanged_history(self):
        policy = self.root / "policy.toml"
        policy.write_text(f'schema=1\nhost_id="{self.host}"\nengine_aliases={{}}\n'
                          f'allowed_input_roots={json.dumps([str(self.root)])}\n')
        policy.chmod(0o600)
        boundary = HostBoundary(policy_path=policy, store_directory=self.path,
                                mutation_lock=self.root / "unused.lock", owner_uid=os.geteuid())
        original, opened = HostStore.open_readonly, []
        def open_fault(*args, **kwargs):
            store = original(*args, **kwargs)
            store._db = ReadFaults(store._db)
            opened.append(store)
            return store
        raw = json.dumps({"version": 1, "verb": "export", "arguments": {"operation": "current"}}).encode()
        with patch.object(HostStore, "open_readonly", side_effect=open_fault):
            response = handle_request(raw, boundary=boundary)
        self.assertEqual(json.loads(response), {"version": 1, "ok": False,
                                               "error": {"code": "store_read_failed"}})
        self.assertNotIn(PRIVATE.encode(), response)
        self.assertNotIn(str(self.root).encode(), response)
        self.assertEqual(len(opened), 1)
        self.assert_closed(opened[0])
        self.unchanged()


if __name__ == "__main__":
    unittest.main()
