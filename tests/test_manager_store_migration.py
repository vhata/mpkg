"""Explicit schema maintenance on private databases; no host migration runs."""
from dataclasses import FrozenInstanceError
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_client import HostClientError, _Reply, request_host
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.store import HostStore, ProtectedInput, SCHEMA_VERSION, StoreError, _TRIGGERS, _json
from mpkg_manager import store_migration as migration


HOST = "12345678-1234-4234-8234-123456789abc"
OTHER = "23456789-1234-4234-8234-123456789abc"
PRIVATE = "PRIVATE_MIGRATION_SENTINEL"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")
PACKAGE = load_declaration(b'''schema=1
components=[]
[[resources]]
id="package"
kind="package"
identity={name="git"}
manage=["present"]
desired={present=true}
''')


class MigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.backup = self.root / "backup"
        self.owner = os.geteuid()

    def legacy(self, *, directory=None, host=HOST, retained=False):
        directory = self.source if directory is None else directory
        with patch("mpkg_manager.store.SCHEMA_VERSION", 1):
            with HostStore.create(directory, host, owner_uid=self.owner) as store:
                if retained:
                    raw = PRIVATE.encode()
                    identity = {"path": "/private/input", "device": 1, "inode": 2, "size": len(raw),
                                "mtime_ns": 3, "uid": self.owner, "gid": os.getegid(),
                                "mode": stat.S_IFREG | 0o600, "links": 1}
                    capture = ProtectedInput("capture", raw, identity, "private configuration")
                    store.adopt(PACKAGE, 0, ["package"], protected_inputs=[capture])
                    stable = store.current()["resources"][0]["stable_id"]
                    store.record_intent(EMPTY, 1)
                    store.relinquish([stable], 2)
                else:
                    store.record_intent(EMPTY, 0)

    def read(self, directory=None, *, host=HOST):
        with HostStore.open_readonly(self.source if directory is None else directory,
                                     host, owner_uid=self.owner) as store:
            return store._schema_version, store.current(), store.history()

    def migrate(self, revision=1, **kwargs):
        return migration.migrate_store(self.source, HOST, expected_revision=revision,
                                        backup_directory=kwargs.pop("backup_directory", self.backup),
                                        owner_uid=self.owner, **kwargs)

    def assert_error(self, code, callback, exception=(migration.MigrationError, StoreError)):
        with self.assertRaises(exception) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)
        self.assertNotIn(PRIVATE, str(raised.exception))
        self.assertNotIn(str(self.root), repr(raised.exception))

    def corrupt(self, directory, table, statement, parameters=()):
        with sqlite3.connect(directory / "state.sqlite3") as db:
            for operation in ("update", "delete"):
                db.execute("DROP TRIGGER " + table + "_" + operation)
            db.execute(statement, parameters)
            for operation in ("update", "delete"):
                db.execute(_TRIGGERS[table + "_" + operation])

    def test_new_stores_have_a_sealed_creation_receipt(self):
        with HostStore.create(self.source, HOST, owner_uid=self.owner) as store:
            self.assertEqual(store._schema_version, SCHEMA_VERSION)
            row = store._db.execute("SELECT kind,from_version,to_version,revision,backup,length(seal) "
                                    "FROM schema_migrations").fetchone()
            self.assertEqual(row, ("created", 0, SCHEMA_VERSION, 0, None, 32))
            store.record_intent(EMPTY, 0)
            self.assertEqual(store._db.execute("SELECT count(*) FROM schema_migrations").fetchone(), (1,))

    def test_creation_receipt_omission_and_changed_private_key_are_corrupt(self):
        with HostStore.create(self.source, HOST, owner_uid=self.owner) as store:
            original = store._db.execute("SELECT * FROM schema_migrations").fetchone()
        self.corrupt(self.source, "schema_migrations", "DELETE FROM schema_migrations")
        self.assert_error("store_corrupt", self.read)
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            db.execute("INSERT INTO schema_migrations VALUES(?,?,?,?,?,?,?,?)", original)
        self.corrupt(self.source, "host", "UPDATE host SET private_key=?", (b"x" * 32,))
        self.assert_error("store_corrupt", self.read)

    def test_schema_history_distinguishes_missing_legacy_evidence_and_redacts_receipts(self):
        self.legacy(retained=True)
        with HostStore.open_readonly(self.source, HOST, owner_uid=self.owner) as store:
            self.assertEqual(store.schema_history(), {"schema_version": 1,
                              "receipt_evidence": "unavailable", "receipts": []})
        receipt = self.migrate(3)
        manifest = json.loads((self.backup / "backup.json").read_bytes())
        with HostStore.open_readonly(self.source, HOST, owner_uid=self.owner) as store:
            projection = store.schema_history()
            self.assertEqual((projection["schema_version"], projection["receipt_evidence"]), (2, "verified"))
            row = projection["receipts"][0]
            self.assertEqual((row["kind"], row["migration_id"], row["backup_id"], row["revision"]),
                             ("migrated", receipt.migration_id, receipt.backup_id, 3))
            public = json.dumps(projection)
            for private in (PRIVATE, str(self.root), manifest["logical_sha256"], manifest["database_sha256"]):
                self.assertNotIn(private, public)
            row["revision"] = 99
            self.assertEqual(store.schema_history()["receipts"][0]["revision"], 3)

    def test_v1_history_remains_readonly_and_ordinary_writes_require_migration(self):
        self.legacy(retained=True)
        before = (self.source / "state.sqlite3").read_bytes()
        version, current, history = self.read()
        self.assertEqual((version, current["revision"], len(history)), (1, 3, 3))
        self.assertEqual(current["resources"][0]["management"], "relinquished")
        self.assert_error("store_migration_required", lambda: HostStore.open_existing(
            self.source, HOST, owner_uid=self.owner))
        self.assertEqual((self.source / "state.sqlite3").read_bytes(), before)
        self.assertFalse(self.backup.exists())

    def test_migration_preserves_history_captures_key_and_a_readable_v1_backup(self):
        self.legacy(retained=True)
        before = self.read()
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            key = db.execute("SELECT private_key FROM host").fetchone()[0]
        receipt = self.migrate(3)
        after = self.read()
        self.assertEqual(after[0], 2)
        self.assertEqual(after[1:], before[1:])
        self.assertEqual(self.read(self.backup), before)
        self.assert_error("store_migration_required", lambda: HostStore.open_existing(
            self.source, HOST, owner_uid=self.owner))
        migration.migrate_store_to_v3(self.source, HOST, expected_revision=3,
            backup_directory=self.root / "v2-backup", owner_uid=self.owner)
        migration.migrate_store_to_v4(self.source, HOST, expected_revision=3,
            backup_directory=self.root / "v3-backup", owner_uid=self.owner)
        migration.migrate_store_to_v5(self.source, HOST, expected_revision=3,
            backup_directory=self.root / "v4-backup", owner_uid=self.owner)
        with HostStore.open_existing(self.source, HOST, owner_uid=self.owner) as store:
            self.assertEqual(store._db.execute("SELECT private_key FROM host").fetchone()[0], key)
            self.assertEqual(store._db.execute("SELECT raw FROM protected_inputs").fetchone()[0], PRIVATE.encode())
            self.assertEqual(store.record_intent(EMPTY, 3)["revision"], 4)
        self.assertEqual(self.read(self.backup)[1]["revision"], 3)
        self.assertEqual(receipt.as_dict()["revision"], 3)

    def test_backup_permissions_manifest_and_public_receipt_are_private(self):
        self.legacy(retained=True)
        receipt = self.migrate(3)
        self.assertEqual(stat.S_IMODE(self.backup.stat().st_mode), 0o700)
        for path in self.backup.iterdir():
            self.assertEqual((stat.S_IMODE(path.stat().st_mode), path.stat().st_uid, path.stat().st_nlink),
                             (0o600, self.owner, 1))
        manifest = json.loads((self.backup / "backup.json").read_bytes())
        digest = hashlib.sha256((self.backup / "state.sqlite3").read_bytes()).hexdigest()
        self.assertEqual(manifest["database_sha256"], digest)
        self.assertEqual(manifest["backup_id"], receipt.backup_id)
        public = repr(receipt) + json.dumps(receipt.as_dict())
        for private in (PRIVATE, str(self.root), digest, manifest["logical_sha256"]):
            self.assertNotIn(private, public)
        with self.assertRaises(FrozenInstanceError):
            receipt.revision = 7
        result = receipt.as_dict()
        result["revision"] = 7
        self.assertEqual(receipt.as_dict()["revision"], 3)

    def test_writer_lock_covers_backup_verification_through_schema_commit(self):
        self.legacy()
        observed = []
        capture, upgrade = migration._Backup.capture, migration._upgrade
        def blocked(stage):
            with sqlite3.connect(self.source / "state.sqlite3", timeout=0) as other:
                with self.assertRaises(sqlite3.OperationalError):
                    other.execute("BEGIN IMMEDIATE")
            self.assert_error("store_busy", lambda: HostStore.open_readonly(
                self.source, HOST, owner_uid=self.owner))
            observed.append(stage)
        def during_capture(backup, store, revision):
            blocked("backup")
            return capture(backup, store, revision)
        def during_upgrade(store, revision, backup):
            blocked("upgrade")
            return upgrade(store, revision, backup)
        with patch.object(migration._Backup, "capture", during_capture), \
                patch.object(migration, "_upgrade", during_upgrade):
            self.migrate()
        self.assertEqual(observed, ["backup", "upgrade"])

    def test_existing_backup_destinations_are_never_changed(self):
        self.legacy()
        existing = self.root / "existing"
        existing.mkdir(mode=0o700)
        sentinel = existing / "sentinel"
        sentinel.write_text(PRIVATE)
        for destination in (existing, sentinel):
            self.assert_error("backup_destination_exists", lambda: self.migrate(backup_directory=destination))
        link = self.root / "link"
        link.symlink_to(existing, target_is_directory=True)
        self.assert_error("backup_destination_exists", lambda: self.migrate(backup_directory=link))
        self.assertEqual(sentinel.read_text(), PRIVATE)
        self.assertEqual(self.read()[0], 1)

    def test_stale_revision_and_repeated_upgrade_create_no_backup(self):
        self.legacy()
        self.assert_error("revision_conflict", lambda: self.migrate(0))
        self.assertFalse(self.backup.exists())
        self.migrate()
        self.assert_error("migration_not_required", lambda: self.migrate(backup_directory=self.root / "second"))
        self.assertFalse((self.root / "second").exists())

    def test_invalid_requests_and_unsafe_destinations_fail_before_upgrade(self):
        self.legacy()
        for revision in (True, -1, 2**63, "1"):
            self.assert_error("invalid_migration_request", lambda: self.migrate(revision))
        for destination in (self.source, self.source / "nested"):
            self.assert_error("invalid_backup_path", lambda: self.migrate(backup_directory=destination))
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        self.assert_error("unsafe_store_ancestor", lambda: self.migrate(backup_directory=unsafe / "backup"))
        self.assertEqual(self.read()[0], 1)

    def test_unknown_schema_and_sidefiles_refuse_without_backup_or_repair(self):
        self.legacy()
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            db.execute("PRAGMA user_version=99")
        self.assert_error("store_schema_unsupported", self.migrate)
        self.assertFalse(self.backup.exists())
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            db.execute("PRAGMA user_version=1")
        sidefile = self.source / "state.sqlite3-journal"
        sidefile.write_text(PRIVATE)
        self.assert_error("store_recovery_required", self.migrate)
        self.assertEqual(sidefile.read_text(), PRIVATE)
        self.assertFalse(self.backup.exists())

    def test_backup_size_and_elapsed_limits_preserve_legacy_source(self):
        self.legacy()
        with patch.object(migration, "MAX_BACKUP_BYTES", 1):
            self.assert_error("backup_size_limit", self.migrate)
        self.assertEqual(self.read()[0], 1)
        with patch.object(migration.time, "monotonic", side_effect=[0, 61]):
            self.assert_error("backup_timeout", lambda: self.migrate(backup_directory=self.root / "timed"))
        self.assertEqual(self.read()[0], 1)

    def test_failed_logical_backup_comparison_prevents_upgrade(self):
        self.legacy()
        original, calls = migration._logical_digest, 0
        def mismatch(db):
            nonlocal calls
            calls += 1
            value = original(db)
            return "0" * 64 if calls == 3 else value
        with patch.object(migration, "_logical_digest", mismatch):
            self.assert_error("backup_verification_failed", self.migrate)
        self.assertEqual(self.read()[0], 1)
        self.assertTrue((self.backup / "state.sqlite3").exists())
        self.assertFalse((self.backup / "backup.json").exists())

    def test_busy_and_wrong_host_requests_create_no_backup(self):
        self.legacy()
        self.assert_error("store_host_mismatch", lambda: migration.migrate_store(
            self.source, OTHER, expected_revision=1, backup_directory=self.backup, owner_uid=self.owner))
        with HostStore.open_readonly(self.source, HOST, owner_uid=self.owner) as store, store._locked():
            self.assert_error("store_busy", self.migrate)
        self.assertFalse(self.backup.exists())

    def test_every_explicit_fsync_failure_before_upgrade_preserves_v1(self):
        self.legacy()
        real = os.fsync
        for fail_at in range(1, 9):
            calls = 0
            def fail(fd):
                nonlocal calls
                calls += 1
                if calls == fail_at:
                    raise OSError(PRIVATE)
                return real(fd)
            with self.subTest(boundary=fail_at), patch.object(migration.os, "fsync", fail):
                self.assert_error("migration_failed", lambda: self.migrate(
                    backup_directory=self.root / ("backup-" + str(fail_at))))
            self.assertEqual(self.read()[0], 1)

    def test_post_commit_fsync_failure_is_uncertain_with_backup_retained(self):
        self.legacy()
        real, calls = os.fsync, 0
        def fail(fd):
            nonlocal calls
            calls += 1
            if calls == 9:
                raise OSError(PRIVATE)
            return real(fd)
        with patch.object(migration.os, "fsync", fail):
            self.assert_error("migration_outcome_unknown", self.migrate)
        self.assertEqual((self.read()[0], self.read(self.backup)[0]), (2, 1))

    def test_schema_write_failure_rolls_back_but_keeps_verified_backup(self):
        self.legacy()
        real = migration._upgrade
        def fail(*args):
            real(*args)
            raise sqlite3.OperationalError(PRIVATE)
        with patch.object(migration, "_upgrade", fail):
            self.assert_error("migration_failed", self.migrate)
        self.assertEqual(self.read(), self.read(self.backup))
        self.assertEqual(self.read()[0], 1)

    def test_commit_failures_before_and_after_completion_never_claim_rollback(self):
        self.legacy()
        commit = HostStore._commit
        with patch.object(HostStore, "_commit", side_effect=OSError(PRIVATE)):
            self.assert_error("migration_outcome_unknown", self.migrate)
        self.assertEqual(self.read()[0], 1)
        def after(store):
            commit(store)
            raise OSError(PRIVATE)
        with patch.object(HostStore, "_commit", after):
            self.assert_error("migration_outcome_unknown", lambda: self.migrate(
                backup_directory=self.root / "after-commit"))
        self.assertEqual(self.read()[0], 2)
        self.assertEqual(self.read(self.root / "after-commit")[0], 1)

    def test_cancellation_preserves_interrupt_and_releases_locks(self):
        self.legacy()
        with patch.object(migration, "_upgrade", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.migrate()
        self.assertEqual(self.read()[0], 1)
        commit = HostStore._commit
        def after(store):
            commit(store)
            raise KeyboardInterrupt
        with patch.object(HostStore, "_commit", after), self.assertRaises(KeyboardInterrupt):
            self.migrate(backup_directory=self.root / "cancelled-after")
        self.assertEqual(self.read()[0], 2)

    def test_post_commit_unlock_and_close_failures_are_uncertain(self):
        for boundary in ("unlock", "close"):
            with self.subTest(boundary=boundary):
                source, backup = self.root / (boundary + "-source"), self.root / (boundary + "-backup")
                self.legacy(directory=source)
                committed = False
                commit, flock, close = HostStore._commit, fcntl.flock, HostStore.close
                def after_commit(store):
                    nonlocal committed
                    commit(store)
                    committed = True
                def fail_unlock(fd, operation):
                    flock(fd, operation)
                    if committed and operation == fcntl.LOCK_UN:
                        raise OSError(PRIVATE)
                def fail_close(store):
                    close(store)
                    if committed:
                        raise OSError(PRIVATE)
                with patch.object(HostStore, "_commit", after_commit), \
                        patch.object(fcntl, "flock", fail_unlock if boundary == "unlock" else flock), \
                        patch.object(HostStore, "close", fail_close if boundary == "close" else close):
                    self.assert_error("migration_outcome_unknown", lambda: migration.migrate_store(
                        source, HOST, expected_revision=1, backup_directory=backup, owner_uid=self.owner))
                self.assertEqual((self.read(source)[0], self.read(backup)[0]), (2, 1))

    def test_backup_bytes_or_identity_changed_after_capture_prevent_commit(self):
        self.legacy()
        original = migration._Backup.capture
        for kind in ("bytes", "manifest", "lock", "directory"):
            destination = self.root / kind
            def tamper(backup, store, revision):
                result = original(backup, store, revision)
                if kind == "bytes":
                    (destination / "state.sqlite3").write_bytes(PRIVATE.encode())
                elif kind == "manifest":
                    (destination / "backup.json").write_bytes(PRIVATE.encode())
                elif kind == "lock":
                    (destination / "state.lock").rename(destination / "old.lock")
                    (destination / "state.lock").touch(mode=0o600)
                else:
                    destination.rename(self.root / "displaced")
                    destination.mkdir(mode=0o700)
                return result
            with self.subTest(kind=kind), patch.object(migration._Backup, "capture", tamper):
                self.assert_error("backup_identity_changed", lambda: self.migrate(backup_directory=destination))
            self.assertEqual(self.read()[0], 1)

    def test_source_replacement_after_backup_prevents_schema_write(self):
        self.legacy()
        original = migration._Backup.capture
        def replace(backup, store, revision):
            result = original(backup, store, revision)
            database = self.source / "state.sqlite3"
            database.rename(self.source / "original.sqlite3")
            shutil.copyfile(self.backup / "state.sqlite3", database)
            database.chmod(0o600)
            return result
        with patch.object(migration._Backup, "capture", replace):
            self.assert_error("migration_source_changed", self.migrate)
        self.assertEqual(self.read()[0], 1)

    def test_omitted_and_modified_receipts_cannot_masquerade_as_valid_v2(self):
        self.legacy()
        self.migrate()
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            original = db.execute("SELECT * FROM schema_migrations").fetchone()
        cases = [("DELETE FROM schema_migrations", ()),
                 ("UPDATE schema_migrations SET revision=100", ()),
                 ("UPDATE schema_migrations SET from_version=0", ()),
                 ("UPDATE schema_migrations SET seal=?", (b"x" * 32,)),
                 ("UPDATE schema_migrations SET backup=?", (_json({"path": PRIVATE}),))]
        for statement, parameters in cases:
            with self.subTest(statement=statement):
                self.corrupt(self.source, "schema_migrations", statement, parameters)
                self.assert_error("store_corrupt", self.read)
                with sqlite3.connect(self.source / "state.sqlite3") as db:
                    db.execute("DROP TRIGGER schema_migrations_delete")
                    db.execute("DELETE FROM schema_migrations")
                    db.execute(_TRIGGERS["schema_migrations_delete"])
                    db.execute("INSERT INTO schema_migrations VALUES(?,?,?,?,?,?,?,?)", original)
        self.assertEqual(self.read()[0], 2)

    def test_receipt_is_bound_to_host_even_when_the_private_key_is_copied(self):
        self.legacy()
        self.migrate()
        other_path = self.root / "other"
        with patch("mpkg_manager.store.SCHEMA_VERSION", 2), \
                HostStore.create(other_path, OTHER, owner_uid=self.owner) as other:
            other.record_intent(EMPTY, 0)
            receipt = other._db.execute("SELECT * FROM schema_migrations").fetchone()
            key = other._db.execute("SELECT private_key FROM host").fetchone()[0]
        self.corrupt(self.source, "host", "UPDATE host SET private_key=?", (key,))
        self.corrupt(self.source, "schema_migrations", "DELETE FROM schema_migrations")
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            db.execute("INSERT INTO schema_migrations VALUES(?,?,?,?,?,?,?,?)", receipt)
        self.assert_error("store_corrupt", self.read)

    def test_helper_exports_legacy_history_but_recording_returns_fixed_migration_error(self):
        self.legacy()
        policy = self.root / "policy.toml"
        policy.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                          f'allowed_input_roots={json.dumps([str(self.root)])}\n')
        policy.chmod(0o600)
        runtime = self.root / "run"
        runtime.mkdir(mode=0o700)
        lock = runtime / "apply.lock"
        lock.touch(mode=0o600)
        boundary = HostBoundary(policy_path=policy, store_directory=self.source,
                                 mutation_lock=lock, owner_uid=self.owner)
        def send(value):
            raw = handle_request(value, boundary=boundary)
            return _Reply(raw, 0 if json.loads(raw)["ok"] else 2)
        current = json.dumps({"version": 1, "verb": "export", "arguments": {"operation": "current"}}).encode()
        self.assertEqual(request_host(current, _sender=send)["revision"], 1)
        record = json.dumps({"version": 1, "verb": "record", "arguments": {"operation": "intent",
            "source": EMPTY.source_bytes.decode(), "source_is_nonsecret": True, "expected_revision": 1}}).encode()
        with self.assertRaises(HostClientError) as result:
            request_host(record, _sender=send)
        self.assertEqual((result.exception.code, result.exception.category, result.exception.exit_status),
                         ("store_migration_required", "rejected", 6))
        self.assertFalse(self.backup.exists())


if __name__ == "__main__":
    unittest.main()
