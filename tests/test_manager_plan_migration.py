"""Version-3 upgrades against authentic older-source SQLite fixtures."""
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.store import HostStore, StoreError, _TRIGGERS, _migration_receipt
from mpkg_manager import store_migration as migration


HOST = "12345678-1234-4234-8234-123456789abc"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")
FIXTURES = Path(__file__).parent / "fixtures" / "store-schemas"


class PlanMigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.backup = self.root / "source", self.root / "backup"
        self.owner = os.geteuid()

    def legacy(self, version):
        self.source.mkdir(mode=0o700)
        (self.source / "state.lock").touch(mode=0o600)
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            db.executescript((FIXTURES / f"v{version}.sql").read_text())
            db.execute("PRAGMA application_id=1297107783")
            db.execute(f"PRAGMA user_version={version}")
        (self.source / "state.sqlite3").chmod(0o600)

    def inspect(self, path=None):
        with HostStore.open_readonly(self.source if path is None else path, HOST, owner_uid=self.owner) as store:
            return store.schema_history(), store.current(), store.history()

    def migrate(self):
        return migration.migrate_store_to_v3(self.source, HOST, expected_revision=1,
                                             backup_directory=self.backup, owner_uid=self.owner)

    def error(self, code, callback):
        with self.assertRaises((StoreError, migration.MigrationError)) as error:
            callback()
        self.assertEqual(error.exception.code, code)

    def rewrite_receipts(self, statement, parameters=()):
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            for operation in ("update", "delete"):
                db.execute("DROP TRIGGER schema_migrations_" + operation)
            db.execute(statement, parameters)
            for operation in ("update", "delete"):
                db.execute(_TRIGGERS["schema_migrations_" + operation])

    def test_genuine_v2_history_and_captures_survive_explicit_upgrade(self):
        self.legacy(2)
        before = self.inspect()
        self.error("store_migration_required", lambda: HostStore.open_existing(
            self.source, HOST, owner_uid=self.owner))
        receipt = self.migrate()
        after = self.inspect()
        self.assertEqual(after[1:], before[1:])
        self.assertEqual(self.inspect(self.backup), before)
        self.assertEqual([(row["from_version"], row["to_version"])
                          for row in after[0]["receipts"]], [(0, 2), (2, 3)])
        self.assertEqual((receipt.from_version, receipt.to_version), (2, 3))
        with HostStore.open_existing(self.source, HOST, owner_uid=self.owner) as store:
            self.assertEqual(store._db.execute("SELECT raw FROM protected_inputs").fetchone()[0],
                             b"PRIVATE_LEGACY_FIXTURE_SENTINEL")
            self.assertEqual(store.record_intent(EMPTY, 1)["revision"], 2)
        self.assertEqual(self.inspect(self.backup)[1]["revision"], 1)

    def test_genuine_v1_requires_two_deliberate_transitions_and_backups(self):
        self.legacy(1)
        initial = self.inspect()
        self.error("migration_not_required", self.migrate)
        self.assertFalse(self.backup.exists())
        first = self.root / "first"
        migration.migrate_store(self.source, HOST, expected_revision=1,
                                backup_directory=first, owner_uid=self.owner)
        self.assertEqual(self.inspect()[0]["schema_version"], 2)
        self.error("store_migration_required", lambda: HostStore.open_existing(
            self.source, HOST, owner_uid=self.owner))
        self.migrate()
        self.assertEqual(self.inspect(first), initial)
        self.assertEqual(self.inspect(self.backup)[0]["schema_version"], 2)
        self.assertEqual([(row["from_version"], row["to_version"])
                          for row in self.inspect()[0]["receipts"]], [(1, 2), (2, 3)])

    def test_missing_chain_link_fails_even_when_last_receipt_is_valid(self):
        self.legacy(2)
        self.migrate()
        self.rewrite_receipts("DELETE FROM schema_migrations WHERE to_version=2")
        self.error("store_corrupt", self.inspect)

    def test_valid_but_replaced_predecessor_breaks_the_v3_chain_seal(self):
        self.legacy(2)
        self.migrate()
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            row = list(db.execute("SELECT * FROM schema_migrations WHERE to_version=2").fetchone())
            key = db.execute("SELECT private_key FROM host").fetchone()[0]
        row[0] = "23456789-1234-4234-8234-123456789abc"
        row[7] = _migration_receipt(key, HOST, *row[:6], None)
        self.rewrite_receipts("UPDATE schema_migrations SET id=?,seal=? WHERE to_version=2", (row[0], row[7]))
        self.error("store_corrupt", self.inspect)

    def test_resealed_invalid_transition_and_revision_regression_fail(self):
        self.legacy(2)
        self.migrate()
        with sqlite3.connect(self.source / "state.sqlite3") as db:
            original = db.execute("SELECT * FROM schema_migrations WHERE to_version=3").fetchone()
            previous = db.execute("SELECT seal FROM schema_migrations WHERE to_version=2").fetchone()[0]
            key = db.execute("SELECT private_key FROM host").fetchone()[0]
        for column, index, value in (("from_version", 2, 1), ("revision", 4, -1)):
            with self.subTest(column=column):
                altered = list(original)
                altered[index] = value
                seal = _migration_receipt(key, HOST, *altered[:6], json.loads(altered[6]), previous)
                self.rewrite_receipts("UPDATE schema_migrations SET " + column + "=?,seal=? WHERE to_version=3",
                                      (value, seal))
                self.error("store_corrupt", self.inspect)
                self.rewrite_receipts("UPDATE schema_migrations SET from_version=2,revision=1,seal=? WHERE to_version=3",
                                      (original[7],))
        self.assertEqual(self.inspect()[0]["schema_version"], 3)

    def test_failed_v3_schema_write_rolls_back_with_readable_v2_backup(self):
        self.legacy(2)
        before = self.inspect()
        upgrade = migration._upgrade
        def fail(*args):
            upgrade(*args)
            raise sqlite3.OperationalError("PRIVATE_FAILURE_SENTINEL")
        with patch.object(migration, "_upgrade", fail):
            self.error("migration_failed", self.migrate)
        self.assertEqual(self.inspect(), before)
        self.assertEqual(self.inspect(self.backup), before)

    def test_post_commit_failure_keeps_v3_uncertain_and_backup_v2(self):
        self.legacy(2)
        commit = HostStore._commit
        def after(store):
            commit(store)
            raise OSError("PRIVATE_FAILURE_SENTINEL")
        with patch.object(HostStore, "_commit", after):
            self.error("migration_outcome_unknown", self.migrate)
        self.assertEqual(self.inspect()[0]["schema_version"], 3)
        self.assertEqual(self.inspect(self.backup)[0]["schema_version"], 2)

    def test_v3_migration_holds_sqlite_writer_lock_through_upgrade(self):
        self.legacy(2)
        upgrade = migration._upgrade
        def compete(*args):
            with sqlite3.connect(self.source / "state.sqlite3", timeout=0) as other:
                with self.assertRaises(sqlite3.OperationalError):
                    other.execute("BEGIN IMMEDIATE")
            return upgrade(*args)
        with patch.object(migration, "_upgrade", compete):
            self.migrate()


if __name__ == "__main__":
    unittest.main()
