"""Isolated SQLite/permission checks; no host package or service operations."""
from dataclasses import replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager.declarations import load_declaration
from mpkg_manager.store import HostStore, ProtectedInput, SCHEMA_VERSION, StoreError


EMPTY = b"schema = 1\ncomponents = []\nresources = []\n"


def package(logical="git", name="git", manage=True):
    return load_declaration((f'''schema = 1
components = []
[[resources]]
id = "{logical}"
kind = "package"
identity = {{ name = "{name}" }}
manage = {('["present"]' if manage else '[]')}
desired = {{ present = true }}
''').encode())


class HostStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "records"
        self.host = str(uuid.uuid4())
        self.owner = os.geteuid()
        self.declaration = package()

    def create(self, **kwargs):
        result = HostStore.create(self.directory, self.host, owner_uid=self.owner, **kwargs)
        self.addCleanup(result.close)
        return result

    def open(self, readonly=False, **kwargs):
        function = HostStore.open_readonly if readonly else HostStore.open_existing
        result = function(self.directory, self.host, owner_uid=self.owner, **kwargs)
        self.addCleanup(result.close)
        return result

    def assert_error(self, code, callback):
        with self.assertRaises(StoreError) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def capture(self, raw=b"SECRET_SENTINEL=fixture-private-value", name="fixture-input"):
        identity = {"path": "/fixture/input.env", "device": 1, "inode": 2,
                    "size": len(raw), "mtime_ns": 3, "uid": 0, "gid": 0,
                    "mode": stat.S_IFREG | 0o600, "links": 1}
        return ProtectedInput(name, raw, identity, "fixture configuration")

    def inventory(self):
        return {str(p.relative_to(self.root)): (p.read_bytes() if p.is_file() else None,
                                               p.stat().st_mtime_ns, stat.S_IMODE(p.stat().st_mode))
                for p in self.root.rglob("*")}

    def corrupt_row(self, table, column, value, where):
        # Preserve the exact schema so these fixtures test semantic corruption,
        # independently of schema checks and immutable-record triggers.
        with sqlite3.connect(self.directory / "state.sqlite3") as db:
            trigger = table + "_update"
            sql = db.execute("SELECT sql FROM sqlite_schema WHERE name=?", (trigger,)).fetchone()[0]
            db.execute("DROP TRIGGER " + trigger)
            db.execute(f"UPDATE {table} SET {column}=? WHERE {where}", (value,))
            db.execute(sql)

    def assert_corrupt_store_refused(self, store, snapshot_id):
        before = self.inventory()
        for callback in (store.current, store.history, lambda: store.snapshot(snapshot_id),
                         lambda: store.record_intent(self.declaration, 2),
                         lambda: self.open(readonly=True), self.open):
            self.assert_error("store_corrupt", callback)
        self.assertEqual(self.inventory(), before)

    def test_create_is_explicit_private_and_binds_host(self):
        store = self.create()
        self.assertEqual(store.current(), {"host_id": self.host, "revision": 0,
                                          "snapshot_id": None, "snapshot": None, "resources": []})
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        for name in ("state.sqlite3", "state.lock"):
            self.assertEqual(stat.S_IMODE((self.directory / name).stat().st_mode), 0o600)
        self.assertEqual(tuple(store._db.execute("PRAGMA " + key).fetchone()[0]
                               for key in ("journal_mode", "synchronous", "foreign_keys")),
                         ("delete", 3, 1))
        self.assert_error("store_exists", self.create)
        self.assert_error("store_host_mismatch", lambda: HostStore.open_existing(
            self.directory, str(uuid.uuid4()), owner_uid=self.owner))

    def test_default_owner_is_root_and_override_is_not_in_declaration(self):
        with patch("mpkg_manager.store.os.geteuid", return_value=12345):
            self.assert_error("store_owner_required", lambda: HostStore.create(self.directory, self.host))
        self.assertFalse(self.directory.exists())

    def test_invalid_store_paths_and_host_identifiers_are_fixed_errors(self):
        for path in ("relative/private", "/", "/tmp/../private", "/tmp/invalid\0path", b"PRIVATE"):
            self.assert_error("invalid_store_path", lambda: HostStore.create(path, self.host, owner_uid=self.owner))
        for host in ("PRIVATE-host", 7, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"):
            self.assert_error("invalid_host_id", lambda: HostStore.open_readonly(
                self.directory, host, owner_uid=self.owner))
        self.assertFalse(self.directory.exists())

    def test_missing_reads_and_existing_opens_create_nothing(self):
        for readonly in (False, True):
            self.assert_error("store_missing", lambda: self.open(readonly))
            self.assertEqual(list(self.root.iterdir()), [])

    def test_readonly_reads_leave_contents_modes_mtimes_and_inventory_unchanged(self):
        store = self.create()
        decision = store.record_intent(self.declaration, 0)
        store.close()
        before = self.inventory()
        reader = self.open(readonly=True)
        self.assertEqual(reader.current()["revision"], 1)
        self.assertEqual(len(reader.history()), 1)
        self.assertEqual(reader.snapshot(decision["snapshot_id"]), self.declaration)
        self.assert_error("store_readonly", lambda: reader.record_intent(self.declaration, 1))
        reader.close()
        self.assertEqual(self.inventory(), before)

    def test_recording_intent_does_not_adopt_resources(self):
        store = self.create()
        result = store.record_intent(self.declaration, 0)
        self.assertEqual(result["kind"], "intent")
        self.assertEqual(store.current()["resources"], [])
        self.assertEqual(store.snapshot(result["snapshot_id"]).source_bytes,
                         self.declaration.source_bytes)

    def test_adoption_survives_missing_declarations_and_reopening(self):
        store = self.create()
        store.adopt(self.declaration, 0, ["git"])
        original = store.current()["resources"][0]
        self.assertEqual(original["observation"]["state"], "unknown")
        store.record_intent(load_declaration(EMPTY), 1)
        store.close()
        reopened = self.open(readonly=True)
        resource = reopened.current()["resources"][0]
        self.assertEqual(resource["stable_id"], original["stable_id"])
        self.assertEqual(resource["definition"], original["definition"])
        self.assertEqual(resource["management"], "accepted")
        self.assertEqual(resource["declaration_state"], "absent")
        self.assertTrue(resource["pending_disposition"])
        self.assertEqual([item["kind"] for item in reopened.history()], ["adopt", "intent"])

    def test_renaming_declaration_retains_physical_identity(self):
        store = self.create()
        store.adopt(self.declaration, 0, ["git"])
        identity = store.current()["resources"][0]["stable_id"]
        renamed = package(logical="source-control")
        store.record_intent(renamed, 1)
        self.assertFalse(store.current()["resources"][0]["pending_disposition"])
        store.adopt(renamed, 2, ["source-control"])
        self.assertEqual(store.current()["resources"][0]["stable_id"], identity)
        self.assertEqual(store.current()["resources"][0]["logical_id"], "source-control")

    def test_changed_identity_and_implicit_authority_upgrade_fail_atomically(self):
        store = self.create()
        store.adopt(package(manage=False), 0, ["git"])
        before = store.current()
        self.assert_error("resource_identity_conflict",
                          lambda: store.adopt(package(name="python"), 1, ["git"]))
        self.assert_error("authority_change_requires_decision",
                          lambda: store.adopt(package(), 1, ["git"]))
        self.assertEqual(store.current(), before)
        self.assertEqual(len(store.history()), 1)

    def test_relinquishment_preserves_history_without_claiming_retirement(self):
        store = self.create()
        store.adopt(self.declaration, 0, ["git"])
        identity = store.current()["resources"][0]["stable_id"]
        result = store.relinquish([identity], 1)
        self.assertEqual(result["kind"], "relinquish")
        resource = store.current()["resources"][0]
        self.assertEqual(resource["management"], "relinquished")
        self.assertEqual(resource["observation"]["state"], "unknown")
        self.assertEqual(resource["definition"]["desired"], {"present": True})
        self.assertFalse(resource["pending_disposition"])

    def test_stale_second_writer_cannot_publish_revision_or_snapshot(self):
        first = self.create()
        second = self.open()
        first.record_intent(self.declaration, 0)
        self.assert_error("revision_conflict", lambda: second.record_intent(load_declaration(EMPTY), 0))
        self.assertEqual(second.current()["revision"], 1)
        self.assertEqual(second._db.execute("SELECT count(*) FROM snapshots").fetchone()[0], 1)

    def test_same_model_preserves_distinct_original_source_bytes(self):
        store = self.create()
        changed = load_declaration(self.declaration.source_bytes + b"\n# original source matters\n")
        self.assertEqual(changed.sha256, self.declaration.sha256)
        one = store.record_intent(self.declaration, 0)
        two = store.record_intent(changed, 1)
        self.assertNotEqual(one["snapshot_id"], two["snapshot_id"])
        self.assertEqual(store.snapshot(one["snapshot_id"]), self.declaration)
        self.assertEqual(store.snapshot(two["snapshot_id"]), changed)
        self.assertEqual(store.current()["snapshot"], {
            "id": two["snapshot_id"], "source_sha256": hashlib.sha256(changed.source_bytes).hexdigest(),
            "canonical_sha256": changed.sha256, "schema_version": 1, "normalization_version": 1})

    def test_forged_declaration_cannot_bypass_validation(self):
        store = self.create()
        for changed in (replace(self.declaration, sha256="a" * 64),
                        replace(self.declaration, canonical_bytes=b'{}'),
                        replace(self.declaration, source_bytes=b"private invalid bytes"),
                        replace(self.declaration, schema_version=2),
                        replace(self.declaration, normalization_version=2)):
            self.assert_error("invalid_declaration", lambda: store.record_intent(changed, 0))
        self.assertEqual(store.history(), [])

    def test_unknown_schema_and_extra_schema_are_refused_without_repair(self):
        store = self.create()
        store.close()
        with sqlite3.connect(self.directory / "state.sqlite3") as db:
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
        before = self.inventory()
        self.assert_error("store_schema_unsupported", self.open)
        self.assertEqual(self.inventory(), before)
        with sqlite3.connect(self.directory / "state.sqlite3") as db:
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            db.execute("CREATE TABLE unexpected(value TEXT)")
        self.assert_error("store_schema_unsupported", self.open)

    def test_corrupt_database_exposes_only_fixed_error(self):
        store = self.create()
        store.close()
        (self.directory / "state.sqlite3").write_bytes(b"PRIVATE-CORRUPT-DATABASE")
        self.assert_error("store_unavailable", self.open)

    def test_semantically_corrupt_authority_rows_fail_before_projection_or_write(self):
        definition = self.declaration.model["resources"][0]
        cases = [
            ("stable_id", "not-a-uuid"),
            ("physical_key", json.dumps(["wrong-host", "package", "git"], separators=(",", ":")).encode()),
            ("physical_key", json.dumps([self.host, "package", "python"], separators=(",", ":")).encode()),
            ("definition", json.dumps(definition | {"manage": []}, sort_keys=True, separators=(",", ":")).encode()),
            ("definition", b'{}'),
            ("requirements", b'{}'),
            ("requirements", b'[{"consumer":"invented","property":"present","value":true}]'),
            ("logical_id", "invented"),
            ("active", 0),
        ]
        for number, (column, value) in enumerate(cases):
            with self.subTest(column=column, case=number):
                self.directory = self.root / str(number)
                store = self.create()
                snapshot = store.adopt(self.declaration, 0, ["git"])["snapshot_id"]
                store.adopt(self.declaration, 1, ["git"])
                self.corrupt_row("resources", column, value, "revision=1")
                self.assert_corrupt_store_refused(store, snapshot)

    def test_semantically_corrupt_history_and_snapshots_fail_closed(self):
        cases = [
            ("decisions", "revision", 100, "revision=2"),
            ("decisions", "parent_revision", None, "revision=2"),
            ("decisions", "created_at", "not-a-time", "revision=1"),
            ("decisions", "created_at", "2026-11-01T00:00:00.000000", "revision=1"),
            ("decisions", "kind", "adopt", "revision=2"),
            ("decisions", "kind", "intent", "revision=1"),
            ("snapshots", "canonical", b'{}', "1=1"),
            ("snapshots", "source", self.declaration.source_bytes + b"# altered", "1=1"),
            ("snapshots", "digest", "a" * 64, "1=1"),
        ]
        for number, (table, column, value, where) in enumerate(cases):
            with self.subTest(table=table, column=column, case=number):
                self.directory = self.root / str(number)
                store = self.create()
                snapshot = store.adopt(self.declaration, 0, ["git"])["snapshot_id"]
                store.record_intent(load_declaration(EMPTY), 1)
                self.corrupt_row(table, column, value, where)
                self.assert_corrupt_store_refused(store, snapshot)

    def test_corrupt_protected_capture_relations_and_tokens_fail_closed(self):
        for number, (table, column, value) in enumerate([
            ("protected_inputs", "token", b"x" * 32),
            ("protected_inputs", "source_identity", b'{}'),
            ("protected_inputs", "purpose", ""),
            ("decision_inputs", "name", "invalid name"),
            ("decision_inputs", "protected_id", "missing-reference"),
        ]):
            with self.subTest(table=table, column=column):
                self.directory = self.root / str(number)
                store = self.create()
                captured = self.capture()
                snapshot = store.record_intent(self.declaration, 0, protected_inputs=[captured])["snapshot_id"]
                store.record_intent(load_declaration(EMPTY), 1)
                self.corrupt_row(table, column, value, "1=1")
                self.assert_corrupt_store_refused(store, snapshot)
                self.assert_error("store_corrupt", lambda: store.compare_protected(
                    1, captured.name, captured.raw, captured.source_identity))

    def test_replay_retains_renamed_relinquished_and_readopted_resources(self):
        store = self.create()
        store.adopt(self.declaration, 0, ["git"])
        stable = store.current()["resources"][0]["stable_id"]
        store.relinquish([stable], 1)
        store.adopt(package(logical="source-control", manage=False), 2, ["source-control"])
        store.record_intent(load_declaration(EMPTY), 3)
        store.close()
        resource = self.open(readonly=True).current()["resources"][0]
        self.assertEqual(resource["stable_id"], stable)
        self.assertEqual(resource["logical_id"], "source-control")
        self.assertEqual(resource["management"], "accepted")
        self.assertTrue(resource["pending_disposition"])

    def test_hot_journal_or_wal_requires_explicit_recovery_and_is_not_changed(self):
        store = self.create()
        store.close()
        for suffix in ("-journal", "-wal", "-shm"):
            side = self.directory / ("state.sqlite3" + suffix)
            side.write_bytes(b"private recovery evidence")
            before = self.inventory()
            self.assert_error("store_recovery_required", lambda: self.open(readonly=True))
            self.assert_error("store_recovery_required", self.open)
            self.assertEqual(self.inventory(), before)
            side.unlink()

    def test_permissions_links_and_symlink_ancestors_are_refused(self):
        store = self.create()
        store.close()
        db = self.directory / "state.sqlite3"
        db.chmod(0o640)
        self.assert_error("store_permissions", self.open)
        db.chmod(0o600)
        other = self.root / "hardlink"
        os.link(db, other)
        self.assert_error("store_permissions", self.open)
        other.unlink()
        db.rename(self.directory / "real.sqlite3")
        db.symlink_to("real.sqlite3")
        self.assert_error("store_permissions", self.open)
        db.unlink()
        (self.directory / "real.sqlite3").rename(db)
        link = self.root / "linked"
        link.symlink_to(self.directory, target_is_directory=True)
        self.assert_error("store_unavailable", lambda: HostStore.open_readonly(
            link, self.host, owner_uid=self.owner))

    def test_existing_open_detects_replaced_database_and_lock(self):
        store = self.create()
        db = self.directory / "state.sqlite3"
        db.rename(self.directory / "old.sqlite3")
        db.write_bytes((self.directory / "old.sqlite3").read_bytes())
        db.chmod(0o600)
        self.assert_error("store_identity_changed", store.current)
        store.close()
        store = self.open()
        lock = self.directory / "state.lock"
        lock.rename(self.directory / "old.lock")
        lock.touch(mode=0o600)
        self.assert_error("store_identity_changed", store.current)

    def test_busy_lock_is_bounded_and_does_not_create_anything(self):
        store = self.create()
        descriptor = os.open(self.directory / "state.lock", os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = self.inventory()
            self.assert_error("store_busy", store.current)
            self.assertEqual(self.inventory(), before)
        finally:
            os.close(descriptor)

    def test_protected_capture_is_atomic_and_public_projections_hide_private_material(self):
        store = self.create()
        captured = self.capture()
        store.record_intent(self.declaration, 0, protected_inputs=[captured])
        reference, token = store._db.execute("SELECT id,token FROM protected_inputs").fetchone()
        key = store._db.execute("SELECT private_key FROM host").fetchone()[0]
        public = json.dumps({"current": store.current(), "history": store.history()}).encode()
        for secret in (captured.raw, reference.encode(), token, token.hex().encode(),
                       key, key.hex().encode(), hashlib.sha256(captured.raw).hexdigest().encode()):
            self.assertNotIn(secret, public)
        self.assertNotIn(captured.raw.decode(), repr(captured))
        self.assertEqual(store.compare_protected(1, captured.name, captured.raw, captured.source_identity), "same")
        changed = captured.raw[:-1] + b"X"
        self.assertEqual(store.compare_protected(1, captured.name, changed, captured.source_identity), "changed")
        self.assertEqual(store.compare_protected(1, captured.name, captured.raw,
                                               captured.source_identity | {"inode": 99}), "changed")
        self.assertEqual(store.compare_protected(1, captured.name, None, None), "unavailable")
        self.assertEqual(store.compare_protected(1, "unknown", captured.raw, captured.source_identity), "unavailable")

    def test_full_database_publishes_no_decision_snapshot_or_protected_reference(self):
        store = self.create()
        pages = store._db.execute("PRAGMA page_count").fetchone()[0]
        store._db.execute(f"PRAGMA max_page_count={pages}")
        captured = self.capture(os.urandom(1024 * 1024))
        self.assert_error("store_write_failed", lambda: store.record_intent(
            self.declaration, 0, protected_inputs=[captured]))
        self.assertEqual(store.history(), [])
        for table in ("snapshots", "protected_inputs", "decision_inputs"):
            self.assertEqual(store._db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_commit_failure_before_and_after_commit_is_reported_unknown(self):
        for committed in (False, True):
            with self.subTest(committed=committed):
                self.directory = self.root / str(committed)
                store = self.create()
                real_commit = store._commit
                def fail():
                    if committed:
                        real_commit()
                    raise sqlite3.OperationalError("PRIVATE-COMMIT-ERROR")
                with patch.object(store, "_commit", fail):
                    self.assert_error("commit_outcome_unknown", lambda: store.record_intent(
                        self.declaration, 0, protected_inputs=[self.capture()]))
                self.assert_error("store_closed", store.current)
                reader = self.open(readonly=True)
                self.assertEqual(reader.current()["revision"], int(committed))
                self.assertEqual(len(reader.history()), int(committed))

    def test_engine_alias_binding_and_duplicates_are_checked_before_recording(self):
        store = self.create(engine_aliases={"first": "engine-id", "second": "engine-id"})
        raw = '''schema=1
components=[]
[[resources]]
id="one"
kind="compose"
identity={engine="first",project="media"}
[[resources]]
id="two"
kind="compose"
identity={engine="second",project="media"}
'''
        duplicate = load_declaration(raw.encode())
        self.assert_error("resource_identity_conflict", lambda: store.record_intent(duplicate, 0))
        first_only = "[[resources]]".join(raw.split("[[resources]]")[:2])
        unknown = load_declaration(first_only.replace('"first"', '"unknown"').encode())
        self.assert_error("resource_identity_unbound", lambda: store.adopt(unknown, 0, ["one"]))
        self.assertEqual(store.history(), [])

    def test_commit_cancellation_closes_transaction_before_unlock_and_preserves_interrupt(self):
        for interruption in (KeyboardInterrupt, SystemExit):
            for committed in (False, True):
                with self.subTest(interruption=interruption, committed=committed):
                    self.directory = self.root / (interruption.__name__ + str(committed))
                    store = self.create()
                    real_commit, real_flock = store._commit, fcntl.flock
                    failure = interruption("fixture cancellation")
                    unlocked = []
                    def interrupt():
                        if committed:
                            real_commit()
                        raise failure
                    def checked_unlock(descriptor, operation):
                        if operation == fcntl.LOCK_UN:
                            self.assertIsNone(store._db)
                            self.assertTrue(store._closed)
                            self.assertFalse((self.directory / "state.sqlite3-journal").exists())
                            unlocked.append(True)
                        return real_flock(descriptor, operation)
                    with patch.object(store, "_commit", interrupt), patch(
                            "mpkg_manager.store.fcntl.flock", checked_unlock):
                        with self.assertRaises(interruption) as caught:
                            store.record_intent(self.declaration, 0, protected_inputs=[self.capture()])
                    self.assertIs(caught.exception, failure)
                    self.assertEqual(unlocked, [True])
                    self.assertIsNone(store._lockfd)
                    self.assert_error("store_closed", store.current)
                    self.assertEqual(self.open(readonly=True).current()["revision"], int(committed))

    def test_returned_engine_aliases_cannot_change_accepted_bindings(self):
        store = self.create(engine_aliases={"local": "accepted-engine"})
        projection = store.engine_aliases
        projection["local"] = "different-engine"
        projection["extra"] = "another-engine"
        self.assertEqual(store.engine_aliases, {"local": "accepted-engine"})
        declaration = load_declaration(b'''schema=1
components=[]
[[resources]]
id="app"
kind="compose"
identity={engine="local",project="media"}
''')
        store.adopt(declaration, 0, ["app"])
        self.assertIn("accepted-engine", store.current()["resources"][0]["physical_key"])

    def test_invalid_protected_capture_is_refused_before_any_record(self):
        store = self.create()
        valid = self.capture()
        cases = [
            replace(valid, raw="PRIVATE"),
            replace(valid, purpose="invalid-\ud800"),
            replace(valid, source_identity=valid.source_identity | {"links": 2}),
            replace(valid, source_identity=valid.source_identity | {"size": 0}),
            replace(valid, source_identity=valid.source_identity | {"mode": stat.S_IFDIR | 0o700}),
            replace(valid, source_identity=valid.source_identity | {"path": "relative"}),
            replace(valid, raw=b"x" * (16 * 1024 * 1024 + 1)),
        ]
        for invalid in cases:
            self.assert_error("invalid_protected_input", lambda: store.record_intent(
                self.declaration, 0, protected_inputs=[invalid]))
        self.assert_error("invalid_protected_input", lambda: store.record_intent(
            self.declaration, 0, protected_inputs=[valid, valid]))
        self.assertEqual(store.history(), [])

    def test_existing_consumers_and_requirements_are_not_erased_by_new_declaration(self):
        store = self.create()
        old = load_declaration(b'''schema=1
[[components]]
id="original"
purpose="Retain shared access"
resources=["data"]
requirements=[{resource="data",property="mode",value=448}]
[[resources]]
id="data"
kind="directory"
identity={path="/fixture/data"}
consumers=["original","external:other"]
manage=["mode"]
desired={mode=448}
''')
        store.adopt(old, 0, ["data"])
        new = load_declaration(b'''schema=1
components=[]
[[resources]]
id="data"
kind="directory"
identity={path="/fixture/data"}
manage=["mode"]
desired={mode=493}
''')
        self.assert_error("consumer_requirement_conflict", lambda: store.adopt(new, 1, ["data"]))
        compatible = load_declaration(new.source_bytes.replace(b"mode=493", b"mode=448"))
        store.adopt(compatible, 1, ["data"])
        current = store.current()["resources"][0]
        self.assertEqual(current["definition"]["consumers"], ["original", "external:other"])
        self.assertEqual(current["requirements"], [{"consumer": "original", "property": "mode", "value": 448}])

    def test_retained_package_constraints_are_contextually_revalidated(self):
        store = self.create()
        old = load_declaration(b'''schema=1
[[components]]
id="original"
purpose="Use AUR package"
resources=["app"]
requirements=[{resource="app",property="source",value="aur"}]
[[resources]]
id="app"
kind="package"
identity={name="app"}
''')
        store.adopt(old, 0, ["app"])
        new = load_declaration(b'''schema=1
components=[]
[[resources]]
id="app"
kind="package"
identity={name="app"}
desired={version={policy="exact",value="1-1"}}
''')
        before = store.current()
        self.assert_error("consumer_requirement_conflict", lambda: store.adopt(new, 1, ["app"]))
        self.assertEqual(store.current(), before)
        self.assertEqual(len(store.history()), 1)
        # A new declaration may restate the source and provide its recipe.
        valid = load_declaration(new.source_bytes.replace(
            b'version={policy="exact",value="1-1"}',
            b'source="aur",version={policy="exact",value="1-1",recipe_revision="' + b"a" * 40 + b'"}'))
        store.adopt(valid, 1, ["app"])
        self.assertEqual(store.current()["resources"][0]["requirements"],
                         [{"consumer": "original", "property": "source", "value": "aur"}])

    def test_retained_file_input_constraints_require_valid_current_context(self):
        store = self.create()
        old = load_declaration(b'''schema=1
[[inputs]]
id="config"
base_directory="/fixture"
files=[{path="input",classification="nonsecret"}]
[[components]]
id="original"
purpose="Read configuration"
resources=["config-file"]
requirements=[{resource="config-file",property="content_input",value="config"}]
[[resources]]
id="config-file"
kind="file"
identity={path="/fixture/config"}
''')
        store.adopt(old, 0, ["config-file"])
        new = b'''schema=1
components=[]
[[resources]]
id="config-file"
kind="file"
identity={path="/fixture/config"}
'''
        inputs = b'''\n[[inputs]]
id="config"
base_directory="/fixture"
files=[{path="input",classification="nonsecret"}]
'''
        for invalid in (new, new + inputs.replace(b'files=[', b'files=[{path="extra",classification="nonsecret"},'),
                        new + b'desired={content="inline"}\n' + inputs):
            self.assert_error("consumer_requirement_conflict", lambda: store.adopt(
                load_declaration(invalid), 1, ["config-file"]))
        self.assertEqual(len(store.history()), 1)
        store.adopt(load_declaration(new + inputs), 1, ["config-file"])
        self.assertEqual(store.current()["resources"][0]["definition"]["consumers"], ["original"])


if __name__ == "__main__":
    unittest.main()
