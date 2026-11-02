"""Bound-reference recording with real private temporary policy/store fixtures."""
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.protected_bindings import BindingError, ProtectedRecorder
from mpkg_manager.protected_capture import capture_protected
from mpkg_manager.store import HostStore, StoreError


HOST = "12345678-1234-4234-8234-123456789abc"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


class ProtectedBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.source = self.inputs / "private.env"
        self.source.write_bytes(b"PROTECTED_BINDING_SENTINEL=value\n")
        directory = self.root / "policy"
        directory.mkdir(mode=0o700)
        self.policy_path = directory / "host-policy.toml"
        self.policy_raw = (f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                           f'allowed_input_roots={json.dumps([str(self.inputs)])}\n').encode()
        self.policy_path.write_bytes(self.policy_raw)
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.store_path = self.root / "store"
        self.store = HostStore.create(self.store_path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)

    def prepare(self, revision=0, **kwargs):
        return self.recorder.prepare(**({"expected_revision": revision, "input_id": "app-inputs",
                                        "base_directory": str(self.inputs), "path": "private.env"} | kwargs))

    def declaration(self, reference, *, comment="", path="private.env", base=None):
        return load_declaration((f'''schema=1
components=[]
[[resources]]
id="app"
kind="package"
identity={{name="example"}}
manage=["present"]
desired={{present=true}}
[[inputs]]
id="app-inputs"
base_directory={json.dumps(str(self.inputs) if base is None else base)}
files=[{{path={json.dumps(path)},classification="protected",reference="{reference}"}}]
{comment}
''').encode())

    def compare(self, decision, **kwargs):
        return self.recorder.compare_input(**({"revision": decision["revision"], "snapshot_id": decision["snapshot_id"],
                                              "input_id": "app-inputs", "path": "private.env"} | kwargs))

    def assert_error(self, kind, code, callback):
        with self.assertRaises(kind) as error:
            callback()
        self.assertEqual(error.exception.code, code)
        self.assertEqual(str(error.exception), code)

    def test_prepare_record_then_adopt_identical_snapshot_keeps_one_origin_link(self):
        prepared = self.prepare()
        declaration = self.declaration(prepared.reference)
        first = self.recorder.record_intent(declaration, 0, prepared_inputs=[prepared])
        self.assertEqual(self.store.snapshot(first["snapshot_id"]).source_bytes, declaration.source_bytes)
        self.assertEqual(self.store.current()["resources"], [])
        self.assertEqual(self.compare(first), "same")
        second = self.recorder.adopt(declaration, 1, ["app"])
        self.assertEqual(second["snapshot_id"], first["snapshot_id"])
        self.assertEqual(self.compare(second), "same")
        self.assertEqual(self.compare(first), "same")
        self.assertEqual(self.store._db.execute("SELECT count(*) FROM protected_inputs").fetchone()[0], 1)
        self.assertEqual(self.store._db.execute("SELECT count(*) FROM decision_inputs").fetchone()[0], 1)
        token = self.store._db.execute("SELECT token FROM protected_inputs").fetchone()[0]
        self.assertTrue(token.startswith(b"MPKGBND\x00\x01"))
        self.assertEqual(self.store.current()["resources"][0]["observation"]["state"], "unknown")

    def test_changed_source_blocks_prepared_record_without_publishing_any_rows(self):
        prepared = self.prepare()
        declaration = self.declaration(prepared.reference)
        self.source.write_bytes(b"CHANGED_PRIVATE_VALUE")
        self.assert_error(BindingError, "protected_input_changed", lambda: self.recorder.record_intent(
            declaration, 0, prepared_inputs=[prepared]))
        self.assertEqual(self.store.history(), [])
        for table in ("snapshots", "protected_inputs", "decision_inputs"):
            self.assertEqual(self.store._db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_legacy_capture_remains_comparable_by_name_but_is_not_a_bound_reference(self):
        captured = capture_protected(self.policy, root=str(self.inputs), relative_path="private.env",
                                     name="legacy", purpose="Legacy fixture")
        declaration = self.declaration(str(uuid.uuid4()))
        decision = self.store.record_intent(declaration, 0, protected_inputs=[captured])
        self.assertEqual(self.store.compare_protected(1, "legacy", captured.raw, captured.source_identity), "same")
        self.assertEqual(self.compare(decision), "unavailable")
        self.assert_error(BindingError, "binding_unavailable", lambda: self.recorder.record_intent(declaration, 1))
        self.assertEqual(len(self.store.history()), 1)

    def test_bound_link_name_tampering_is_detected_by_durable_validation(self):
        prepared = self.prepare()
        self.recorder.record_intent(self.declaration(prepared.reference), 0, prepared_inputs=[prepared])
        with sqlite3.connect(self.store_path / "state.sqlite3") as db:
            sql = db.execute("SELECT sql FROM sqlite_schema WHERE name='decision_inputs_update'").fetchone()[0]
            db.execute("DROP TRIGGER decision_inputs_update")
            db.execute("UPDATE decision_inputs SET name='retargeted'")
            db.execute(sql)
        self.assert_error(StoreError, "store_corrupt", self.store.current)


if __name__ == "__main__":
    unittest.main()
