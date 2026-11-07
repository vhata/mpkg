"""Separate installed requests with private fixtures, never sudo or live tools."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager.cli import main
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_client import _Reply
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.store import HostStore, StoreError


HOST = "12345678-1234-4234-8234-123456789abc"
SECRET = "PROTECTED_RECORDING_SECRET_SENTINEL"


class ProtectedRecordingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.secret = self.inputs / "private.xml"
        self.secret.write_text(SECRET)
        self.policy = self.root / "policy.toml"
        self.policy.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                               f'allowed_input_roots={json.dumps([str(self.inputs)])}\n')
        self.policy.chmod(0o600)
        self.lock = self.root / "apply.lock"
        self.lock.touch(mode=0o600)
        self.store = self.root / "store"
        with HostStore.create(self.store, HOST, owner_uid=os.geteuid()):
            pass
        self.reference = str(uuid.uuid4())
        self.source = self.root / "intent.toml"
        self.source.write_text(f'''schema=1
components=[]
[[resources]]
id="config"
kind="file"
identity={{path="/srv/app/config.xml"}}
manage=["content_input"]
desired={{content_input="config-input"}}
[[inputs]]
id="config-input"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="private.xml",classification="protected",reference="{self.reference}"}}]
''')
        self.sent = []

    def sender(self, raw):
        self.sent.append(raw)
        # Every call gets fresh policy/store handles, as separate helper
        # invocations do. Nothing recorder-local survives this seam.
        boundary = HostBoundary(policy_path=self.policy, store_directory=self.store,
                                mutation_lock=self.lock, owner_uid=os.geteuid())
        response = handle_request(raw, boundary=boundary)
        self.assertNotIn(SECRET.encode(), response)
        self.assertNotIn(str(self.inputs).encode(), response)
        self.assertNotIn(self.reference.encode(), response)
        return _Reply(response, 0 if json.loads(response)["ok"] else 2)

    def invoke(self, *args):
        output = io.StringIO()
        with redirect_stdout(output), patch("subprocess.Popen", side_effect=AssertionError("host tool")), \
                patch("socket.socket", side_effect=AssertionError("host probe")):
            status = main([*args, "--json"], _sender=self.sender)
        self.assertNotIn(SECRET, output.getvalue())
        return status, json.loads(output.getvalue())

    def prepare(self, revision=0):
        status, value = self.invoke("prepare-inputs", str(self.source), "--source-is-nonsecret",
                                    "--expected-revision", str(revision))
        self.assertEqual(status, 0, value)
        return value["result"]["preparation_id"]

    def record(self, identifier, revision=0, *, adopt=False, capture=False):
        args = ["adopt" if adopt else "record", str(self.source), "--source-is-nonsecret",
                "--expected-revision", str(revision), "--prepared-inputs", identifier]
        if adopt:
            args += ["--resource", "config"]
        if capture:
            args += ["--capture-inputs"]
        return self.invoke(*args)

    def revision(self):
        with HostStore.open_readonly(self.store, HOST, owner_uid=os.geteuid()) as store:
            return store.current()["revision"]

    def assert_rejected(self, result, code="input_capture_rejected"):
        status, value = result
        self.assertEqual((status, value["error"]["code"]), (6, code), value)

    def test_prepare_record_and_adopt_preserve_bytes_and_original_checks(self):
        original = self.secret.read_bytes(), self.source.read_bytes()
        receipt = self.prepare()
        self.assertEqual(self.revision(), 0)
        pending = self.store / "protected-preparation.json"
        self.assertEqual(pending.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(SECRET.encode(), pending.read_bytes())
        self.assertEqual(self.record(receipt)[0], 0)
        self.assertFalse(pending.exists())
        receipt = self.prepare(1)
        self.assertEqual(self.record(receipt, 1, adopt=True)[0], 0)
        with HostStore.open_readonly(self.store, HOST, owner_uid=os.geteuid()) as store, \
                load_host_policy(path=self.policy, owner_uid=os.geteuid()) as policy:
            current = store.current()
            recorder = ProtectedRecorder(store, policy)
            self.assertEqual(recorder.compare_input(revision=2, snapshot_id=current["snapshot_id"],
                input_id="config-input", path="private.xml"), "same")
            self.assertEqual(len(current["resources"]), 1)
            self.assertEqual(store._db.execute("SELECT count(*) FROM protected_inputs").fetchone()[0], 1)
        self.assertEqual(original, (self.secret.read_bytes(), self.source.read_bytes()))
        self.assertEqual(self.invoke("history")[0], 0)
        self.assertEqual(self.invoke("current")[0], 0)

    def test_source_and_reference_substitution_are_rejected_before_consuming(self):
        for change in (lambda raw: raw + "# same model, different source\n",
                       lambda raw: raw.replace(self.reference, str(uuid.uuid4()))):
            with self.subTest(change=change):
                receipt = self.prepare()
                original = self.source.read_text()
                self.source.write_text(change(original))
                self.assert_rejected(self.record(receipt))
                self.source.write_text(original)
                self.assertTrue((self.store / "protected-preparation.json").exists())
        self.assertEqual(self.revision(), 0)

    def test_changed_bytes_identity_or_policy_refuse_without_record(self):
        for change in (lambda: self.secret.write_text(SECRET + "changed"),
                       lambda: self.secret.chmod(0o600),
                       lambda: self.policy.write_text(self.policy.read_text() + "# changed\n")):
            with self.subTest(change=change):
                receipt = self.prepare()
                change()
                self.assert_rejected(self.record(receipt))
        self.assertEqual(self.revision(), 0)

    def test_stale_revision_rejects_before_capture(self):
        receipt = self.prepare()
        with HostStore.open_existing(self.store, HOST, owner_uid=os.geteuid()) as store:
            store.record_intent(load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n"), 0)
        with patch.object(ProtectedRecorder, "_capture", side_effect=AssertionError("read")):
            self.assert_rejected(self.record(receipt), "revision_conflict")

    def test_another_preparation_invalidates_previous_id_and_quota_is_constant(self):
        first = self.prepare()
        second = self.prepare()
        self.assertNotEqual(first, second)
        self.assert_rejected(self.record(first))
        self.assertEqual(len(list(self.store.glob("protected-preparation*"))), 1)
        self.assertEqual(self.record(second)[0], 0)

    def test_missing_or_wrong_receipt_and_replay_never_record(self):
        self.assert_rejected(self.record(str(uuid.uuid4())))
        receipt = self.prepare()
        self.assert_rejected(self.record(str(uuid.uuid4())))
        self.assertEqual(self.record(receipt)[0], 0)
        self.assert_rejected(self.record(receipt, 1))
        self.assertEqual(self.revision(), 1)

    def test_cross_store_receipt_fails_authentication(self):
        receipt = self.prepare()
        pending = (self.store / "protected-preparation.json").read_bytes()
        other = self.root / "other-store"
        with HostStore.create(other, HOST, owner_uid=os.geteuid()):
            pass
        self.store = other
        (other / "protected-preparation.json").write_bytes(pending)
        (other / "protected-preparation.json").chmod(0o600)
        self.assert_rejected(self.record(receipt))

    def test_manifest_tampering_is_rejected(self):
        receipt = self.prepare()
        pending = self.store / "protected-preparation.json"
        value = json.loads(pending.read_bytes())
        value["manifest"]["entries"][0]["token"] = "0" * 64
        pending.write_text(json.dumps(value))
        self.assert_rejected(self.record(receipt))
        self.assertEqual(self.revision(), 0)

    def test_failed_commit_burns_receipt_and_preserves_unknown_outcome(self):
        receipt = self.prepare()
        with patch.object(HostStore, "_commit", side_effect=OSError(SECRET)):
            status, value = self.record(receipt)
        self.assertEqual((status, value["error"]["code"]), (7, "commit_outcome_unknown"))
        self.assertFalse((self.store / "protected-preparation.json").exists())
        self.assert_rejected(self.record(receipt))
        self.assertEqual(self.revision(), 0)

    def test_post_commit_failure_preserves_decision_but_cannot_replay(self):
        receipt = self.prepare()
        commit = HostStore._commit
        def uncertain(store):
            commit(store)
            raise OSError(SECRET)
        with patch.object(HostStore, "_commit", uncertain):
            self.assertEqual(self.record(receipt)[0], 7)
        self.assertEqual(self.revision(), 1)
        self.assert_rejected(self.record(receipt, 1))

    def test_receipt_removal_and_sync_failures_prevent_decision(self):
        receipt = self.prepare()
        with patch("mpkg_manager.protected_preparation.os.unlink", side_effect=OSError(SECRET)):
            self.assert_rejected(self.record(receipt))
        self.assertEqual(self.revision(), 0)
        with patch("mpkg_manager.protected_preparation.os.fsync", side_effect=OSError(SECRET)):
            self.assert_rejected(self.record(receipt))
        self.assertFalse((self.store / "protected-preparation.json").exists())
        self.assertEqual(self.revision(), 0)

    def test_unsafe_pending_file_is_refused_without_following_or_overwriting(self):
        target = self.root / "target"
        target.write_text(SECRET)
        (self.store / "protected-preparation.json").symlink_to(target)
        status, value = self.invoke("prepare-inputs", str(self.source), "--source-is-nonsecret",
                                    "--expected-revision", "0")
        self.assertEqual((status, value["error"]["code"]), (6, "input_capture_rejected"))
        self.assertEqual(target.read_text(), SECRET)

    def test_legacy_reference_is_not_promoted(self):
        with HostStore.open_existing(self.store, HOST, owner_uid=os.geteuid()) as store, \
                load_host_policy(path=self.policy, owner_uid=os.geteuid()) as policy:
            captured = ProtectedRecorder(store, policy)._capture({"input_id": "config-input",
                "base_directory": str(self.inputs), "path": "private.xml", "classification": "protected"})
            store.record_intent(load_declaration(self.source.read_bytes()), 0,
                                protected_inputs=[captured])
            reference = store._db.execute("SELECT id FROM protected_inputs").fetchone()[0]
        self.source.write_text(self.source.read_text().replace(self.reference, reference))
        status, value = self.invoke("prepare-inputs", str(self.source), "--source-is-nonsecret",
                                    "--expected-revision", "1")
        self.assertEqual((status, value["error"]["code"]), (6, "input_capture_rejected"))

    def test_bounds_and_private_tool_errors_never_publish_capture(self):
        with patch("mpkg_manager.protected_preparation.MAX_PROTECTED_ENTRIES", 0):
            status, value = self.invoke("prepare-inputs", str(self.source), "--source-is-nonsecret",
                                        "--expected-revision", "0")
        self.assertEqual((status, value["error"]["code"]), (6, "input_capture_rejected"))
        self.assertEqual(self.revision(), 0)

    def test_closed_protocol_rejects_caller_capture_bytes(self):
        from mpkg_manager.host_protocol import RequestError, parse_request
        self.prepare()
        wire = json.loads(self.sent[-1])
        for extra in ("raw", "path", "policy", "token", "command", "captures"):
            with self.subTest(extra=extra):
                candidate = json.loads(json.dumps(wire))
                candidate["arguments"][extra] = SECRET
                with self.assertRaises(RequestError):
                    parse_request(json.dumps(candidate).encode())


if __name__ == "__main__":
    unittest.main()
