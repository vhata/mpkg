"""Explicit input capture through the CLI and private installed-boundary fixtures."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.cli import main
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_client import _Reply
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.host_protocol import RequestError, parse_request
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
SECRET = "PRIVATE_CAPTURE_SENTINEL"
EMPTY = b"schema=1\ncomponents=[]\nresources=[]\n"


class RecordingCaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.payload = self.inputs / "source.conf"
        self.payload.write_text(SECRET)
        self.policy = self.root / "policy.toml"
        self.policy.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                               f'allowed_input_roots={json.dumps([str(self.inputs)])}\n')
        self.policy.chmod(0o600)
        runtime = self.root / "run"
        runtime.mkdir(mode=0o700)
        lock = runtime / "apply.lock"
        lock.touch(mode=0o600)
        self.store_path = self.root / "store"
        self.boundary = HostBoundary(policy_path=self.policy, store_directory=self.store_path,
                                     mutation_lock=lock, owner_uid=os.geteuid())
        with HostStore.create(self.store_path, HOST, owner_uid=os.geteuid()):
            pass
        self.source = self.root / "environment.toml"
        self.source.write_text(f'''schema=1
components=[]
[[resources]]
id="config"
kind="file"
identity={{path={json.dumps(str(self.root / "absent-target"))}}}
manage=["content_input"]
desired={{content_input="config-input"}}
[[inputs]]
id="config-input"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="source.conf",classification="nonsecret"}}]
''')
        self.sent = []

    def sender(self, raw):
        self.sent.append(raw)
        response = handle_request(raw, boundary=self.boundary)
        return _Reply(response, 0 if json.loads(response)["ok"] else 2)

    def invoke(self, *args):
        output = io.StringIO()
        with redirect_stdout(output), patch("subprocess.Popen", side_effect=AssertionError("host query")), \
                patch("socket.socket", side_effect=AssertionError("host probe")):
            code = main([*args, "--json"], _sender=self.sender)
        raw = output.getvalue()
        for forbidden in (SECRET, str(self.root), self.payload.name):
            self.assertNotIn(forbidden, raw)
        return code, json.loads(raw)

    def record(self, *, revision=0, adopt=False, capture=True):
        arguments = ["adopt" if adopt else "record", str(self.source), "--source-is-nonsecret",
                     "--expected-revision", str(revision)]
        if adopt:
            arguments += ["--resource", "config"]
        if capture:
            arguments += ["--capture-inputs"]
        return self.invoke(*arguments)

    def state(self):
        with HostStore.open_readonly(self.store_path, HOST, owner_uid=os.geteuid()) as store:
            return store.current(), store.history(), store._db.execute(
                "SELECT count(*) FROM protected_inputs").fetchone()[0]

    def status(self):
        code, value = self.invoke("status")
        self.assertEqual(code, 0, value)
        return value["result"]["report"]["recorded_inputs"]["scopes"]

    def test_explicit_record_captures_bytes_without_changing_source_or_input(self):
        before = self.source.read_bytes(), self.payload.read_bytes(), self.payload.stat().st_mtime_ns
        self.assertEqual(self.record()[0], 0)
        request = parse_request(self.sent[-1])
        self.assertTrue(request.capture_inputs)
        self.assertEqual(request.source, before[0])
        self.assertEqual(self.state()[2], 1)
        self.assertEqual(self.status()[0]["entries"][0]["state"], "same")
        self.assertEqual(before, (self.source.read_bytes(), self.payload.read_bytes(), self.payload.stat().st_mtime_ns))

    def test_legacy_record_does_not_read_or_invent_capture_baselines(self):
        with patch.object(ProtectedRecorder, "_capture", side_effect=AssertionError("implicit read")):
            self.assertEqual(self.record(capture=False)[0], 0)
        self.assertNotIn("capture_inputs", json.loads(self.sent[-1])["arguments"])
        self.assertEqual(self.state()[2], 0)
        self.assertEqual(self.status()[0]["entries"][0]["state"], "unavailable")

    def test_adoption_and_new_intent_keep_distinct_original_baselines(self):
        self.assertEqual(self.record(adopt=True)[0], 0)
        self.payload.write_text("new nonsecret contents")
        self.assertEqual(self.record(revision=1)[0], 0)
        scopes = self.status()
        self.assertEqual({scope["role"]: scope["entries"][0]["state"] for scope in scopes},
                         {"current": "same", "accepted": "changed"})
        self.assertEqual(self.state()[2], 2)

    def test_re_adoption_explicitly_replaces_the_accepted_capture_baseline(self):
        self.assertEqual(self.record(adopt=True)[0], 0)
        self.payload.write_text("changed")
        self.assertEqual(self.record(adopt=True, revision=1)[0], 0)
        self.assertTrue(all(scope["entries"][0]["state"] == "same" for scope in self.status()))

    def test_missing_capture_leaves_no_decision_snapshot_or_capture(self):
        self.payload.unlink()
        before = self.state()
        code, value = self.record()
        self.assertEqual((code, value["error"]["code"]), (6, "input_capture_rejected"))
        self.assertEqual(self.state(), before)

    def test_failure_after_an_earlier_capture_publishes_nothing(self):
        self.source.write_text(self.source.read_text() + f'''[[inputs]]
id="later"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="absent.conf",classification="nonsecret"}}]
''')
        before = self.state()
        self.assertEqual(self.record()[1]["error"]["code"], "input_capture_rejected")
        self.assertEqual(self.state(), before)

    def test_symlink_and_outside_policy_inputs_are_not_captured(self):
        outside = self.root / "outside.conf"
        outside.write_text(SECRET)
        self.payload.unlink()
        self.payload.symlink_to(outside)
        self.assertEqual(self.record()[1]["error"]["code"], "input_capture_rejected")
        self.source.write_text(self.source.read_text().replace(str(self.inputs), str(self.root))
                               .replace("source.conf", "outside.conf"))
        self.assertEqual(self.record()[1]["error"]["code"], "input_capture_rejected")
        self.assertEqual(self.state()[0]["revision"], 0)

    def test_revision_conflict_before_capture_never_reads_inputs(self):
        with patch.object(ProtectedRecorder, "_capture", side_effect=AssertionError("stale read")):
            self.assertEqual(self.record(revision=1)[1]["error"]["code"], "revision_conflict")
        self.assertEqual(self.state()[0]["revision"], 0)

    def test_revision_change_during_capture_does_not_publish_stale_intent(self):
        original = ProtectedRecorder._capture
        def concurrent(recorder, entry, **kwargs):
            captured = original(recorder, entry, **kwargs)
            with HostStore.open_existing(self.store_path, HOST, owner_uid=os.geteuid()) as other:
                other.record_intent(load_declaration(EMPTY), 0)
            return captured
        with patch.object(ProtectedRecorder, "_capture", concurrent):
            self.assertEqual(self.record()[1]["error"]["code"], "revision_conflict")
        current, history, captures = self.state()
        self.assertEqual((current["revision"], len(history), captures), (1, 1, 0))

    def test_revoked_policy_during_capture_prevents_publication(self):
        original = ProtectedRecorder._capture
        def revoke(recorder, entry, **kwargs):
            captured = original(recorder, entry, **kwargs)
            self.policy.write_text(self.policy.read_text().replace(str(self.inputs), str(self.root)))
            return captured
        with patch.object(ProtectedRecorder, "_capture", revoke):
            self.assertEqual(self.record()[1]["error"]["code"], "input_capture_rejected")
        self.assertEqual(self.state()[0]["revision"], 0)

    def test_capture_budget_failure_is_rejected_without_reading(self):
        with patch("mpkg_manager.protected_bindings.MAX_PROTECTED_ENTRIES", 0), \
                patch.object(ProtectedRecorder, "_capture", side_effect=AssertionError("limit read")):
            self.assertEqual(self.record()[1]["error"]["code"], "input_capture_rejected")
        self.assertEqual(self.state()[2], 0)

    def test_commit_uncertainty_is_preserved_without_retrying_capture(self):
        commit = HostStore._commit
        def uncertain(store):
            commit(store)
            raise OSError(SECRET)
        with patch.object(HostStore, "_commit", uncertain):
            code, value = self.record()
        self.assertEqual((code, value["category"], value["error"]["code"]),
                         (7, "uncertain", "commit_outcome_unknown"))
        self.assertEqual(len(self.sent), 1)
        self.assertEqual((self.state()[0]["revision"], self.state()[2]), (1, 1))

    def test_protected_entries_remain_unsupported_before_transport(self):
        self.source.write_text(self.source.read_text().replace('classification="nonsecret"',
                               f'classification="protected",reference="{HOST}"'))
        code, value = self.record()
        self.assertEqual((code, value["error"]["code"]), (2, "protected_recording_unsupported"))
        self.assertEqual(self.sent, [])

    def test_unknown_adoption_selection_is_rejected_before_capture(self):
        with patch.object(ProtectedRecorder, "_capture", side_effect=AssertionError("invalid selection read")):
            code, value = self.invoke("adopt", str(self.source), "--source-is-nonsecret",
                                     "--capture-inputs", "--expected-revision", "0", "--resource", "missing")
        self.assertEqual((code, value["error"]["code"]), (2, "unknown_resource_selection"))
        self.assertEqual(self.sent, [])

    def test_closed_capture_flag_accepts_only_booleans_on_record_and_adopt(self):
        base = {"version": 1, "verb": "record", "arguments": {"operation": "intent",
                "source": self.source.read_text(), "source_is_nonsecret": True, "expected_revision": 0}}
        for flag in (False, True):
            base["arguments"]["capture_inputs"] = flag
            self.assertIs(parse_request(json.dumps(base).encode()).capture_inputs, flag)
        for flag in (0, 1, "true", None, [], {}):
            base["arguments"]["capture_inputs"] = flag
            with self.assertRaises(RequestError):
                parse_request(json.dumps(base).encode())
        for verb, operation in (("record", "initialize"), ("export", "history")):
            bad = {"version": 1, "verb": verb, "arguments": {"operation": operation, "capture_inputs": True}}
            with self.assertRaises(RequestError):
                parse_request(json.dumps(bad).encode())

    def test_capture_flag_cannot_be_used_on_observation_or_relinquishment(self):
        for args in (("status", "--capture-inputs"), ("history", "--capture-inputs"),
                     ("relinquish", "--resource", HOST, "--expected-revision", "0", "--capture-inputs")):
            self.assertEqual(self.invoke(*args)[0], 2)
        self.assertEqual(self.sent, [])


if __name__ == "__main__":
    unittest.main()
