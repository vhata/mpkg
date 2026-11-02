"""Read-only installed status flow through private stores and fixed query stubs."""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager import host_helper, status_collection
from mpkg_manager._endpoint_process import ProbeResult
from mpkg_manager.cli import main
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_client import _Reply, _TransportFailure
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.host_protocol import RequestError, parse_request
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.query_process import QueryResult
from mpkg_manager.recorded_inputs import RecordedInputError
from mpkg_manager.status_collection import StatusCollectionError, collect_status
from mpkg_manager.status_wire import validate_status
from mpkg_manager.store import HostStore, StoreError


HOST = "12345678-1234-4234-8234-123456789abc"
PRIVATE = "PRIVATE_STATUS_SENTINEL"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


def wire(**changes):
    arguments = {"operation": "status", "expected_revision": None, "source": None,
                 "source_is_nonsecret": False, "selected_components": None, "probe_endpoints": False}
    arguments.update(changes)
    return json.dumps({"version": 1, "verb": "observe", "arguments": arguments}).encode()


class StatusCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.input = self.inputs / "private.conf"
        self.input.write_text(PRIVATE)
        self.policy_path = self.root / "policy.toml"
        self.policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                                   f'allowed_input_roots={json.dumps([str(self.inputs)])}\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.store_path = self.root / "store"
        self.writer = HostStore.create(self.store_path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.writer.close)
        self.recorder = ProtectedRecorder(self.writer, self.policy)
        # Deliberately absent: status must neither open nor provision a lock.
        self.boundary = HostBoundary(policy_path=self.policy_path, store_directory=self.store_path,
                                     mutation_lock=self.root / "missing.lock", owner_uid=os.geteuid())
        self.source = self.root / "working.toml"
        self.calls, self.queries, self.probes = [], [], []
        self.hook = None
        for target in ("subprocess.Popen", "socket.socket"):
            guard = patch(target, side_effect=AssertionError("unexpected real host operation"))
            guard.start()
            self.addCleanup(guard.stop)
        native = patch.object(status_collection.observe_native, "run_readonly", side_effect=self.native)
        native.start()
        self.addCleanup(native.stop)
        probe = patch("mpkg_manager.observe_endpoint.run_probe", side_effect=self.endpoint)
        probe.start()
        self.addCleanup(probe.stop)

    def native(self, argv, **kwargs):
        self.queries.append(argv)
        if self.hook:
            self.hook()
        values = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                  "UnitFileState": "enabled", "Type": "simple", "MainPID": "123",
                  "InvocationID": "1234567890abcdef1234567890abcdef",
                  "ActiveEnterTimestampMonotonic": "100000"}
        return QueryResult("ok", "".join(f"{key}={value}\n" for key, value in values.items()).encode())

    def endpoint(self, url, timeout):
        self.probes.append((url, timeout))
        return ProbeResult("ok", 200)

    def declaration(self, *, inputs=False, protected=None, endpoint=False, logical="app", running=True):
        source = f'''schema=1
[[components]]
id="selected"
purpose="Status fixture"
resources=["{logical}"]
[[components]]
id="other"
purpose="Unselected fixture"
resources=[]
[[resources]]
id="{logical}"
kind="service"
identity={{manager="system",unit="private-app.service"}}
manage=["running"]
desired={{running={str(running).lower()}}}
checks=["check"]
'''
        if inputs:
            source += 'input={bundle="bundle"}\n'
        if endpoint:
            source += f'''[[checks]]
id="check"
kind="endpoint"
resource="{logical}"
url="http://127.0.0.1:12345/{PRIVATE}"
expected_status=200
timeout_seconds=1
'''
        else:
            source += f'''[[checks]]
id="check"
kind="service"
resource="{logical}"
expected={{running={str(running).lower()}}}
timeout_seconds=1
'''
        if inputs:
            classification = ('classification="protected",reference=' + json.dumps(protected)
                              if protected else 'classification="nonsecret"')
            source += f'''[[inputs]]
id="bundle"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="private.conf",{classification}}}]
'''
        return load_declaration(source.encode())

    def record(self, declaration=None, *, adopt=True, capture=True):
        declaration = self.declaration() if declaration is None else declaration
        revision = self.writer.current()["revision"]
        if adopt:
            method = self.recorder.adopt_all_inputs if capture else self.writer.adopt
            method(declaration, revision, [declaration.model["resources"][0]["id"]])
        else:
            method = self.recorder.record_all_inputs if capture else self.writer.record_intent
            method(declaration, revision)
        return declaration

    def sender(self, raw):
        self.calls.append(raw)
        response = handle_request(raw, boundary=self.boundary)
        return _Reply(response, 0 if json.loads(response)["ok"] else 2)

    def invoke(self, *args, sender=None, human=False):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["status", *args, *([] if human else ["--json"])],
                        _sender=self.sender if sender is None else sender)
        raw = output.getvalue()
        for forbidden in (PRIVATE, str(self.inputs), self.input.name, "private-app.service"):
            self.assertNotIn(forbidden, raw)
        return code, raw if human else json.loads(raw)

    def result(self, *args):
        code, value = self.invoke(*args)
        self.assertEqual(code, 0, value)
        return value["result"]

    def files(self):
        return {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                for p in self.store_path.iterdir()}

    def test_recorded_status_is_readonly_and_uses_no_mutation_lock(self):
        self.record()
        before = self.files()
        with patch.object(HostStore, "open_existing", side_effect=AssertionError("writable open")), \
                patch.object(host_helper, "_mutation_lock", side_effect=AssertionError("mutation lock")):
            result = self.result()
        self.assertEqual(self.files(), before)
        self.assertTrue(result["report"]["target"]["recorded"])
        self.assertEqual(result["report"]["resources"][0]["properties"][0]["comparison"], "agreement")
        self.assertEqual(len(self.queries), 2)
        self.assertFalse(result["report"]["executable"])
        self.assertEqual(result["report"]["recorded_inputs"]["coverage"], "complete")

    def test_no_snapshot_is_explicit_and_missing_store_is_not_created(self):
        code, value = self.invoke()
        self.assertEqual((code, value["error"]["code"]), (6, "status_no_recorded_snapshot"))
        self.boundary._store_directory = self.root / "missing"
        code, value = self.invoke()
        self.assertEqual((code, value["error"]["code"]), (6, "store_missing"))
        self.assertFalse((self.root / "missing").exists())
        self.assertEqual(self.queries, [])

    def test_working_tree_at_revision_zero_is_explicitly_unrecorded(self):
        self.source.write_bytes(self.declaration().source_bytes)
        result = self.result(str(self.source), "--source-is-nonsecret")
        self.assertEqual(result["collection"]["revision"], 0)
        self.assertFalse(result["report"]["target"]["recorded"])
        self.assertEqual(result["report"]["recorded_inputs"]["reason"], "intent_not_recorded")
        self.assertEqual(self.writer.current()["revision"], 0)

    def test_source_classification_and_utf8_fail_before_transport(self):
        self.source.write_bytes(self.declaration().source_bytes)
        for args in ((str(self.source),), ("--source-is-nonsecret",)):
            self.assertEqual(self.invoke(*args)[0], 2)
        self.source.write_bytes(b"\xff")
        self.assertEqual(self.invoke(str(self.source), "--source-is-nonsecret")[0], 2)
        self.assertEqual(self.calls, [])

    def test_invalid_selection_and_revision_fail_before_host_queries(self):
        self.record()
        self.source.write_bytes(self.declaration().source_bytes)
        self.assertEqual(self.invoke(str(self.source), "--source-is-nonsecret", "--component", "missing")[0], 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.invoke("--expected-revision", "-1")[0], 2)
        code, value = self.invoke("--expected-revision", "0")
        self.assertEqual((code, value["error"]["code"]), (6, "revision_conflict"))
        code, value = self.invoke("--component", "missing")
        self.assertEqual((code, value["error"]["code"]), (6, "invalid_status_selection"))
        self.assertEqual(self.queries, [])

    def test_closed_request_rejects_controls_coercion_and_duplicate_selection(self):
        for changes in ({"program": PRIVATE}, {"budget_seconds": 999}, {"source": EMPTY.source_bytes.decode()},
                        {"source_is_nonsecret": 1}, {"probe_endpoints": 1}, {"expected_revision": True},
                        {"selected_components": ["x", "x"]}, {"selected_components": ["bad/path"]},
                        {"selected_components": "x"}, {"source": 1}, {"expected_revision": 2**63 - 1}):
            with self.subTest(changes=changes), self.assertRaises(RequestError):
                parse_request(wire(**changes))
        parsed = parse_request(wire(selected_components=[]))
        self.assertEqual(parsed.selected_components, ())

    def test_all_input_classes_and_original_accepted_baselines_are_compared(self):
        source = self.record(self.declaration(inputs=True))
        self.input.write_text(PRIVATE + " later")
        self.recorder.record_all_inputs(source, 1)
        before = self.files()
        result = self.result()
        scopes = result["report"]["recorded_inputs"]["scopes"]
        self.assertEqual([[row["state"] for row in scope["entries"]] for scope in scopes], [["same"], ["changed"]])
        self.assertEqual([scope["recorded_revision"] for scope in scopes], [2, 1])
        self.assertEqual(self.files(), before)
        self.assertNotIn(hashlib.sha256(self.input.read_bytes()).hexdigest(), json.dumps(result))

    def test_protected_reference_status_never_captures_or_exports_reference(self):
        prepared = self.recorder.prepare(expected_revision=0, input_id="bundle",
                                         base_directory=str(self.inputs), path=self.input.name)
        source = self.declaration(inputs=True, protected=prepared.reference)
        self.recorder.adopt_all_inputs(source, 0, ["app"], prepared_inputs=[prepared])
        self.source.write_bytes(source.source_bytes)
        with patch.object(ProtectedRecorder, "prepare", side_effect=AssertionError("new capture")), \
                patch.object(ProtectedRecorder, "observe_inputs", side_effect=AssertionError("legacy mode")):
            result = self.result(str(self.source), "--source-is-nonsecret")
        self.assertEqual(result["report"]["protected_inputs"]["entries"][0]["state"], "same")
        self.assertNotIn(prepared.reference, json.dumps(result))

    def test_unrecorded_inputs_are_not_read_or_presented_as_recorded(self):
        source = self.record(self.declaration(inputs=True))
        self.source.write_bytes(source.source_bytes + b"# working edit\n")
        with patch.object(ProtectedRecorder, "observe_recorded_inputs", side_effect=AssertionError("unrecorded reads")):
            result = self.result(str(self.source), "--source-is-nonsecret", "--probe-endpoints")
        self.assertFalse(result["report"]["target"]["recorded"])
        self.assertEqual(result["collection"]["recorded_input_reason"], "status_target_not_recorded")
        self.assertEqual(result["report"]["recorded_inputs"]["reason"], "intent_not_recorded")
        self.assertEqual(self.probes, [])

    def test_legacy_nonsecret_recording_remains_unavailable_without_store_changes(self):
        self.record(self.declaration(inputs=True), capture=False)
        before = self.files()
        result = self.result()
        self.assertEqual(result["report"]["recorded_inputs"]["coverage"], "complete")
        self.assertTrue(all(row["state"] == "unavailable" for scope in result["report"]["recorded_inputs"]["scopes"]
                            for row in scope["entries"]))
        self.assertEqual(self.files(), before)

    def test_unselected_removed_and_relinquished_obligations_remain_visible(self):
        self.record(self.declaration(inputs=True))
        result = self.result("--component", "other")
        self.assertEqual(result["report"]["resources"], [])
        self.assertEqual(result["report"]["unselected_resources"][0]["checks"][0]["result"], "passed")
        self.writer.record_intent(EMPTY, 1)
        result = self.result()
        stable_id = result["report"]["retained_resources"][0]["stable_id"]
        self.assertEqual(result["report"]["recorded_inputs"]["scopes"][1]["entries"][0]["state"], "same")
        self.writer.relinquish([stable_id], 2)
        result = self.result()
        self.assertEqual(result["report"]["retained_resources"][0]["management"], "relinquished")
        self.assertEqual(result["report"]["recorded_inputs"]["scopes"][1]["management"], "relinquished")

    def test_retained_dependency_consumer_input_obligation_comes_from_original_history(self):
        source = load_declaration(f'''schema=1
[[components]]
id="consumer"
purpose="Retained dependency fixture"
resources=["app", "config"]
requirements=[{{resource="config",property="content_input",value="bundle"}}]
[[resources]]
id="app"
kind="service"
identity={{manager="system",unit="private-app.service"}}
requires=["config"]
[[resources]]
id="config"
kind="file"
identity={{path={json.dumps(str(self.input))}}}
[[inputs]]
id="bundle"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="private.conf",classification="nonsecret"}}]
'''.encode())
        self.recorder.adopt_all_inputs(source, 0, ["app"])
        self.writer.record_intent(EMPTY, 1)
        self.input.write_text(PRIVATE + " drift")
        result = self.result()
        scopes = result["report"]["recorded_inputs"]["scopes"]
        self.assertEqual(scopes[0]["entries"], [])
        self.assertEqual(scopes[1]["entries"], [{"input_id": "bundle", "file_index": 0,
                                               "classification": "nonsecret", "state": "changed"}])

    def test_full_schema_accepts_existing_adapter_report_variants(self):
        import test_manager_status_collection as fixtures
        fixture = fixtures.StatusCollectionTests()
        fixture.setUp()
        try:
            body = fixtures.package(version=True) + fixtures.compose() + fixtures.service() + '''[[resources]]
id="account"
kind="user"
identity={name="fixture-user"}
desired={present=true,home="/home/fixture",shell="/usr/bin/nologin",groups=["unverified"]}
[[resources]]
id="group"
kind="group"
identity={name="fixture-group"}
desired={present=true,members=["unverified"]}
[[resources]]
id="volume"
kind="volume"
identity={engine="local",name="data"}
desired={present=true}
'''
            source = fixtures.declaration(body)
            fixture.record(source, adopt=True)
            result = fixture.collect(source, complete_inputs=True)
            validate_status(result, parse_request(wire()))
            self.assertFalse(result["report"]["executable"])
        finally:
            fixture.doCleanups()

    def test_endpoint_probes_are_explicit_and_exactly_recorded(self):
        source = self.record(self.declaration(endpoint=True))
        self.result()
        self.assertEqual(self.probes, [])
        self.source.write_bytes(source.source_bytes + b"# different\n")
        self.result(str(self.source), "--source-is-nonsecret", "--probe-endpoints")
        self.assertEqual(self.probes, [])
        result = self.result("--probe-endpoints")
        self.assertEqual(len(self.probes), 1)
        checks = result["report"]["resources"][0]["checks"]
        self.assertEqual([row["route_result"] for row in checks], ["match", "match"])
        self.assertEqual([row["result"] for row in checks], ["unknown", "unknown"])

    def test_revision_change_between_target_load_and_collection_refuses_queries(self):
        self.record()
        original = host_helper.collect_status
        def changed(*args, **kwargs):
            self.writer.record_intent(EMPTY, 1)
            return original(*args, **kwargs)
        with patch.object(host_helper, "collect_status", side_effect=changed):
            code, value = self.invoke()
        self.assertEqual((code, value["error"]["code"]), (6, "revision_conflict"))
        self.assertEqual(self.queries, [])

    def test_revision_change_during_queries_returns_no_mixed_report(self):
        self.record()
        def changed():
            self.hook = None
            self.writer.record_intent(EMPTY, 1)
        self.hook = changed
        code, value = self.invoke()
        self.assertEqual((code, value["error"]["code"]), (6, "status_context_changed"))
        self.assertNotIn("result", value)

    def test_manifest_failure_refuses_queries_and_raw_errors_are_sanitized(self):
        self.record()
        with patch.object(HostStore, "current_with_inputs", side_effect=StoreError(PRIVATE)):
            code, value = self.invoke()
        self.assertEqual((code, value["error"]["code"]), (6, "status_unavailable"))
        self.assertEqual(self.queries, [])

    def test_input_failure_keeps_properties_but_explicitly_loses_input_evidence(self):
        self.record(self.declaration(inputs=True))
        with patch.object(ProtectedRecorder, "observe_recorded_inputs", side_effect=RecordedInputError(PRIVATE)):
            result = self.result()
        self.assertEqual(result["report"]["resources"][0]["properties"][0]["comparison"], "agreement")
        self.assertEqual(result["report"]["recorded_inputs"]["reason"], "not_observed")
        self.assertEqual(result["collection"]["recorded_input_reason"], "status_input_observation_unavailable")

    def test_fixed_installed_collection_limits_are_not_request_controls(self):
        self.record()
        original = host_helper.collect_status
        with patch.object(host_helper, "collect_status", wraps=original) as collector:
            self.result("--expected-revision", "1")
        kwargs = collector.call_args.kwargs
        self.assertEqual(kwargs, {"selected_components": None, "probe_endpoints": False,
                                  "complete_inputs": True, "expected_revision": 1, "budget_seconds": 45})
        self.assertTrue(collector.call_args.args[1].readonly)

    def test_helper_rejects_malformed_internal_projection_without_leaking_it(self):
        self.record()
        class BadResult:
            def as_dict(self):
                return {"private": PRIVATE}
        with patch.object(host_helper, "collect_status", return_value=BadResult()):
            code, value = self.invoke()
        self.assertEqual((code, value["category"]), (5, "transport"))
        self.assertNotIn("result", value)

    def test_client_rejects_unknown_fields_free_text_and_false_authority(self):
        self.record()
        valid = self.result()
        mutations = [lambda value: value.update(private=PRIVATE),
                     lambda value: value["report"].update(executable=True),
                     lambda value: value["report"]["resources"][0]["properties"][0].update(value=PRIVATE),
                     lambda value: value["report"]["blockers"].append(PRIVATE),
                     lambda value: value["collection"].update(recorded_input_reason=PRIVATE),
                     lambda value: value["report"]["recorded_inputs"].update(full_input_closure="verified"),
                     lambda value: value["report"]["target"].update(recorded=1),
                     lambda value: value["collection"].update(revision=9),
                     lambda value: value["report"]["blockers"].clear(),
                     lambda value: value["report"]["endpoint_checks"].update(functional_result="passed")]
        for mutate in mutations:
            bad = deepcopy(valid)
            mutate(bad)
            sender = lambda raw: _Reply(json.dumps({"version": 1, "ok": True, "result": bad}).encode(), 0)
            code, value = self.invoke(sender=sender)
            self.assertEqual((code, value["error"]["code"]), (5, "invalid_helper_response"))

    def test_client_rejects_foreign_target_selection_and_revision(self):
        self.record()
        valid = self.result()
        def sender(raw):
            return _Reply(json.dumps({"version": 1, "ok": True, "result": valid}).encode(), 0)
        self.source.write_bytes(self.declaration(running=False).source_bytes)
        for args in ((str(self.source), "--source-is-nonsecret"), ("--component", "other"), ("--expected-revision", "9")):
            code, value = self.invoke(*args, sender=sender)
            self.assertEqual((code, value["error"]["code"]), (5, "invalid_helper_response"))

    def test_transport_interruption_is_not_reported_as_mutation_uncertainty(self):
        def sender(raw):
            raise _TransportFailure("helper_timeout", dispatched=True)
        code, value = self.invoke(sender=sender)
        self.assertEqual((code, value["category"]), (5, "transport"))
        self.assertNotIn("next_step", value)

    def test_human_output_distinguishes_working_intent_and_retained_checks(self):
        self.record()
        self.source.write_bytes(EMPTY.source_bytes)
        code, text = self.invoke(str(self.source), "--source-is-nonsecret", human=True)
        self.assertEqual(code, 0)
        self.assertIn("working-tree (unrecorded)", text)
        self.assertIn("retained; accepted", text)
        self.assertIn("accepted check check: passed", text)
        self.assertIn("attempt history remain unavailable", text)

    def test_collection_rejects_invalid_modes_and_revision_before_queries(self):
        with HostStore.open_readonly(self.store_path, HOST, owner_uid=os.geteuid()) as store:
            for kwargs in ({"complete_inputs": 1}, {"expected_revision": True}, {"expected_revision": -1}):
                with self.assertRaisesRegex(StatusCollectionError, "invalid_status_collection_request"):
                    collect_status(EMPTY, store, self.policy, **kwargs)
            with self.assertRaisesRegex(StatusCollectionError, "status_revision_conflict"):
                collect_status(EMPTY, store, self.policy, expected_revision=1, complete_inputs=True)
        self.assertEqual(self.queries, [])


if __name__ == "__main__":
    unittest.main()
