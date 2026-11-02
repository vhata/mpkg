"""Opt-in target comparisons retain exact history roles through installed status."""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta
import hashlib
import io
import json
import os
import unittest
from unittest.mock import patch

from mpkg_manager import status_collection
from mpkg_manager.cli import main
from mpkg_manager.declarations import canonical_json, load_declaration
from mpkg_manager.file_content import FileContentError, FileContentEvidence, FileContentManifest
from mpkg_manager.host_client import _Reply
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.host_protocol import RequestError, parse_request
from mpkg_manager.planning import PlanningError, build_report
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.status_collection import StatusCollectionError, collect_status
from mpkg_manager.status_wire import validate_status
from mpkg_manager.store import HostStore
import test_manager_file_content as fixture
from test_manager_status_cli import wire


NOW = datetime.fromisoformat(fixture.WHEN)
_DEFAULT = object()


class _Identities:
    def user(self, uid):
        return "fixture-user"

    def group(self, gid):
        return "fixture-group"


class FileContentReportingTests(unittest.TestCase):
    setUp = fixture.FileContentTests.setUp
    declaration = fixture.FileContentTests.declaration
    record = fixture.FileContentTests.record
    collect = fixture.FileContentTests.collect
    manifest = fixture.FileContentTests.manifest
    store_files = fixture.FileContentTests.store_files

    def report(self, declaration, *, evidence=_DEFAULT, manifest=_DEFAULT, **kwargs):
        return build_report(declaration, self.store.current_with_inputs(), None, host_id=fixture.HOST,
            now=kwargs.pop("now", NOW), file_content_requested=True,
            file_content_manifest=self.manifest() if manifest is _DEFAULT else manifest,
            file_content_observations=self.collect() if evidence is _DEFAULT else evidence, **kwargs).as_dict()

    @staticmethod
    def property(report):
        return next(row for row in report["resources"][0]["properties"] if row["property"] == "content_input")

    @staticmethod
    def typed(value):
        return FileContentEvidence(canonical_json(value))

    def unavailable(self, report, reason):
        summary = report["file_content"]
        self.assertEqual((summary["state"], summary["reason"]), ("unavailable", reason))
        self.assertEqual(summary["historical_coverage"], "unavailable")
        self.assertTrue(all(row["state"] == "unavailable" for scope in summary["scopes"] for row in scope["entries"]))
        self.assertEqual(self.property(report)["comparison"], "unknown")

    def status(self, declaration, **kwargs):
        with HostStore.open_readonly(self.store_path, fixture.HOST, owner_uid=os.geteuid()) as reader:
            return collect_status(declaration, reader, self.policy, identities=_Identities(),
                                  complete_inputs=True, **kwargs).as_dict()

    def invoke(self, *args, human=False):
        boundary = HostBoundary(policy_path=self.policy_path, store_directory=self.store_path,
            mutation_lock=self.root / "absent-lock", owner_uid=os.geteuid())
        calls = []
        def sender(raw):
            calls.append(raw)
            response = handle_request(raw, boundary=boundary)
            return _Reply(response, 0 if json.loads(response)["ok"] else 2)
        output = io.StringIO()
        with redirect_stdout(output), patch("mpkg_manager.observe_files.SystemIdentities", _Identities), \
                patch("subprocess.Popen", side_effect=AssertionError("no process")), \
                patch("socket.socket", side_effect=AssertionError("no socket")):
            code = main(["status", *args, *([] if human else ["--json"])], _sender=sender)
        text = output.getvalue()
        for forbidden in (str(self.root), self.source.name, self.target.name, fixture.PAYLOAD.decode(),
                          hashlib.sha256(fixture.PAYLOAD).hexdigest()):
            self.assertNotIn(forbidden, text)
        return code, text if human else json.loads(text), calls

    def test_default_has_no_content_evidence_or_target_reads(self):
        declaration, _ = self.record()
        with patch.object(status_collection, "collect_file_content", side_effect=AssertionError("no target read")), \
                patch.object(status_collection, "file_content_manifest", side_effect=AssertionError("not requested")):
            report = self.status(declaration)
            code, value, calls = self.invoke()
        self.assertEqual(code, 0, value)
        self.assertNotIn("file_content", report["report"])
        self.assertEqual(self.property(report["report"])["comparison"], "unknown")
        self.assertNotIn("check_file_content", json.loads(calls[0])["arguments"])

    def test_opt_in_flows_through_helper_and_closed_client_without_mutation(self):
        self.record(consumer=True, protected=True)
        before = self.store_files()
        code, value, calls = self.invoke("--check-file-content")
        self.assertEqual(code, 0, value)
        result = value["result"]
        self.assertTrue(json.loads(calls[0])["arguments"]["check_file_content"])
        self.assertEqual(result["report"]["file_content"]["required_obligations"], 4)
        self.assertEqual(self.property(result["report"])["comparison"], "agreement")
        self.assertEqual(result["collection"]["file_content_reason"], None)
        self.assertEqual(self.store_files(), before)
        code, text, _ = self.invoke("--check-file-content", human=True)
        self.assertEqual(code, 0)
        self.assertIn("Target file content: collected", text)
        self.assertIn("consumer reader", text)
        self.assertIn("accepted ", text)
        self.assertIn("desired", text)

    def test_source_freshness_and_target_bytes_are_independent(self):
        declaration, _ = self.record()
        self.target.write_bytes(b"target changed")
        result = self.status(declaration, check_file_content=True)["report"]
        self.assertEqual(result["recorded_inputs"]["scopes"][0]["entries"][0]["state"], "same")
        self.assertEqual(self.property(result)["comparison"], "difference")
        self.target.write_bytes(fixture.PAYLOAD)
        self.source.write_bytes(b"source changed")
        result = self.status(declaration, check_file_content=True)["report"]
        self.assertEqual(result["recorded_inputs"]["scopes"][0]["entries"][0]["state"], "changed")
        self.assertEqual(self.property(result)["comparison"], "agreement")
        self.assertEqual(result["file_content"]["source_input_freshness"], "not_observed")
        self.assertFalse(result["executable"])

    def test_retained_consumer_does_not_borrow_newer_same_id_baseline(self):
        declaration, _ = self.record(consumer=True)
        self.source.write_bytes(b"new baseline")
        self.target.write_bytes(b"new baseline")
        self.recorder.record_all_inputs(declaration, 1)
        report = self.report(declaration)
        scopes = report["file_content"]["scopes"]
        self.assertEqual([scope["recorded_revision"] for scope in scopes], [2, 1])
        self.assertEqual([[row["state"] for row in scope["entries"]] for scope in scopes],
                         [["same", "same"], ["changed", "changed"]])
        self.assertEqual(self.property(report)["comparison"], "difference")

    def test_old_desired_remains_visible_without_overriding_new_desired(self):
        declaration, _ = self.record()
        self.source.write_bytes(b"new baseline")
        self.target.write_bytes(b"new baseline")
        self.recorder.record_all_inputs(declaration, 1)
        report = self.report(declaration)
        self.assertEqual(self.property(report)["comparison"], "agreement")
        self.assertEqual(report["file_content"]["scopes"][1]["entries"][0]["state"], "changed")
        self.assertIn("file_content_changed", report["blockers"])

    def test_missing_applicable_consumer_evidence_keeps_property_unknown(self):
        declaration, _ = self.record(consumer=True)
        self.recorder.record_all_inputs(declaration, 1)
        evidence = self.collect().as_dict()
        for row in evidence["scopes"][1]["entries"]:
            row.update(state="unavailable", reason="baseline_unavailable")
        report = self.report(declaration, evidence=self.typed(evidence))
        self.assertEqual(report["file_content"]["state"], "available")
        self.assertEqual(self.property(report)["comparison"], "unknown")

    def test_rename_keeps_accepted_consumer_bound_to_original_resource(self):
        self.record(consumer=True)
        declaration = self.declaration(resource_id="renamed", consumer=True)
        self.recorder.record_all_inputs(declaration, 1)
        report = self.report(declaration)
        self.assertEqual(self.property(report)["comparison"], "agreement")
        self.assertEqual(report["file_content"]["scopes"][1]["entries"][1]["resource_id"], "config")

    def test_removed_relinquished_dependency_roles_survive_empty_selection(self):
        self.record(consumer=True, dependency=True, desired=False)
        stable = self.store.current()["resources"][0]["stable_id"]
        self.store.relinquish([stable], 1)
        self.store.record_intent(fixture.EMPTY, 2)
        report = self.report(fixture.EMPTY, selected_components=[])
        scopes = report["file_content"]["scopes"]
        self.assertEqual(scopes[0]["entries"], [])
        self.assertEqual(scopes[1]["management"], "relinquished")
        self.assertEqual(scopes[1]["entries"][0]["requirement"], "consumer")
        self.assertEqual(report["resources"], [])

    def test_legacy_baseline_and_missing_target_remain_unknown(self):
        declaration, _ = self.record(legacy=True)
        report = self.report(declaration)
        self.assertEqual(self.property(report)["comparison"], "unknown")
        self.assertEqual(report["file_content"]["scopes"][0]["entries"][0]["reason"], "baseline_unavailable")
        self.recorder.adopt_all_inputs(declaration, 1, ["config"])
        self.target.unlink()
        report = self.report(declaration)
        self.assertEqual(self.property(report)["comparison"], "unknown")
        self.assertEqual(report["file_content"]["scopes"][0]["entries"][0]["reason"], "target_unavailable")

    def test_json_is_not_a_trusted_manifest_or_evidence(self):
        declaration, _ = self.record()
        for values in ({"manifest": self.manifest().as_dict()}, {"evidence": self.collect().as_dict()}):
            with self.subTest(values=list(values)), self.assertRaises(PlanningError):
                self.report(declaration, **values)
        self.unavailable(self.report(declaration, manifest=None), "manifest_unavailable")
        self.unavailable(self.report(declaration, evidence=None), "not_observed")

    def test_context_age_and_complete_coverage_are_checked_independently(self):
        declaration, _ = self.record(consumer=True)
        original = self.collect().as_dict()
        cases = [
            ("host_mismatch", lambda v: v.update(host_id="22345678-1234-4234-8234-123456789abc")),
            ("target_mismatch", lambda v: v.update(revision=v["revision"] + 1)),
            ("coverage_incomplete", lambda v: v["scopes"].pop()),
            ("coverage_incomplete", lambda v: v["scopes"][0]["entries"].pop()),
            ("coverage_incomplete", lambda v: v["scopes"][0]["entries"][1].update(consumer_id="other")),
            ("scope_mismatch", lambda v: v["scopes"][1].update(management="relinquished")),
        ]
        for reason, mutate in cases:
            value = deepcopy(original)
            mutate(value)
            with self.subTest(reason=reason):
                self.unavailable(self.report(declaration, evidence=self.typed(value)), reason)
        evidence = self.typed(original)
        self.unavailable(self.report(declaration, evidence=evidence, now=NOW + timedelta(seconds=61)), "stale")
        self.unavailable(self.report(declaration, evidence=evidence, now=NOW - timedelta(seconds=1)), "from_future")

    def test_manifest_cannot_drop_declared_or_accepted_obligations(self):
        declaration, _ = self.record(consumer=True)
        for index in (0, 1):
            value = self.manifest().as_dict()
            value["scopes"][index]["entries"].pop()
            self.unavailable(self.report(declaration, manifest=FileContentManifest(canonical_json(value))),
                             "manifest_context_mismatch")

    def test_unrecorded_edit_never_collects_sources_or_target_bytes(self):
        self.record(consumer=True)
        changed = self.declaration(target=self.targets / "edited-target")
        with patch.object(status_collection, "collect_file_content", side_effect=AssertionError("target read")), \
                patch.object(ProtectedRecorder, "observe_recorded_inputs", side_effect=AssertionError("source read")):
            result = self.status(changed, check_file_content=True)
        self.unavailable(result["report"], "intent_not_recorded")
        self.assertEqual(len(result["report"]["file_content"]["scopes"]), 2)
        self.assertEqual(result["collection"]["file_content_reason"], "status_target_not_recorded")

    def test_failure_is_sanitized_and_still_checks_final_manifest(self):
        declaration, _ = self.record()
        original = status_collection.file_content_manifest
        with patch.object(status_collection, "collect_file_content", side_effect=FileContentError(str(self.target))), \
                patch.object(status_collection, "file_content_manifest", wraps=original) as manifest:
            result = self.status(declaration, check_file_content=True)
        self.assertEqual(manifest.call_count, 2)
        self.unavailable(result["report"], "not_observed")
        self.assertEqual(result["collection"]["file_content_reason"], "status_file_content_unavailable")

    def test_changed_final_manifest_refuses_report_even_after_collection_failure(self):
        declaration, _ = self.record()
        first = self.manifest()
        changed = first.as_dict()
        changed["scopes"][1]["management"] = "relinquished"
        with patch.object(status_collection, "collect_file_content", side_effect=FileContentError()), \
                patch.object(status_collection, "file_content_manifest",
                             side_effect=[first, FileContentManifest(canonical_json(changed))]):
            with self.assertRaisesRegex(StatusCollectionError, "status_context_changed"):
                self.status(declaration, check_file_content=True)

    def test_empty_content_scope_still_rechecks_history(self):
        self.store.record_intent(fixture.EMPTY, 0)
        original = status_collection.file_content_manifest
        with patch.object(status_collection, "file_content_manifest", wraps=original) as manifest:
            result = self.status(fixture.EMPTY, check_file_content=True)
        self.assertEqual(manifest.call_count, 2)
        self.assertEqual(result["report"]["file_content"]["required_obligations"], 0)

    def test_late_content_is_discarded_and_history_still_rechecked(self):
        declaration, _ = self.record()
        clock = [0]
        original = status_collection.collect_file_content
        def late(*args, **kwargs):
            result = original(*args, **kwargs)
            clock[0] = 100
            return result
        with patch.object(status_collection.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(status_collection, "collect_file_content", side_effect=late), \
                patch.object(status_collection, "file_content_manifest", wraps=status_collection.file_content_manifest) as manifest:
            result = self.status(declaration, check_file_content=True)
        self.assertEqual(manifest.call_count, 2)
        self.assertEqual(result["collection"]["file_content_reason"], "status_collection_budget_exhausted")
        self.unavailable(result["report"], "not_observed")

    def test_revision_change_after_content_refuses_mixed_result(self):
        declaration, _ = self.record()
        original = status_collection.collect_file_content
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.store.record_intent(declaration, 1)
            return result
        with patch.object(status_collection, "collect_file_content", side_effect=changed):
            with self.assertRaisesRegex(StatusCollectionError, "status_context_changed"):
                self.status(declaration, check_file_content=True)

    def test_contradictory_desired_and_consumer_predicates_stay_conflicted(self):
        self.record(consumer=True)
        declaration = self.declaration(
            suffix=f'[[inputs]]\nid="different"\nbase_directory={json.dumps(str(self.inputs))}\n'
                   'files=[{path="source.conf",classification="nonsecret"}]\n')
        declaration = load_declaration(declaration.source_bytes.replace(
            b'desired={content_input="configuration"}', b'desired={content_input="different"}'))
        self.recorder.record_all_inputs(declaration, 1)
        report = self.report(declaration)
        self.assertEqual(self.property(report)["comparison"], "conflict")
        self.assertTrue(all(row["state"] == "same" for scope in report["file_content"]["scopes"]
                            for row in scope["entries"]))

    def test_closed_wire_rejects_private_fields_and_inconsistent_claims(self):
        self.record()
        code, value, calls = self.invoke("--check-file-content")
        self.assertEqual(code, 0, value)
        original, request = value["result"], parse_request(calls[0])
        mutations = [
            lambda v: v["report"]["file_content"].update(path=str(self.target)),
            lambda v: v["report"]["file_content"]["scopes"][0]["entries"][0].update(digest="secret"),
            lambda v: v["report"]["file_content"].update(required_obligations=99),
            lambda v: v["report"]["file_content"]["scopes"][0]["entries"][0].update(reason="different_bytes"),
            lambda v: v["report"]["file_content"].update(state="unavailable"),
            lambda v: v["report"]["target"].update(recorded=False),
        ]
        for mutate in mutations:
            response = deepcopy(original)
            mutate(response)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                validate_status(response, request)
        with self.assertRaises(ValueError):
            validate_status(original, parse_request(wire()))

    def test_flag_is_strictly_boolean_and_checked_before_authorization(self):
        for value in (None, 0, 1, "true", [], {}):
            raw = wire(check_file_content=value)
            with self.subTest(value=value), self.assertRaises(RequestError):
                parse_request(raw)
            boundary = HostBoundary(policy_path=self.policy_path, store_directory=self.store_path,
                mutation_lock=self.root / "absent-lock", owner_uid=os.geteuid())
            with patch.object(HostBoundary, "dispatch", side_effect=AssertionError("authorization before validation")):
                response = json.loads(handle_request(raw, boundary=boundary))
            self.assertFalse(response["ok"])
        self.assertFalse(parse_request(wire()).check_file_content)
        self.assertTrue(parse_request(wire(check_file_content=True)).check_file_content)
