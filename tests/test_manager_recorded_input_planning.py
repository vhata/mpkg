"""Pure reports validate input evidence against independently loaded history."""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import canonical_json, load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.observations import Observation, ObservationBatch
from mpkg_manager.planning import PlanningError, build_report
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.recorded_inputs import RecordedInputEvidence, RecordedInputManifest
from mpkg_manager.store import HostStore, StoreError


HOST = "12345678-1234-4234-8234-123456789abc"
OTHER_HOST = "22345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T21:00:00Z"
NOW = datetime(2026, 11, 2, 21, 0, tzinfo=timezone.utc)
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")
_DEFAULT = object()


class RecordedInputPlanningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "private-input-root"
        self.inputs.mkdir(mode=0o700)
        self.public = self.inputs / "private-path-public.conf"
        self.secret = self.inputs / "private-path-secret.env"
        self.public.write_bytes(b"EXPLICIT_PUBLIC_FILE_SENTINEL=config\n")
        self.secret.write_bytes(b"SECRET_REPORT_SENTINEL=hidden\n")
        self.policy_path = self.root / "host-policy.toml"
        self.policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                                    f'allowed_input_roots={json.dumps([str(self.inputs)])}\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.store_path = self.root / "records"
        self.store = HostStore.create(self.store_path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)
        prepared = self.recorder.prepare(expected_revision=0, input_id="app-inputs",
                                        base_directory=str(self.inputs), path=self.secret.name)
        self.reference = prepared.reference
        self.declaration = self.source(reference=self.reference)
        self.recorder.adopt_all_inputs(self.declaration, 0, ["app"], prepared_inputs=[prepared])

    def source(self, *, reference=None, logical="app", filename=None):
        filename = self.public.name if filename is None else filename
        secret = (f',{{path={json.dumps(self.secret.name)},classification="protected",reference="{reference}"}}'
                  if reference else "")
        return load_declaration(f'''schema=1
[[components]]
id="app-component"
purpose="Input reporting fixture"
resources=["{logical}"]
[[resources]]
id="{logical}"
kind="service"
identity={{manager="system",unit="app.service"}}
manage=["running"]
desired={{running=true}}
input={{bundle="app-inputs"}}
[[inputs]]
id="app-inputs"
base_directory={json.dumps(str(self.inputs))}
files=[{{path={json.dumps(filename)},classification="nonsecret"}}{secret}]
'''.encode())

    def collect(self):
        current = self.store.current()
        return self.recorder.observe_recorded_inputs(revision=current["revision"],
            snapshot_id=current["snapshot_id"], observed_at=WHEN)

    def observations(self, declaration):
        facts = tuple(Observation(HOST, resource["id"], resource["kind"], resource["identity"],
            "running", "known", True, WHEN, "systemd_unit_properties")
            for resource in declaration.model["resources"] if resource["kind"] == "service")
        return ObservationBatch(HOST, WHEN, facts, tuple(item.resource_id for item in facts)).as_dict()

    def report(self, evidence=None, *, declaration=None, current=_DEFAULT, **kwargs):
        declaration = self.declaration if declaration is None else declaration
        current = self.store.current_with_inputs() if current is _DEFAULT else current
        return build_report(declaration, current, self.observations(declaration), host_id=HOST,
            now=kwargs.pop("now", NOW), recorded_input_observations=evidence, **kwargs)

    @staticmethod
    def typed(value):
        return RecordedInputEvidence(canonical_json(value))

    def unavailable(self, report, reason):
        summary = report.as_dict()["recorded_inputs"]
        self.assertEqual(summary["state"], "unavailable")
        self.assertEqual(summary["reason"], reason)
        self.assertEqual(summary["coverage"], "unavailable")
        self.assertEqual(summary["historical_coverage"], "unavailable")
        self.assertTrue(all(entry["state"] == "unavailable" for scope in summary["scopes"] for entry in scope["entries"]))
        self.assertTrue(all(entry["state"] == "unavailable" for entry in report.as_dict()["protected_inputs"]["entries"]))
        self.assertIn("recorded_input_unavailable", report.as_dict()["blockers"])
        return summary

    def files(self):
        return {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns) for p in self.store_path.iterdir()}

    def test_all_classifications_and_roles_are_reported_without_application_authority(self):
        report = self.report(self.collect()).as_dict()
        summary = report["recorded_inputs"]
        self.assertEqual((summary["state"], summary["coverage"], summary["historical_coverage"]),
                         ("available", "complete", "complete"))
        self.assertEqual(summary["required_slots"], 4)
        self.assertEqual([scope["role"] for scope in summary["scopes"]], ["current", "accepted"])
        self.assertTrue(all(entry["state"] == "same" for scope in summary["scopes"] for entry in scope["entries"]))
        self.assertEqual(report["protected_inputs"]["entries"], [{"input_id": "app-inputs", "file_index": 1, "state": "same"}])
        self.assertEqual(report["protected_inputs"]["historical_coverage"], "unavailable")
        self.assertEqual(report["protected_inputs"]["nonsecret_entries_unchecked"], 1)
        self.assertEqual(summary["full_input_closure"], "unverified")
        self.assertTrue({"input_freshness_unverified", "application_not_implemented",
                         "attempt_history_unavailable"} <= set(report["blockers"]))
        self.assertFalse(report["executable"])
        self.assertNotIn("actions", report)

    def test_changed_nonsecret_input_does_not_hide_ordinary_property_agreement(self):
        self.public.write_bytes(b"changed nonsecret value")
        report = self.report(self.collect()).as_dict()
        self.assertEqual(report["resources"][0]["properties"][0]["comparison"], "agreement")
        self.assertEqual(report["protected_inputs"]["entries"][0]["state"], "same")
        self.assertIn("recorded_input_changed", report["blockers"])
        self.assertNotIn("protected_input_changed", report["blockers"])
        self.assertEqual([scope["entries"][0]["state"] for scope in report["recorded_inputs"]["scopes"]],
                         ["changed", "changed"])

    def test_identical_toml_recordings_keep_distinct_accepted_byte_baselines(self):
        self.public.write_bytes(b"new recorded version")
        self.recorder.record_all_inputs(self.declaration, 1)
        summary = self.report(self.collect()).as_dict()["recorded_inputs"]
        self.assertEqual([scope["recorded_revision"] for scope in summary["scopes"]], [2, 1])
        self.assertEqual([scope["entries"][0]["state"] for scope in summary["scopes"]], ["same", "changed"])

    def test_removal_rename_and_reused_bundle_ids_preserve_original_accepted_slots(self):
        replacement = self.inputs / "replacement.conf"
        replacement.write_bytes(b"new current input")
        changed = self.source(logical="renamed", filename=replacement.name)
        self.recorder.record_all_inputs(changed, 1)
        self.public.write_bytes(b"old accepted input changed")
        summary = self.report(self.collect(), declaration=changed).as_dict()["recorded_inputs"]
        self.assertEqual([len(scope["entries"]) for scope in summary["scopes"]], [1, 2])
        self.assertEqual(summary["scopes"][1]["resource_id"], "app")
        self.assertEqual(summary["scopes"][1]["entries"][0]["state"], "changed")
        self.store.record_intent(EMPTY, 2)
        summary = self.report(self.collect(), declaration=EMPTY).as_dict()["recorded_inputs"]
        self.assertEqual([len(scope["entries"]) for scope in summary["scopes"]], [0, 2])
        self.assertEqual(summary["scopes"][1]["entries"][0]["state"], "changed")

    def test_relinquished_input_obligations_remain_visible_after_current_removal(self):
        stable = self.store.current()["resources"][0]["stable_id"]
        self.store.relinquish([stable], 1)
        self.store.record_intent(EMPTY, 2)
        report = self.report(self.collect(), declaration=EMPTY).as_dict()
        scope = report["recorded_inputs"]["scopes"][1]
        self.assertEqual((scope["stable_id"], scope["management"], scope["adoption_revision"]),
                         (stable, "relinquished", 1))
        self.assertEqual(len(scope["entries"]), 2)
        self.assertEqual(report["retained_resources"][0]["management"], "relinquished")

    def test_selection_does_not_reduce_input_or_retained_role_coverage(self):
        evidence = self.collect()
        report = self.report(evidence, selected_components=[]).as_dict()
        self.assertEqual(report["resources"], [])
        self.assertEqual(len(report["unselected_resources"]), 1)
        self.assertEqual(report["recorded_inputs"]["required_slots"], 4)
        wire = evidence.as_dict()
        wire["scopes"] = wire["scopes"][:1]
        self.unavailable(self.report(self.typed(wire), selected_components=[]), "coverage_incomplete")

    def test_evidence_cannot_define_its_own_missing_or_extra_coverage(self):
        value = self.collect().as_dict()
        for selected in ((0,), (1,), (0, 1)):
            wire = deepcopy(value)
            for index in selected:
                wire["scopes"][index]["entries"] = wire["scopes"][index]["entries"][:1]
            self.unavailable(self.report(self.typed(wire)), "coverage_incomplete")
        wire = deepcopy(value)
        wire["scopes"][1]["entries"].append({"input_id": "extra", "file_index": 0,
            "classification": "nonsecret", "state": "same"})
        self.unavailable(self.report(self.typed(wire)), "coverage_incomplete")

    def test_current_manifest_is_crosschecked_against_declared_slots(self):
        current = self.store.current_with_inputs()
        evidence = self.collect().as_dict()
        current["input_manifest"]["scopes"][0]["entries"] = current["input_manifest"]["scopes"][0]["entries"][:1]
        evidence["scopes"][0]["entries"] = evidence["scopes"][0]["entries"][:1]
        self.unavailable(self.report(self.typed(evidence), current=current), "manifest_context_mismatch")

    def test_manifest_cannot_hide_direct_accepted_inputs_behind_empty_coverage(self):
        current = self.store.current_with_inputs()
        current["input_manifest"]["scopes"][1]["entries"] = []
        with self.assertRaises(PlanningError) as failure:
            self.report(self.collect(), current=current)
        self.assertEqual(failure.exception.code, "invalid_management_projection")

    def test_classification_is_bound_even_if_evidence_roles_agree_with_each_other(self):
        wire = self.collect().as_dict()
        for scope in wire["scopes"]:
            scope["entries"][1]["classification"] = "nonsecret"
        self.unavailable(self.report(self.typed(wire)), "coverage_incomplete")

    def test_accepted_recording_revision_and_snapshot_metadata_must_match_history(self):
        self.recorder.record_all_inputs(self.declaration, 1)
        original = self.collect().as_dict()
        for field, value in (("adoption_revision", 2), ("resource_id", "other"), ("management", "relinquished")):
            wire = deepcopy(original)
            wire["scopes"][1][field] = value
            if field == "adoption_revision":
                wire["scopes"][1]["recorded_revision"] = value
            self.unavailable(self.report(self.typed(wire)), "scope_mismatch")
        wire = deepcopy(original)
        wire["scopes"][1]["snapshot"]["source_sha256"] = "a" * 64
        self.unavailable(self.report(self.typed(wire)), "scope_mismatch")

    def test_host_current_revision_and_exact_snapshot_binding(self):
        original = self.collect().as_dict()
        for field, value, reason in (("host_id", OTHER_HOST, "host_mismatch"),
                                     ("revision", 2, "target_mismatch")):
            self.unavailable(self.report(self.typed(original | {field: value})), reason)
        for field in ("id", "source_sha256", "canonical_sha256"):
            wire = deepcopy(original)
            wire["snapshot"][field] = "b" * 64
            wire["scopes"][0]["snapshot"][field] = "b" * 64
            self.unavailable(self.report(self.typed(wire)), "target_mismatch")

    def test_stale_future_and_exact_age_boundary(self):
        evidence = self.collect()
        self.unavailable(self.report(evidence, now=NOW + timedelta(seconds=60, microseconds=1)), "stale")
        self.unavailable(self.report(evidence, now=NOW - timedelta(microseconds=1)), "from_future")
        self.assertEqual(self.report(evidence, now=NOW + timedelta(seconds=60)).as_dict()
                         ["recorded_inputs"]["state"], "available")

    def test_source_comment_changes_do_not_reuse_recorded_evidence(self):
        changed = load_declaration(self.declaration.source_bytes + b"\n# different exact source\n")
        self.assertEqual(changed.canonical_bytes, self.declaration.canonical_bytes)
        self.unavailable(self.report(self.collect(), declaration=changed), "intent_not_recorded")

    def test_missing_manifest_history_or_observation_has_explicit_unknown_coverage(self):
        evidence = self.collect()
        self.unavailable(self.report(evidence, current=self.store.current()), "manifest_unavailable")
        self.unavailable(self.report(evidence, current=None), "history_unavailable")
        self.unavailable(self.report(), "not_observed")
        current = self.store.current_with_inputs()
        current["input_manifest"] = None
        self.unavailable(self.report(evidence, current=current), "manifest_unavailable")

    def test_collecting_after_policy_revocation_does_not_preserve_positive_rows(self):
        self.policy_path.chmod(0o644)
        self.unavailable(self.report(self.collect()), "policy_unavailable")

    def test_legacy_only_reports_are_unchanged_and_both_modes_are_rejected(self):
        current = self.store.current()
        legacy = self.recorder.observe_inputs(revision=current["revision"], snapshot_id=current["snapshot_id"], observed_at=WHEN)
        args = {"host_id": HOST, "now": NOW, "input_observations": legacy}
        ordinary = build_report(self.declaration, current, self.observations(self.declaration), **args)
        extended = build_report(self.declaration, self.store.current_with_inputs(), self.observations(self.declaration), **args)
        self.assertEqual(ordinary.canonical_bytes, extended.canonical_bytes)
        self.assertNotIn("recorded_inputs", ordinary.as_dict())
        for value in (legacy, {**legacy.as_dict(), "entries": [{"input_id": "app-inputs", "file_index": 1, "state": "changed"}]}):
            with self.assertRaises(PlanningError) as failure:
                self.report(self.collect(), input_observations=value)
            self.assertEqual(failure.exception.code, "conflicting_input_observation_modes")

    def test_raw_json_and_malformed_typed_evidence_have_fixed_errors(self):
        evidence = self.collect()
        malformed = object.__new__(RecordedInputEvidence)
        for value in (evidence.as_dict(), evidence.canonical_bytes, {}, malformed):
            with self.assertRaises(PlanningError) as failure:
                self.report(value)
            self.assertEqual(failure.exception.code, "invalid_recorded_input_observation")
        wire = evidence.as_dict()
        wire["snapshot"]["normalization_version"] = 2
        object.__setattr__(malformed, "canonical_bytes", canonical_json(wire))
        with self.assertRaises(PlanningError) as failure:
            self.report(malformed)
        self.assertEqual(failure.exception.code, "invalid_recorded_input_observation")

    def test_malformed_manifest_and_role_crossbindings_have_fixed_errors(self):
        good = self.store.current_with_inputs()
        cases = []
        for field, value in (("host_id", OTHER_HOST), ("revision", 2), ("source", "PRIVATE_SENTINEL")):
            changed = deepcopy(good)
            changed["input_manifest"][field] = value
            cases.append(changed)
        changed = deepcopy(good)
        changed["input_manifest"]["scopes"] = changed["input_manifest"]["scopes"][:1]
        cases.append(changed)
        for field, value in (("stable_id", OTHER_HOST), ("resource_id", "other"), ("management", "relinquished")):
            changed = deepcopy(good)
            changed["input_manifest"]["scopes"][1][field] = value
            cases.append(changed)
        changed = deepcopy(good)
        changed["input_manifest"]["scopes"][1]["snapshot"]["source_sha256"] = "a" * 64
        cases.append(changed)
        for current in cases:
            with self.assertRaises(PlanningError) as failure:
                self.report(self.collect(), current=current)
            self.assertEqual(failure.exception.code, "invalid_management_projection")

    def test_report_is_immutable_private_and_performs_no_io(self):
        evidence = self.collect()
        current = self.store.current_with_inputs()
        observations = self.observations(self.declaration)
        before = self.files()
        with ExitStack() as stack:
            for name in ("builtins.open", "os.open", "os.stat", "os.listdir", "pathlib.Path.open",
                         "sqlite3.connect", "socket.socket", "subprocess.Popen",
                         "mpkg_manager.protected_bindings.capture_protected",
                         "mpkg_manager.store.HostStore.current_with_inputs"):
                stack.enter_context(patch(name, side_effect=AssertionError("Unexpected I/O")))
            report = build_report(self.declaration, current, observations, host_id=HOST, now=NOW,
                                  recorded_input_observations=evidence)
        self.assertEqual(self.files(), before)
        public = report.as_dict()
        public["recorded_inputs"]["scopes"].clear()
        self.assertEqual(len(report.as_dict()["recorded_inputs"]["scopes"]), 2)
        with self.assertRaises(FrozenInstanceError):
            report.canonical_bytes = b"{}"
        for forbidden in (str(self.inputs), self.public.name, self.secret.name, self.reference,
                          "EXPLICIT_PUBLIC_FILE_SENTINEL", "SECRET_REPORT_SENTINEL",
                          hashlib.sha256(self.public.read_bytes()).hexdigest(),
                          hashlib.sha256(self.secret.read_bytes()).hexdigest()):
            self.assertNotIn(forbidden.encode(), report.canonical_bytes)

    def test_manifest_projection_reads_history_without_capturing_or_observing_files(self):
        before = self.files()
        with patch("mpkg_manager.protected_bindings.capture_protected", side_effect=AssertionError("no capture")), \
                patch("subprocess.Popen", side_effect=AssertionError("no process")):
            current = self.store.current_with_inputs()
        self.assertEqual(self.files(), before)
        self.assertNotIn("input_manifest", self.store.current())
        manifest = RecordedInputManifest(canonical_json(current["input_manifest"]))
        value = manifest.as_dict()
        self.assertNotIn("observed_at", value)
        self.assertTrue(all("state" not in row for scope in value["scopes"] for row in scope["entries"]))
        value["scopes"].clear()
        self.assertEqual(len(manifest.as_dict()["scopes"]), 2)
        for forbidden in (str(self.inputs), self.public.name, self.secret.name, self.reference):
            self.assertNotIn(forbidden.encode(), manifest.canonical_bytes)

    def test_manifest_generation_refuses_revision_race_and_coverage_limit(self):
        current = self.store.current
        def changed():
            result = current()
            self.store.record_intent(EMPTY, result["revision"])
            return result
        with patch.object(self.store, "current", side_effect=changed), self.assertRaises(StoreError) as failure:
            self.store.current_with_inputs()
        self.assertEqual(failure.exception.code, "input_manifest_unavailable")
        with patch("mpkg_manager.recorded_inputs.MAX_CAPTURE_COUNT", 1), self.assertRaises(StoreError) as failure:
            self.store.current_with_inputs()
        self.assertEqual(failure.exception.code, "input_manifest_unavailable")

    def test_legacy_missing_baselines_keep_complete_declared_coverage_but_unknown_results(self):
        # A new generic decision has no nonsecret capture. Protected references
        # remain bound only to their original exact source/model snapshot.
        self.recorder.record_intent(self.declaration, 1)
        report = self.report(self.collect()).as_dict()
        summary = report["recorded_inputs"]
        self.assertEqual(summary["state"], "available")
        self.assertEqual(summary["coverage"], "complete")
        self.assertEqual(summary["scopes"][0]["entries"][0]["state"], "unavailable")
        self.assertEqual(summary["scopes"][1]["entries"][0]["state"], "same")
        self.assertIn("recorded_input_unavailable", report["blockers"])

    def test_scope_and_slot_order_do_not_change_the_result(self):
        evidence = self.collect()
        original = self.report(evidence)
        changed = evidence.as_dict()
        changed["scopes"].reverse()
        for scope in changed["scopes"]:
            scope["entries"].reverse()
        self.assertEqual(self.report(self.typed(changed)).canonical_bytes, original.canonical_bytes)

    def test_accepted_dependency_content_requirement_coverage_comes_from_history(self):
        declaration = load_declaration(f'''schema=1
[[components]]
id="dependent-component"
purpose="Retained consumer fixture"
resources=["dependent", "configuration"]
requirements=[{{resource="configuration",property="content_input",value="configuration-input"}}]
[[resources]]
id="dependent"
kind="service"
identity={{manager="system",unit="dependent.service"}}
requires=["configuration"]
[[resources]]
id="configuration"
kind="file"
identity={{path="/var/lib/example/private-config"}}
[[inputs]]
id="configuration-input"
base_directory={json.dumps(str(self.inputs))}
files=[{{path={json.dumps(self.public.name)},classification="nonsecret"}}]
'''.encode())
        self.recorder.adopt_all_inputs(declaration, 1, ["dependent"])
        self.store.record_intent(EMPTY, 2)
        self.public.write_bytes(b"changed retained dependency")
        evidence = self.collect()
        current = self.store.current_with_inputs()
        record = next(item for item in current["resources"] if item["logical_id"] == "dependent")
        self.assertEqual(record["accepted_checks"]["definitions"], [])
        summary = self.report(evidence, declaration=EMPTY, current=current).as_dict()["recorded_inputs"]
        scope = next(item for item in summary["scopes"] if item["resource_id"] == "dependent")
        self.assertEqual(scope["entries"], [{"input_id": "configuration-input", "file_index": 0,
                                           "classification": "nonsecret", "state": "changed"}])
        wire = evidence.as_dict()
        next(item for item in wire["scopes"] if item["resource_id"] == "dependent")["entries"] = []
        self.unavailable(self.report(self.typed(wire), declaration=EMPTY, current=current), "coverage_incomplete")

    def test_empty_accepted_scope_cannot_be_omitted_even_with_no_input_files(self):
        declaration = load_declaration(b'''schema=1
components=[]
[[resources]]
id="empty"
kind="service"
identity={manager="system",unit="empty.service"}
''')
        with HostStore.create(self.root / "no-input-store", HOST, owner_uid=os.geteuid()) as store:
            recorder = ProtectedRecorder(store, self.policy)
            decision = recorder.adopt_all_inputs(declaration, 0, ["empty"])
            evidence = recorder.observe_recorded_inputs(revision=1, snapshot_id=decision["snapshot_id"], observed_at=WHEN)
            current = store.current_with_inputs()
        summary = self.report(evidence, declaration=declaration, current=current).as_dict()["recorded_inputs"]
        self.assertEqual((summary["required_slots"], len(summary["scopes"])), (0, 2))
        wire = evidence.as_dict()
        wire["scopes"] = wire["scopes"][:1]
        self.unavailable(self.report(self.typed(wire), declaration=declaration, current=current), "coverage_incomplete")

    def test_uninitialized_store_does_not_claim_complete_empty_history(self):
        with HostStore.create(self.root / "empty-store", HOST, owner_uid=os.geteuid()) as empty:
            current = empty.current_with_inputs()
        self.assertIsNone(current["input_manifest"])
        report = self.report(declaration=EMPTY, current=current)
        self.unavailable(report, "intent_not_recorded")


if __name__ == "__main__":
    unittest.main()
