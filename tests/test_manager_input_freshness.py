"""Actual private policy/store/capture evidence, composed with pure reports."""
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
import uuid

from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.input_evidence import InputEvidenceError, ProtectedInputEvidence
from mpkg_manager.observations import Observation, ObservationBatch
from mpkg_manager.planning import PlanningError, build_report
from mpkg_manager.protected_bindings import BindingError, ProtectedRecorder
from mpkg_manager.protected_capture import CaptureError, capture_protected
from mpkg_manager.store import HostStore, MAX_INPUT_BYTES


HOST = "12345678-1234-4234-8234-123456789abc"
OTHER_HOST = "22345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T08:00:00Z"
NOW = datetime(2026, 11, 2, 8, 0, tzinfo=timezone.utc)


class InputFreshnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "private-input-root"
        self.inputs.mkdir(mode=0o700)
        self.first = self.inputs / "private-first.env"
        self.second = self.inputs / "private-second.env"
        self.first.write_bytes(b"FIRST_SECRET_SENTINEL=value\n")
        self.second.write_bytes(b"SECOND_SECRET_SENTINEL=other\n")
        directory = self.root / "policy"
        directory.mkdir(mode=0o700)
        self.policy_path = directory / "host-policy.toml"
        self.policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                                    f'allowed_input_roots={json.dumps([str(self.inputs)])}\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.store_path = self.root / "records"
        self.store = HostStore.create(self.store_path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)
        self.record()

    def record(self):
        revision = self.store.current()["revision"]
        prepared = [self.recorder.prepare(expected_revision=revision, input_id="app-inputs",
                    base_directory=str(self.inputs), path=path.name) for path in (self.first, self.second)]
        self.references = [item.reference for item in prepared]
        self.declaration = load_declaration(f'''schema=1
[[components]]
id="app"
purpose="shared input fixture"
resources=["first","second"]
[[resources]]
id="first"
kind="service"
identity={{manager="system",unit="first.service"}}
manage=["running"]
desired={{running=true}}
input={{bundle="app-inputs"}}
[[resources]]
id="second"
kind="service"
identity={{manager="system",unit="second.service"}}
manage=["running"]
desired={{running=true}}
input={{bundle="app-inputs"}}
[[inputs]]
id="app-inputs"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="{self.first.name}",classification="protected",reference="{prepared[0].reference}"}},
       {{path="never-read.yaml",classification="nonsecret"}},
       {{path="{self.second.name}",classification="protected",reference="{prepared[1].reference}"}}]
'''.encode())
        self.decision = self.recorder.adopt(self.declaration, revision, ["first", "second"], prepared_inputs=prepared)

    def collect(self, **changes):
        return self.recorder.observe_inputs(**({"revision": self.decision["revision"],
            "snapshot_id": self.decision["snapshot_id"], "observed_at": WHEN} | changes))

    def report(self, evidence=None, *, declaration=None, current=None, now=NOW, selection=None):
        declaration = self.declaration if declaration is None else declaration
        facts = [Observation(HOST, item["id"], item["kind"], item["identity"], "running", "known", True,
                             WHEN, "systemd_unit_properties") for item in declaration.model["resources"]]
        batch = ObservationBatch(HOST, WHEN, tuple(facts), tuple(f.resource_id for f in facts))
        return build_report(declaration, self.store.current() if current is None else current,
                            batch.as_dict(), host_id=HOST, now=now, selected_components=selection,
                            input_observations=evidence)

    def files(self):
        return {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                for path in self.store_path.iterdir()}

    def states(self, evidence):
        return [item["state"] for item in evidence.as_dict()["entries"]]

    def test_real_collection_report_is_complete_immutable_private_and_read_only(self):
        before = self.files()
        with patch("subprocess.Popen", side_effect=AssertionError("Unexpected process")):
            evidence = self.collect()
            report = self.report(evidence)
        self.assertEqual(self.files(), before)
        value = evidence.as_dict()
        self.assertEqual(value["entries"], [{"input_id": "app-inputs", "file_index": 0, "state": "same"},
                                             {"input_id": "app-inputs", "file_index": 2, "state": "same"}])
        self.assertEqual(value["snapshot"], self.store.current()["snapshot"])
        summary = report.as_dict()["protected_inputs"]
        self.assertEqual(summary["state"], "available")
        self.assertEqual(summary["coverage"], "complete")
        self.assertEqual(summary["nonsecret_entries_unchecked"], 1)
        self.assertEqual(summary["historical_coverage"], "unavailable")
        self.assertEqual(summary["full_input_closure"], "unverified")
        self.assertIn("input_freshness_unverified", report.as_dict()["blockers"])
        self.assertFalse(report.as_dict()["executable"])
        value["entries"].clear()
        self.assertEqual(len(evidence.as_dict()["entries"]), 2)
        with self.assertRaises(FrozenInstanceError):
            evidence.canonical_bytes = b"{}"
        for secret in [str(self.inputs), self.first.name, self.second.name, *self.references,
                       "FIRST_SECRET_SENTINEL", "SECOND_SECRET_SENTINEL",
                       hashlib.sha256(self.first.read_bytes()).hexdigest()]:
            self.assertNotIn(secret.encode(), evidence.canonical_bytes)
            self.assertNotIn(secret.encode(), report.canonical_bytes)

    def test_shared_bundles_are_captured_once_even_with_empty_resource_selection(self):
        with patch.object(self.recorder, "_capture", wraps=self.recorder._capture) as capture:
            evidence = self.collect()
        self.assertEqual(capture.call_count, 2)
        result = self.report(evidence, selection=[]).as_dict()
        self.assertEqual(result["resources"], [])
        self.assertEqual(len(result["protected_inputs"]["entries"]), 2)
        self.assertEqual(len(result["unselected_resources"]), 2)

    def test_changed_bytes_identity_and_missing_file_stay_independent_of_property_agreement(self):
        self.first.write_bytes(b"FIRST_SECRET_SENTINEL=changed\n")
        changed = self.collect()
        self.assertEqual(self.states(changed), ["changed", "same"])
        replacement = self.inputs / "replacement"
        replacement.write_bytes(self.second.read_bytes())
        replacement.replace(self.second)
        self.assertEqual(self.states(self.collect()), ["changed", "changed"])
        self.second.unlink()
        missing = self.collect()
        self.assertEqual(self.states(missing), ["changed", "unavailable"])
        result = self.report(missing).as_dict()
        self.assertTrue(all(row["properties"][0]["comparison"] == "agreement" for row in result["resources"]))
        self.assertIn("protected_input_changed", result["blockers"])
        self.assertIn("protected_input_unavailable", result["blockers"])

    def test_missing_evidence_and_unrecorded_comments_are_explicitly_unavailable(self):
        self.assertEqual(self.report().as_dict()["protected_inputs"]["reason"], "not_observed")
        changed = load_declaration(b"# new exact source\n" + self.declaration.source_bytes)
        self.assertEqual(changed.sha256, self.declaration.sha256)
        result = self.report(self.collect(), declaration=changed).as_dict()
        self.assertEqual(result["protected_inputs"]["reason"], "intent_not_recorded")
        self.assertEqual({row["state"] for row in result["protected_inputs"]["entries"]}, {"unavailable"})

    def test_foreign_revision_and_snapshot_evidence_cannot_appear_current(self):
        wire = self.collect().as_dict()
        variants = [({**wire, "host_id": OTHER_HOST}, "host_mismatch"),
                    ({**wire, "revision": 2}, "target_mismatch")]
        for field in ("id", "source_sha256", "canonical_sha256"):
            changed = deepcopy(wire)
            changed["snapshot"][field] = "e" * 64
            variants.append((changed, "target_mismatch"))
        for evidence, reason in variants:
            with self.subTest(reason=reason):
                summary = self.report(evidence).as_dict()["protected_inputs"]
                self.assertEqual(summary["reason"], reason)
                self.assertTrue(all(row["state"] == "unavailable" for row in summary["entries"]))

    def test_collection_start_is_conservative_and_future_evidence_is_unavailable(self):
        evidence = self.collect()
        for now, reason in ((NOW + timedelta(seconds=60), "collected"),
                            (NOW + timedelta(seconds=60, microseconds=1), "stale"),
                            (NOW - timedelta(microseconds=1), "from_future")):
            self.assertEqual(self.report(evidence, now=now).as_dict()["protected_inputs"]["reason"], reason)
        with patch("mpkg_manager.protected_bindings.collection_time", return_value=WHEN) as clock:
            self.collect(observed_at=None)
        clock.assert_called_once_with(None)

    def test_partial_or_extra_coverage_invalidates_all_protected_results(self):
        wire = self.collect().as_dict()
        variants = [wire["entries"][:1], [wire["entries"][0], {**wire["entries"][1], "file_index": 1}],
                    wire["entries"] + [{"input_id": "other", "file_index": 0, "state": "same"}]]
        for entries in variants:
            summary = self.report({**wire, "entries": entries}).as_dict()["protected_inputs"]
            self.assertEqual(summary["reason"], "coverage_incomplete")
            self.assertEqual([row["state"] for row in summary["entries"]], ["unavailable", "unavailable"])

    def test_malformed_evidence_has_fixed_diagnostics(self):
        wire = self.collect().as_dict()
        variants = [{**wire, "revision": True}, {**wire, "source": "PRIVATE_DIAGNOSTIC"},
                    {**wire, "observed_at": None}, {**wire, "observed_at": "not-a-time"},
                    {**wire, "private_path": "PRIVATE_DIAGNOSTIC"},
                    {**wire, "entries": [wire["entries"][0], wire["entries"][0]]},
                    {**wire, "entries": [{"input_id": "app-inputs", "file_index": True, "state": "same"}]}]
        for value in variants:
            with self.assertRaises(PlanningError) as failure:
                self.report(value)
            self.assertEqual(str(failure.exception), "invalid_input_observation_projection")
        with self.assertRaises(InputEvidenceError):
            ProtectedInputEvidence(b'{"private":"PRIVATE_DIAGNOSTIC"}')

    def test_revision_change_after_last_capture_invalidates_the_entire_batch(self):
        capture = self.recorder._capture
        calls = 0
        def changed(*args, **kwargs):
            nonlocal calls
            result = capture(*args, **kwargs)
            calls += 1
            if calls == 2:
                self.store.record_intent(self.declaration, self.decision["revision"])
            return result
        with patch.object(self.recorder, "_capture", changed):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["reason"], "target_changed")
        self.assertEqual(self.states(evidence), ["unavailable", "unavailable"])

    def test_policy_revocation_after_last_capture_invalidates_the_entire_batch(self):
        capture = self.recorder._capture
        calls = 0
        def changed(*args, **kwargs):
            nonlocal calls
            result = capture(*args, **kwargs)
            calls += 1
            if calls == 2:
                self.policy_path.write_bytes(self.policy_path.read_bytes() + b"\n# revoked\n")
            return result
        with patch.object(self.recorder, "_capture", changed):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["reason"], "policy_unavailable")
        self.assertEqual(self.states(evidence), ["unavailable", "unavailable"])

    def test_empty_protected_set_still_rechecks_policy_and_does_not_claim_full_closure(self):
        self.declaration = load_declaration(b'''schema=1
components=[]
resources=[]
[[inputs]]
id="public"
base_directory="/fixture"
files=[{path="never-read",classification="nonsecret"}]
''')
        self.decision = self.store.record_intent(self.declaration, self.decision["revision"])
        fresh = self.report(self.collect()).as_dict()["protected_inputs"]
        self.assertEqual(fresh["state"], "available")
        self.assertEqual(fresh["entries"], [])
        self.assertEqual(fresh["nonsecret_entries_unchecked"], 1)
        self.assertEqual(fresh["full_input_closure"], "unverified")
        context = self.recorder._policy_context
        calls = 0
        def revoked():
            nonlocal calls
            value = context()
            calls += 1
            if calls == 1:
                self.policy_path.write_bytes(self.policy_path.read_bytes() + b"\n# revoked\n")
            return value
        with patch.object(self.recorder, "_policy_context", revoked):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["state"], "unavailable")
        self.assertEqual(evidence.as_dict()["reason"], "policy_unavailable")
        self.assertEqual(evidence.as_dict()["entries"], [])

    def test_historical_collection_is_refused_and_retained_input_coverage_stays_unavailable(self):
        evidence = self.collect()
        empty = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")
        self.store.record_intent(empty, self.decision["revision"])
        with self.assertRaises(BindingError) as failure:
            self.collect()
        self.assertEqual(str(failure.exception), "input_observation_target_unavailable")
        result = self.report(evidence, declaration=empty).as_dict()
        self.assertEqual(result["protected_inputs"]["historical_coverage"], "unavailable")
        self.assertEqual(len(result["retained_resources"]), 2)

    def test_collection_capture_never_holds_the_store_transaction(self):
        capture = self.recorder._capture
        def checked(*args, **kwargs):
            self.assertFalse(self.store._db.in_transaction)
            return capture(*args, **kwargs)
        with patch.object(self.recorder, "_capture", checked):
            self.assertEqual(self.states(self.collect()), ["same", "same"])

    def test_aggregate_bound_uses_remaining_allowance_and_overflow_erases_partial_success(self):
        total = len(self.first.read_bytes()) + len(self.second.read_bytes())
        with patch("mpkg_manager.protected_bindings.MAX_PROTECTED_BYTES", total):
            self.assertEqual(self.states(self.collect()), ["same", "same"])
        with patch("mpkg_manager.protected_bindings.MAX_PROTECTED_BYTES", total - 1), \
             patch.object(self.recorder, "_capture", wraps=self.recorder._capture) as capture:
            evidence = self.collect()
        self.assertEqual(capture.call_args.kwargs["max_bytes"], len(self.second.read_bytes()) - 1)
        self.assertEqual(evidence.as_dict()["reason"], "protected_input_limit")
        self.assertEqual(self.states(evidence), ["unavailable", "unavailable"])

    def test_exhausted_aggregate_budget_still_accepts_empty_files(self):
        self.second.write_bytes(b"")
        self.record()
        with patch("mpkg_manager.protected_bindings.MAX_PROTECTED_BYTES", len(self.first.read_bytes())):
            self.assertEqual(self.states(self.collect()), ["same", "same"])

    def test_lower_capture_bound_cannot_raise_limit_or_accept_invalid_types(self):
        arguments = {"root": str(self.inputs), "relative_path": self.first.name,
                     "name": "bounded", "purpose": "fixture"}
        for maximum in (-1, True, 1.0, MAX_INPUT_BYTES + 1):
            with self.assertRaises(CaptureError) as failure:
                capture_protected(self.policy, **arguments, max_bytes=maximum)
            self.assertEqual(str(failure.exception), "invalid_capture_request")
        with patch("mpkg_manager.protected_capture.os.read", side_effect=AssertionError("Must not read")):
            with self.assertRaises(CaptureError) as failure:
                capture_protected(self.policy, **arguments, max_bytes=len(self.first.read_bytes()) - 1)
            self.assertEqual(str(failure.exception), "input_too_large")

    def test_legacy_unbound_inputs_remain_unavailable(self):
        legacy = load_declaration(self.declaration.source_bytes.replace(self.references[0].encode(),
                                                                        str(uuid.uuid4()).encode()))
        self.declaration = legacy
        self.decision = self.store.record_intent(legacy, self.decision["revision"])
        self.assertEqual(self.states(self.collect()), ["unavailable", "unavailable"])

    def test_failed_capture_stops_further_reads_without_claiming_other_inputs_match(self):
        self.first.unlink()
        with patch.object(self.recorder, "_capture", wraps=self.recorder._capture) as capture:
            evidence = self.collect()
        self.assertEqual(capture.call_count, 1)
        self.assertEqual(self.states(evidence), ["unavailable", "unavailable"])
        self.assertEqual(evidence.as_dict()["state"], "complete")

    def test_excessive_protected_entry_count_is_refused_before_capture(self):
        files = ",".join('{path="file-' + str(index) + '",classification="protected",reference="'
                         + str(uuid.uuid4()) + '"}' for index in range(65))
        self.declaration = load_declaration(('schema=1\ncomponents=[]\nresources=[]\n'
            '[[inputs]]\nid="many"\nbase_directory="/fixture"\nfiles=[' + files + ']\n').encode())
        self.decision = self.store.record_intent(self.declaration, self.decision["revision"])
        with patch.object(self.recorder, "_capture", side_effect=AssertionError("Must not capture")):
            with self.assertRaises(BindingError) as failure:
                self.collect()
        self.assertEqual(str(failure.exception), "protected_input_limit")

    def test_report_consumes_collected_evidence_without_opening_files_or_processes(self):
        evidence = self.collect()
        current = self.store.current()
        with patch("builtins.open", side_effect=AssertionError("Unexpected file read")), \
             patch("os.open", side_effect=AssertionError("Unexpected file read")), \
             patch("subprocess.Popen", side_effect=AssertionError("Unexpected process")):
            report = self.report(evidence, current=current).as_dict()
        self.assertEqual(report["protected_inputs"]["state"], "available")
        self.assertFalse(report["executable"])


if __name__ == "__main__":
    unittest.main()
