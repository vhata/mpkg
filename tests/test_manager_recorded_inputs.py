"""Recorded input coverage with real isolated policies, captures and history."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import canonical_json, load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.protected_bindings import BindingError, ProtectedRecorder
from mpkg_manager.protected_capture import capture_protected
from mpkg_manager.recorded_inputs import RecordedInputError, RecordedInputEvidence
from mpkg_manager.store import HostStore, StoreError, _nonsecret_name


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T18:00:00Z"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


class RecordedInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "private-inputs"
        self.inputs.mkdir(mode=0o700)
        self.public = self.inputs / "public.conf"
        self.secret = self.inputs / "private.env"
        self.public.write_bytes(b"EXPLICIT_NONSECRET_SENTINEL=setting\n")
        self.secret.write_bytes(b"PROTECTED_INPUT_SENTINEL=secret\n")
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

    def declaration(self, *, prepared=None, resource_id="app", filename="public.conf", suffix=""):
        files = [{"path": filename, "classification": "nonsecret"}]
        if prepared is not None:
            files.append({"path": self.secret.name, "classification": "protected", "reference": prepared.reference})
        source = f'''schema=1
components=[]
[[resources]]
id={json.dumps(resource_id)}
kind="service"
identity={{manager="system",unit="app.service"}}
manage=["running"]
desired={{running=true}}
input={{bundle="app-inputs"}}
[[inputs]]
id="app-inputs"
base_directory={json.dumps(str(self.inputs))}
files=[{','.join('{' + ','.join(key+'='+json.dumps(value) for key,value in item.items()) + '}' for item in files)}]
{suffix}
'''
        return load_declaration(source.encode())

    def record(self, *, protected=False, all_inputs=True, adopt=True, resource_id="app", filename="public.conf"):
        revision = self.store.current()["revision"]
        prepared = self.recorder.prepare(expected_revision=revision, input_id="app-inputs",
                                        base_directory=str(self.inputs), path=self.secret.name) if protected else None
        declaration = self.declaration(prepared=prepared, resource_id=resource_id, filename=filename)
        kwargs = {"prepared_inputs": [prepared] if prepared else []}
        if adopt:
            method = self.recorder.adopt_all_inputs if all_inputs else self.recorder.adopt
            decision = method(declaration, revision, [resource_id], **kwargs)
        else:
            method = self.recorder.record_all_inputs if all_inputs else self.recorder.record_intent
            decision = method(declaration, revision, **kwargs)
        return declaration, decision

    def collect(self, recorder=None, **changes):
        current = self.store.current()
        return (self.recorder if recorder is None else recorder).observe_recorded_inputs(**{
            "revision": current["revision"], "snapshot_id": current["snapshot_id"],
            "observed_at": WHEN, **changes})

    @staticmethod
    def states(evidence):
        return [[item["state"] for item in scope["entries"]] for scope in evidence.as_dict()["scopes"]]

    def store_files(self):
        return {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                for p in self.store_path.iterdir()}

    def corrupt(self, table, values, where="1=1"):
        with sqlite3.connect(self.store_path / "state.sqlite3") as db:
            trigger = db.execute("SELECT sql FROM sqlite_schema WHERE name=?", (table + "_update",)).fetchone()[0]
            db.execute("DROP TRIGGER " + table + "_update")
            db.execute(f"UPDATE {table} SET " + ",".join(key + "=?" for key in values) + " WHERE " + where,
                       tuple(values.values()))
            db.execute(trigger)

    def test_all_classes_are_recorded_atomically_and_read_only_evidence_is_private(self):
        declaration, decision = self.record(protected=True)
        before = self.store_files()
        with patch("subprocess.Popen", side_effect=AssertionError("no process")), \
                patch.object(self.recorder, "_capture", wraps=self.recorder._capture) as capture:
            evidence = self.collect()
        self.assertEqual(capture.call_count, 2)
        self.assertEqual(self.store_files(), before)
        self.assertEqual(self.states(evidence), [["same", "same"], ["same", "same"]])
        value = evidence.as_dict()
        self.assertEqual(value["snapshot"], self.store.current()["snapshot"])
        self.assertEqual(value["full_input_closure"], "unverified")
        self.assertEqual(value["observed_at"], WHEN)
        self.assertEqual(value["state"], "complete")
        self.assertEqual(value["scopes"][1]["adoption_revision"], decision["revision"])
        self.assertEqual(value["scopes"][0]["entries"][0]["classification"], "nonsecret")
        self.assertEqual(value["scopes"][0]["entries"][1]["classification"], "protected")
        for forbidden in (str(self.inputs), self.public.name, self.secret.name,
                          "EXPLICIT_NONSECRET_SENTINEL", "PROTECTED_INPUT_SENTINEL",
                          hashlib.sha256(self.public.read_bytes()).hexdigest(),
                          declaration.model["inputs"][0]["files"][1]["reference"]):
            self.assertNotIn(forbidden.encode(), evidence.canonical_bytes)
            self.assertNotIn(forbidden, repr(evidence))
        value["scopes"][0]["entries"].clear()
        self.assertEqual(len(evidence.as_dict()["scopes"][0]["entries"]), 2)
        with self.assertRaises(FrozenInstanceError):
            evidence.canonical_bytes = b"{}"

    def test_nonsecret_baseline_is_specific_to_recording_not_latest_identical_snapshot(self):
        declaration, first = self.record()
        self.public.write_bytes(b"new explicitly accepted nonsecret bytes")
        second = self.recorder.record_all_inputs(declaration, first["revision"])
        self.assertEqual(first["snapshot_id"], second["snapshot_id"])
        self.assertEqual(self.states(self.collect()), [["same"], ["changed"]])
        scopes = self.collect().as_dict()["scopes"]
        self.assertEqual([scope["recorded_revision"] for scope in scopes], [2, 1])

    def test_relinquishment_preserves_last_recording_and_original_adoption(self):
        declaration, first = self.record()
        self.public.write_bytes(b"recorded after adoption")
        self.recorder.record_all_inputs(declaration, 1)
        stable_id = self.store.current()["resources"][0]["stable_id"]
        self.store.relinquish([stable_id], 2)
        evidence = self.collect()
        self.assertEqual(evidence.as_dict()["revision"], 3)
        self.assertEqual(self.states(evidence), [["same"], ["changed"]])
        self.assertEqual(evidence.as_dict()["scopes"][1]["management"], "relinquished")
        self.assertEqual([scope["recorded_revision"] for scope in evidence.as_dict()["scopes"]], [2, 1])

    def test_retained_inputs_survive_removal_rename_and_bundle_id_reuse(self):
        original, _ = self.record()
        other = self.inputs / "other.conf"
        other.write_bytes(b"new source")
        changed = self.declaration(resource_id="renamed", filename=other.name)
        self.recorder.record_all_inputs(changed, 1)
        self.public.write_bytes(b"old accepted source changed")
        evidence = self.collect()
        self.assertEqual(self.states(evidence), [["same"], ["changed"]])
        accepted = evidence.as_dict()["scopes"][1]
        self.assertEqual(accepted["resource_id"], "app")
        self.assertNotEqual(accepted["snapshot"], evidence.as_dict()["snapshot"])
        self.store.record_intent(EMPTY, 2)
        self.assertEqual(self.states(self.collect()), [[], ["changed"]])

    def test_readonly_store_can_collect_without_creating_or_recovering_any_file(self):
        self.record(protected=True)
        before = self.store_files()
        with HostStore.open_readonly(self.store_path, HOST, owner_uid=os.geteuid()) as store:
            recorder = ProtectedRecorder(store, self.policy)
            self.assertEqual(self.states(self.collect(recorder)), [["same", "same"], ["same", "same"]])
        self.assertEqual(self.store_files(), before)

    def test_legacy_recording_does_not_invent_nonsecret_baseline(self):
        self.record(protected=True, all_inputs=False)
        before = self.store_files()
        self.assertEqual(self.states(self.collect()), [["unavailable", "same"], ["unavailable", "same"]])
        self.assertEqual(self.store_files(), before)

    def test_later_legacy_record_cannot_reuse_older_nonsecret_baseline(self):
        declaration, _ = self.record()
        self.recorder.record_intent(declaration, 1)
        self.assertEqual(self.states(self.collect()), [["unavailable"], ["same"]])

    def test_legacy_capture_with_matching_name_is_not_an_authenticated_nonsecret_baseline(self):
        declaration = self.declaration()
        captured = capture_protected(self.policy, root=str(self.inputs), relative_path=self.public.name,
            name=_nonsecret_name("app-inputs", self.public.name), purpose="Legacy named capture")
        self.store.adopt(declaration, 0, ["app"], protected_inputs=[captured])
        self.assertEqual(self.states(self.collect()), [["unavailable"], ["unavailable"]])

    def test_current_bytes_and_file_identity_both_matter(self):
        self.record()
        self.public.write_bytes(b"changed bytes")
        self.assertEqual(self.states(self.collect()), [["changed"], ["changed"]])
        self.public.write_bytes(b"EXPLICIT_NONSECRET_SENTINEL=setting\n")
        replacement = self.inputs / "replacement"
        replacement.write_bytes(self.public.read_bytes())
        replacement.replace(self.public)
        self.assertEqual(self.states(self.collect()), [["changed"], ["changed"]])

    def test_failed_read_keeps_remaining_rows_unavailable_without_reusing_budget(self):
        self.record(protected=True)
        self.public.unlink()
        with patch.object(self.recorder, "_capture", wraps=self.recorder._capture) as capture:
            evidence = self.collect()
        self.assertEqual(capture.call_count, 1)
        self.assertEqual(self.states(evidence), [["unavailable", "unavailable"], ["unavailable", "unavailable"]])
        self.assertEqual(evidence.as_dict()["state"], "complete")

    def test_failed_nonsecret_capture_publishes_no_decision_or_prepared_capture(self):
        before = self.store_files()
        prepared = self.recorder.prepare(expected_revision=0, input_id="app-inputs",
                                        base_directory=str(self.inputs), path=self.secret.name)
        declaration = self.declaration(prepared=prepared, filename="missing")
        with self.assertRaises(BindingError):
            self.recorder.adopt_all_inputs(declaration, 0, ["app"], prepared_inputs=[prepared])
        self.assertEqual(self.store.current()["revision"], 0)
        self.assertEqual(self.store_files(), before)

    def test_policy_revocation_invalidates_every_role(self):
        self.record()
        original = self.recorder._capture
        def revoke(entry, **kwargs):
            result = original(entry, **kwargs)
            self.policy_path.chmod(0o644)
            return result
        with patch.object(self.recorder, "_capture", side_effect=revoke):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["reason"], "policy_unavailable")
        self.assertEqual(self.states(evidence), [["unavailable"], ["unavailable"]])

    def test_revision_change_invalidates_every_role(self):
        self.record(protected=True)
        original = self.recorder._capture
        done = False
        def change(entry, **kwargs):
            nonlocal done
            result = original(entry, **kwargs)
            if not done:
                done = True
                self.store.record_intent(EMPTY, 1)
            return result
        current = self.store.current()
        with patch.object(self.recorder, "_capture", side_effect=change):
            evidence = self.recorder.observe_recorded_inputs(revision=1, snapshot_id=current["snapshot_id"], observed_at=WHEN)
        self.assertEqual(evidence.as_dict()["reason"], "target_changed")
        self.assertEqual(self.states(evidence), [["unavailable", "unavailable"], ["unavailable", "unavailable"]])

    def test_empty_manifest_still_rechecks_policy_and_current_revision(self):
        decision = self.recorder.record_all_inputs(EMPTY, 0)
        original = self.recorder._policy_context
        count = 0
        def change():
            nonlocal count
            count += 1
            result = original()
            if count == 1:
                self.store.record_intent(EMPTY, 1)
            return result
        with patch.object(self.recorder, "_policy_context", side_effect=change):
            evidence = self.recorder.observe_recorded_inputs(revision=1, snapshot_id=decision["snapshot_id"])
        self.assertEqual(evidence.as_dict()["reason"], "target_changed")
        self.assertEqual(self.states(evidence), [[]])

    def test_limits_are_enforced_before_capture_and_total_bytes_are_not_reset_per_role(self):
        self.record(protected=True)
        for constant, value in (("MAX_CAPTURE_COUNT", 1), ("MAX_SCOPE_COUNT", 1), ("MAX_SLOT_COUNT", 3),
                                ("MAX_EVIDENCE_BYTES", 100)):
            with self.subTest(constant=constant), patch("mpkg_manager.recorded_inputs." + constant, value), \
                    patch.object(self.recorder, "_capture", side_effect=AssertionError("must not capture")):
                with self.assertRaises(RecordedInputError) as failure:
                    self.collect()
                self.assertEqual(failure.exception.code, "recorded_input_coverage_limit")
        with patch("mpkg_manager.recorded_inputs.MAX_CAPTURE_BYTES", len(self.public.read_bytes())):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["reason"], "input_limit")
        self.assertEqual(self.states(evidence), [["unavailable", "unavailable"], ["unavailable", "unavailable"]])

    def test_empty_files_fit_zero_byte_collection_budget(self):
        self.public.write_bytes(b"")
        self.record()
        with patch("mpkg_manager.recorded_inputs.MAX_CAPTURE_BYTES", 0):
            self.assertEqual(self.states(self.collect()), [["same"], ["same"]])

    def test_nonsecret_reference_cannot_be_replayed_as_protected(self):
        self.record()
        reference = self.store._db.execute("SELECT id FROM protected_inputs").fetchone()[0]
        current = self.store.current()
        with self.store._read():
            self.assertIsNone(self.store._bound_capture(reference, current["snapshot_id"], 1))
        declaration = load_declaration(self.declaration().source_bytes.replace(
            b'classification="nonsecret"', f'classification="protected",reference="{reference}"'.encode()))
        with self.assertRaises(BindingError) as failure:
            self.recorder.record_intent(declaration, 1)
        self.assertEqual(failure.exception.code, "binding_unavailable")
        self.assertEqual(self.store.current()["revision"], 1)

    def test_nonsecret_token_or_origin_tampering_is_detected_on_reopen(self):
        self.record()
        token = self.store._db.execute("SELECT token FROM protected_inputs").fetchone()[0]
        self.assertTrue(token.startswith(b"MPKGNSC\x00\x01"))
        self.corrupt("protected_inputs", {"token": token[:-1] + bytes([token[-1] ^ 1])})
        self.store.close()
        with self.assertRaises(StoreError) as failure:
            HostStore.open_readonly(self.store_path, HOST, owner_uid=os.geteuid())
        self.assertEqual(failure.exception.code, "store_corrupt")

    def test_relabelled_nonsecret_capture_cannot_supply_another_input_slot(self):
        self.record()
        self.corrupt("decision_inputs", {"name": "nonsecret-v1:" + "a" * 64})
        with self.assertRaises(StoreError) as failure:
            self.store.current()
        self.assertEqual(failure.exception.code, "store_corrupt")

    def test_collection_cancellation_propagates_without_modifying_history(self):
        self.record()
        before = self.store_files()
        with patch.object(self.recorder, "_capture", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.collect()
        self.assertEqual(self.store_files(), before)

    def test_malformed_request_and_projection_fail_with_fixed_diagnostics(self):
        self.record()
        for changes in ({"revision": True}, {"snapshot_id": "PRIVATE_VALUE"}, {"observed_at": "PRIVATE_VALUE"}):
            with self.assertRaises(RecordedInputError) as failure:
                self.collect(**changes)
            self.assertEqual(str(failure.exception), "invalid_recorded_input_request")
        with self.assertRaises(RecordedInputError) as failure:
            self.collect(snapshot_id="a" * 64)
        self.assertEqual(failure.exception.code, "recorded_input_target_unavailable")
        good = self.collect().as_dict()
        variants = [{**good, "observed_at": None}, {**good, "full_input_closure": "verified"},
                    {**good, "extra": "PRIVATE_VALUE"}, {**good, "revision": True},
                    {**good, "scopes": good["scopes"] + [good["scopes"][1]]},
                    {**good, "state": "unavailable", "reason": "target_changed"}]
        invalid = deepcopy(good)
        invalid["scopes"][1]["entries"].append(invalid["scopes"][1]["entries"][0])
        variants.append(invalid)
        contradictory = deepcopy(good)
        contradictory["scopes"][1]["entries"][0]["state"] = "changed"
        variants.append(contradictory)
        for value in variants:
            with self.assertRaises(RecordedInputError) as failure:
                RecordedInputEvidence(canonical_json(value))
            self.assertEqual(str(failure.exception), "invalid_recorded_input_evidence")

    def test_dependency_and_consumer_content_inputs_use_the_original_snapshot(self):
        extra = self.inputs / "extra.conf"
        extra.write_bytes(b"unrelated current input")
        source = f'''schema=1
[[components]]
id="app"
purpose="dependency fixture"
resources=["service","config"]
requirements=[{{resource="config",property="content_input",value="configuration"}}]
[[resources]]
id="service"
kind="service"
identity={{manager="system",unit="app.service"}}
requires=["config"]
[[resources]]
id="config"
kind="file"
identity={{path="/var/lib/example/config"}}
[[inputs]]
id="configuration"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="public.conf",classification="nonsecret"}}]
[[inputs]]
id="unlinked"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="extra.conf",classification="nonsecret"}}]
'''
        declaration = load_declaration(source.encode())
        self.recorder.adopt_all_inputs(declaration, 0, ["service"])
        self.store.record_intent(EMPTY, 1)
        self.public.write_bytes(b"changed accepted dependency")
        evidence = self.collect().as_dict()
        self.assertEqual(evidence["scopes"][0]["entries"], [])
        self.assertEqual(evidence["scopes"][1]["entries"], [{"input_id": "configuration", "file_index": 0,
                                                           "classification": "nonsecret", "state": "changed"}])

    def test_re_adoption_changes_only_that_resources_accepted_baseline(self):
        declaration, _ = self.record()
        self.public.write_bytes(b"new adopted bytes")
        self.recorder.adopt_all_inputs(declaration, 1, ["app"])
        evidence = self.collect()
        self.assertEqual(self.states(evidence), [["same"], ["same"]])
        self.assertEqual(evidence.as_dict()["scopes"][1]["adoption_revision"], 2)


if __name__ == "__main__":
    unittest.main()
