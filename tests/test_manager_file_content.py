"""Target bytes, authenticated baselines and retained roles in private fixtures."""
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
from mpkg_manager.file_content import (FileContentError, FileContentEvidence, FileContentManifest,
                                       collect_file_content, file_content_manifest)
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.protected_capture import capture_protected
from mpkg_manager.store import HostStore, _nonsecret_name


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T18:00:00Z"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")
PAYLOAD = b"PRIVATE_CONTENT_SENTINEL=expected\n"


class FileContentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "private-inputs"
        self.targets = self.root / "private-targets"
        self.inputs.mkdir(mode=0o700)
        self.targets.mkdir(mode=0o700)
        self.source = self.inputs / "source.conf"
        self.target = self.targets / "target.conf"
        self.source.write_bytes(PAYLOAD)
        self.target.write_bytes(PAYLOAD)
        self.policy_path = self.root / "policy.toml"
        self.policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                                   f'allowed_input_roots={json.dumps([str(self.inputs), str(self.targets)])}\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.store_path = self.root / "records"
        self.store = HostStore.create(self.store_path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)

    def declaration(self, *, reference=None, resource_id="config", filename="source.conf",
                    target=None, consumer=False, desired=True, dependency=False, suffix=""):
        component = (f'[[components]]\nid="reader"\npurpose="Read configuration"\n'
                     f'resources=["{resource_id}"]\n'
                     f'requirements=[{{resource="{resource_id}",property="content_input",value="configuration"}}]\n'
                     if consumer else 'components=[]\n')
        service = ('[[resources]]\nid="service"\nkind="service"\n'
                   'identity={manager="system",unit="private-fixture.service"}\n'
                   f'requires=["{resource_id}"]\n' if dependency else '')
        item = f'path={json.dumps(filename)},classification="nonsecret"'
        if reference is not None:
            item = f'path={json.dumps(filename)},classification="protected",reference={json.dumps(reference)}'
        source = (f'schema=1\n{component}[[resources]]\nid={json.dumps(resource_id)}\nkind="file"\n'
                  f'identity={{path={json.dumps(str(self.target if target is None else target))}}}\n'
                  + ('desired={content_input="configuration"}\n' if desired else '')
                  + f'{service}[[inputs]]\nid="configuration"\nbase_directory={json.dumps(str(self.inputs))}\n'
                  + f'files=[{{{item}}}]\n{suffix}')
        return load_declaration(source.encode())

    def record(self, *, protected=False, legacy=False, adopt=True, **kwargs):
        revision = self.store.current()["revision"]
        preparation = self.recorder.prepare(expected_revision=revision, input_id="configuration",
            base_directory=str(self.inputs), path=kwargs.get("filename", self.source.name)) if protected else None
        declaration = self.declaration(reference=preparation.reference if preparation else None, **kwargs)
        args = {"prepared_inputs": [preparation] if preparation else []}
        if adopt:
            method = self.recorder.adopt if legacy else self.recorder.adopt_all_inputs
            decision = method(declaration, revision, ["service" if kwargs.get("dependency")
                                                     else kwargs.get("resource_id", "config")], **args)
        else:
            method = self.recorder.record_intent if legacy else self.recorder.record_all_inputs
            decision = method(declaration, revision, **args)
        return declaration, decision

    def collect(self, recorder=None, **changes):
        current = self.store.current()
        return collect_file_content(self.recorder if recorder is None else recorder, **{
            "revision": current["revision"], "snapshot_id": current["snapshot_id"],
            "observed_at": WHEN, **changes})

    def manifest(self):
        current = self.store.current()
        return file_content_manifest(self.store, revision=current["revision"], snapshot_id=current["snapshot_id"])

    @staticmethod
    def states(evidence):
        return [[item["state"] for item in scope["entries"]] for scope in evidence.as_dict()["scopes"]]

    def store_files(self):
        return {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                for p in self.store_path.iterdir()}

    def corrupt(self, table, values):
        with sqlite3.connect(self.store_path / "state.sqlite3") as db:
            trigger = db.execute("SELECT sql FROM sqlite_schema WHERE name=?", (table + "_update",)).fetchone()[0]
            db.execute("DROP TRIGGER " + table + "_update")
            db.execute(f"UPDATE {table} SET " + ",".join(key + "=?" for key in values), tuple(values.values()))
            db.execute(trigger)

    def test_matching_source_does_not_hide_target_drift(self):
        self.record()
        self.target.write_bytes(b"manually changed target")
        current = self.store.current()
        sources = self.recorder.observe_recorded_inputs(revision=current["revision"], snapshot_id=current["snapshot_id"])
        self.assertEqual(self.states(sources), [["same"], ["same"]])
        self.assertEqual(self.states(self.collect()), [["changed"], ["changed"]])
        self.assertEqual(self.collect().as_dict()["source_input_freshness"], "not_observed")

    def test_target_agreement_uses_recorded_bytes_without_reading_live_source(self):
        self.record()
        self.source.write_bytes(b"changed source input")
        current = self.store.current()
        sources = self.recorder.observe_recorded_inputs(revision=current["revision"], snapshot_id=current["snapshot_id"])
        self.assertEqual(self.states(sources), [["changed"], ["changed"]])
        self.assertEqual(self.states(self.collect()), [["same"], ["same"]])
        self.source.unlink()
        with patch.object(self.recorder, "_capture", side_effect=AssertionError("no source read")):
            self.assertEqual(self.states(self.collect()), [["same"], ["same"]])
        replacement = self.targets / "replacement"
        replacement.write_bytes(PAYLOAD)
        replacement.replace(self.target)
        self.assertEqual(self.states(self.collect()), [["same"], ["same"]])

    def test_protected_and_nonsecret_baselines_compare_privately_without_store_writes(self):
        for protected in (False, True):
            with self.subTest(protected=protected):
                # Re-recording is deliberate; this also changes each baseline context.
                declaration, _ = self.record(protected=protected)
                before = self.store_files()
                with patch("subprocess.Popen", side_effect=AssertionError("no process")), \
                        patch("mpkg_manager.file_content.capture_protected", wraps=capture_protected) as read:
                    evidence = self.collect()
                self.assertEqual(read.call_count, 1)
                self.assertEqual(self.states(evidence), [["same"], ["same"]])
                self.assertEqual(self.store_files(), before)
                manifest = self.manifest()
                for projection in (evidence, manifest):
                    for forbidden in (str(self.root), self.target.name, self.source.name,
                                      PAYLOAD.decode(), hashlib.sha256(PAYLOAD).hexdigest()):
                        self.assertNotIn(forbidden.encode(), projection.canonical_bytes)
                        self.assertNotIn(forbidden, repr(projection))
                    if protected:
                        self.assertNotIn(declaration.model["inputs"][0]["files"][0]["reference"].encode(), projection.canonical_bytes)
                    value = projection.as_dict()
                    value["scopes"].clear()
                    self.assertTrue(projection.as_dict()["scopes"])
                    with self.assertRaises(FrozenInstanceError):
                        projection.canonical_bytes = b"{}"

    def test_current_and_accepted_keep_their_exact_recording_baselines(self):
        declaration, _ = self.record()
        self.source.write_bytes(b"new baseline")
        self.target.write_bytes(b"new baseline")
        self.recorder.record_all_inputs(declaration, 1)
        self.assertEqual(self.states(self.collect()), [["same"], ["changed"]])
        self.assertEqual([s["recorded_revision"] for s in self.collect().as_dict()["scopes"]], [2, 1])
        self.recorder.adopt_all_inputs(declaration, 2, ["config"])
        self.assertEqual(self.states(self.collect()), [["same"], ["same"]])
        self.assertEqual(self.collect().as_dict()["scopes"][1]["adoption_revision"], 3)

    def test_renaming_removal_relinquishment_and_bundle_reuse_preserve_original_target(self):
        self.record(consumer=True)
        newer = self.inputs / "new-source"
        newer.write_bytes(b"new baseline")
        newer_target = self.targets / "new-target"
        newer_target.write_bytes(b"new baseline")
        changed = self.declaration(resource_id="renamed", filename=newer.name, target=newer_target)
        self.recorder.record_all_inputs(changed, 1)
        self.target.write_bytes(b"old target changed")
        self.assertEqual(self.states(self.collect()), [["same"], ["changed", "changed"]])
        stable = self.store.current()["resources"][0]["stable_id"]
        self.store.relinquish([stable], 2)
        self.assertEqual(self.collect().as_dict()["scopes"][1]["management"], "relinquished")
        self.store.record_intent(EMPTY, 3)
        evidence = self.collect().as_dict()
        self.assertEqual(evidence["scopes"][0]["entries"], [])
        accepted = evidence["scopes"][1]
        self.assertEqual(accepted["resource_id"], "config")
        self.assertEqual([entry["requirement"] for entry in accepted["entries"]], ["desired", "consumer"])
        self.assertEqual([entry["state"] for entry in accepted["entries"]], ["changed", "changed"])

    def test_original_dependency_and_consumer_only_content_obligation_survives_removal(self):
        self.record(consumer=True, desired=False, dependency=True)
        self.store.record_intent(EMPTY, 1)
        self.target.write_bytes(b"changed dependency target")
        evidence = self.collect().as_dict()
        self.assertEqual(evidence["scopes"][1]["resource_id"], "service")
        entry = evidence["scopes"][1]["entries"][0]
        self.assertEqual((entry["resource_id"], entry["requirement"], entry["consumer_id"], entry["state"]),
                         ("config", "consumer", "reader", "changed"))

    def test_readoption_preserves_omitted_consumer_role(self):
        self.record(consumer=True, desired=False)
        declaration = self.declaration(desired=False)
        self.recorder.adopt_all_inputs(declaration, 1, ["config"])
        evidence = self.collect().as_dict()
        self.assertEqual(evidence["scopes"][0]["entries"], [])
        entry = evidence["scopes"][1]["entries"][0]
        self.assertEqual((entry["requirement"], entry["consumer_id"], entry["state"]), ("consumer", "reader", "same"))

    def test_manifest_is_independent_of_target_reads_and_results(self):
        self.record(consumer=True)
        with patch("mpkg_manager.file_content.capture_protected", side_effect=AssertionError("no target read")):
            manifest = self.manifest().as_dict()
        self.target.unlink()
        evidence = self.collect().as_dict()
        for expected_scope, observed_scope in zip(manifest["scopes"], evidence["scopes"]):
            projected = deepcopy(observed_scope)
            for entry in projected["entries"]:
                del entry["state"], entry["reason"]
            self.assertEqual(projected, expected_scope)
        self.assertNotIn("observed_at", manifest)

    def test_legacy_missing_baseline_never_reads_target(self):
        self.record(legacy=True)
        with patch("mpkg_manager.file_content.capture_protected", side_effect=AssertionError("no authenticated baseline")):
            evidence = self.collect()
        self.assertEqual(self.states(evidence), [["unavailable"], ["unavailable"]])
        self.assertEqual(evidence.as_dict()["scopes"][0]["entries"][0]["reason"], "baseline_unavailable")

    def test_later_legacy_record_does_not_borrow_older_nonsecret_baseline(self):
        declaration, _ = self.record()
        self.recorder.record_intent(declaration, 1)
        self.assertEqual(self.states(self.collect()), [["unavailable"], ["same"]])

    def test_generic_legacy_capture_cannot_impersonate_bound_nonsecret_content(self):
        declaration = self.declaration()
        capture = capture_protected(self.policy, root=str(self.inputs), relative_path=self.source.name,
            name=_nonsecret_name("configuration", self.source.name), purpose="Legacy")
        self.store.adopt(declaration, 0, ["config"], protected_inputs=[capture])
        self.assertEqual(self.states(self.collect()), [["unavailable"], ["unavailable"]])

    def test_protected_reference_replay_in_different_snapshot_is_unavailable(self):
        original, _ = self.record(protected=True)
        reference = original.model["inputs"][0]["files"][0]["reference"]
        changed = self.declaration(reference=reference, suffix="# different exact source\n")
        self.store.record_intent(changed, 1)
        self.assertEqual(self.states(self.collect()), [["unavailable"], ["same"]])

    def test_nonsecret_reference_cannot_be_reclassified_as_protected(self):
        self.record()
        reference = self.store._db.execute("SELECT id FROM protected_inputs").fetchone()[0]
        self.store.record_intent(self.declaration(reference=reference), 1)
        evidence = self.collect()
        self.assertEqual(self.states(evidence), [["unavailable"], ["same"]])
        self.assertEqual([s["entries"][0]["classification"] for s in evidence.as_dict()["scopes"]],
                         ["protected", "nonsecret"])

    def test_protected_capture_cannot_supply_reclassified_nonsecret_slot(self):
        self.record(protected=True)
        self.store.record_intent(self.declaration(), 1)
        self.assertEqual(self.states(self.collect()), [["unavailable"], ["same"]])

    def test_token_or_slot_tampering_cannot_supply_expected_bytes(self):
        self.record()
        token = self.store._db.execute("SELECT token FROM protected_inputs").fetchone()[0]
        self.corrupt("protected_inputs", {"token": token[:-1] + bytes([token[-1] ^ 1])})
        with self.assertRaises(FileContentError) as failure:
            collect_file_content(self.recorder, revision=1, snapshot_id="a" * 64)
        self.assertEqual(failure.exception.code, "file_content_store_unavailable")

    def test_relabelled_capture_slot_is_rejected_before_reading_targets(self):
        _, decision = self.record()
        self.corrupt("decision_inputs", {"name": "nonsecret-v1:" + "a" * 64})
        with patch("mpkg_manager.file_content.capture_protected", side_effect=AssertionError("no target read")):
            with self.assertRaises(FileContentError) as failure:
                collect_file_content(self.recorder, revision=1, snapshot_id=decision["snapshot_id"])
        self.assertEqual(failure.exception.code, "file_content_store_unavailable")

    def test_missing_wrong_kind_symlink_hardlink_and_fifo_are_unknown(self):
        self.record()
        for kind in ("missing", "directory", "symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                self.target.unlink()
                if kind == "directory":
                    self.target.mkdir()
                elif kind == "symlink":
                    self.target.symlink_to(self.source)
                elif kind == "hardlink":
                    os.link(self.source, self.target)
                elif kind == "fifo":
                    os.mkfifo(self.target)
                evidence = self.collect()
                self.assertEqual(self.states(evidence), [["unavailable"], ["unavailable"]])
                if kind == "directory":
                    self.target.rmdir()
                elif kind != "missing":
                    self.target.unlink()
                self.target.write_bytes(PAYLOAD)

    def test_parent_symlink_and_target_outside_policy_are_unknown(self):
        alias = self.targets / "alias"
        alias.symlink_to(self.inputs, target_is_directory=True)
        self.record(target=alias / self.source.name)
        self.assertEqual(self.states(self.collect()), [["unavailable"], ["unavailable"]])
        outside = self.root / "outside"
        outside.write_bytes(PAYLOAD)
        self.record(adopt=False, target=outside)
        self.assertEqual(self.collect().as_dict()["scopes"][0]["entries"][0]["reason"], "target_outside_policy")

    def test_in_read_byte_and_path_replacements_remain_unknown(self):
        self.record()
        from mpkg_manager.protected_capture import _read_bounded
        for replace in (False, True):
            with self.subTest(replace=replace):
                def changed(fd, maximum):
                    raw = _read_bounded(fd, maximum)
                    if replace:
                        new = self.targets / "replacement"
                        new.write_bytes(PAYLOAD)
                        new.replace(self.target)
                    else:
                        self.target.write_bytes(b"changed during capture")
                    return raw
                with patch("mpkg_manager.protected_capture._read_bounded", side_effect=changed):
                    evidence = self.collect()
                self.assertEqual(self.states(evidence), [["unavailable"], ["unavailable"]])
                self.assertIn(evidence.as_dict()["scopes"][0]["entries"][0]["reason"],
                              {"target_changed", "target_unsupported"})
                self.target.write_bytes(PAYLOAD)

    def test_parent_replacement_during_read_remains_unknown(self):
        self.record()
        from mpkg_manager.protected_capture import _read_bounded
        def change(fd, maximum):
            raw = _read_bounded(fd, maximum)
            self.targets.rename(self.root / "moved")
            self.targets.mkdir()
            self.target.write_bytes(PAYLOAD)
            return raw
        with patch("mpkg_manager.protected_capture._read_bounded", side_effect=change):
            self.assertEqual(self.states(self.collect()), [["unavailable"], ["unavailable"]])

    def test_policy_or_revision_change_invalidates_all_roles(self):
        self.record(consumer=True)
        def change(*args, **kwargs):
            captured = capture_protected(*args, **kwargs)
            self.store.record_intent(EMPTY, 1)
            return captured
        with patch("mpkg_manager.file_content.capture_protected", side_effect=change):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["reason"], "target_changed")
        self.assertEqual(self.states(evidence), [["unavailable", "unavailable"], ["unavailable", "unavailable"]])
        def revoke(*args, **kwargs):
            captured = capture_protected(*args, **kwargs)
            self.policy_path.chmod(0o644)
            return captured
        with patch("mpkg_manager.file_content.capture_protected", side_effect=revoke):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["reason"], "policy_unavailable")
        self.assertEqual(self.states(evidence), [[], ["unavailable", "unavailable"]])

    def test_empty_collection_rechecks_revision_and_policy(self):
        decision = self.recorder.record_all_inputs(EMPTY, 0)
        original = self.recorder._policy_context
        calls = 0
        def change():
            nonlocal calls
            calls += 1
            result = original()
            if calls == 1:
                self.store.record_intent(EMPTY, 1)
            return result
        with patch.object(self.recorder, "_policy_context", side_effect=change):
            evidence = collect_file_content(self.recorder, revision=1, snapshot_id=decision["snapshot_id"])
        self.assertEqual(evidence.as_dict()["reason"], "target_changed")
        self.policy.close()
        self.assertEqual(self.collect().as_dict()["reason"], "policy_unavailable")

    def test_failed_read_stops_later_contexts_and_still_rechecks_policy(self):
        declaration, _ = self.record()
        self.recorder.record_all_inputs(declaration, 1)
        def denied(*args, **kwargs):
            self.policy_path.chmod(0o644)
            from mpkg_manager.protected_capture import CaptureError
            raise CaptureError("input_unavailable")
        with patch("mpkg_manager.file_content.capture_protected", side_effect=denied) as read:
            evidence = self.collect()
        self.assertEqual(read.call_count, 1)
        self.assertEqual(evidence.as_dict()["reason"], "policy_unavailable")
        self.assertEqual(self.states(evidence), [["unavailable"], ["unavailable"]])

    def test_missing_target_leaves_later_context_unobserved_without_reading_it(self):
        declaration, _ = self.record()
        self.recorder.record_all_inputs(declaration, 1)
        self.target.unlink()
        with patch("mpkg_manager.file_content.capture_protected", wraps=capture_protected) as read:
            evidence = self.collect().as_dict()
        self.assertEqual(read.call_count, 1)
        self.assertEqual(evidence["state"], "complete")
        self.assertEqual([s["entries"][0]["reason"] for s in evidence["scopes"]],
                         ["target_unavailable", "not_observed"])

    def test_store_integrity_change_after_read_invalidates_all_roles(self):
        self.record()
        def corrupt(*args, **kwargs):
            captured = capture_protected(*args, **kwargs)
            token = self.store._db.execute("SELECT token FROM protected_inputs").fetchone()[0]
            self.corrupt("protected_inputs", {"token": token[:-1] + bytes([token[-1] ^ 1])})
            return captured
        with patch("mpkg_manager.file_content.capture_protected", side_effect=corrupt):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["reason"], "store_unavailable")
        self.assertEqual(self.states(evidence), [["unavailable"], ["unavailable"]])

    def test_count_and_size_limits_precede_reads_and_aggregate_overflow_invalidates_matches(self):
        declaration, _ = self.record(consumer=True)
        self.recorder.record_all_inputs(declaration, 1)
        for constant, value in (("MAX_TARGET_COUNT", 1), ("MAX_SCOPE_COUNT", 1),
                                ("MAX_ENTRY_COUNT", 3), ("MAX_EVIDENCE_BYTES", 100)):
            with self.subTest(constant=constant), patch("mpkg_manager.file_content." + constant, value), \
                    patch("mpkg_manager.file_content.capture_protected", side_effect=AssertionError("no read")):
                with self.assertRaises(FileContentError) as failure:
                    self.collect()
                self.assertEqual(failure.exception.code, "file_content_coverage_limit")
        with patch("mpkg_manager.file_content.MAX_TARGET_BYTES", len(PAYLOAD)):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["reason"], "content_limit")
        self.assertEqual(self.states(evidence), [["unavailable", "unavailable"], ["unavailable", "unavailable"]])

    def test_zero_byte_budget_still_accepts_empty_targets(self):
        self.source.write_bytes(b"")
        self.target.write_bytes(b"")
        self.record()
        with patch("mpkg_manager.file_content.MAX_TARGET_BYTES", 0):
            self.assertEqual(self.states(self.collect()), [["same"], ["same"]])

    def test_per_file_limit_refuses_oversized_target_before_content_read(self):
        self.record()
        with patch("mpkg_manager.file_content.MAX_INPUT_BYTES", len(PAYLOAD) - 1), \
                patch("mpkg_manager.protected_capture._read_bounded", side_effect=AssertionError("size is known")):
            evidence = self.collect()
        self.assertEqual(evidence.as_dict()["reason"], "content_limit")
        self.assertEqual(self.states(evidence), [["unavailable"], ["unavailable"]])

    def test_unrecorded_or_wrong_revision_cannot_manufacture_empty_coverage(self):
        with self.assertRaises(FileContentError):
            file_content_manifest(self.store, revision=0, snapshot_id="a" * 64)
        _, decision = self.record()
        self.store.record_intent(EMPTY, 1)
        with self.assertRaises(FileContentError) as failure:
            collect_file_content(self.recorder, revision=1, snapshot_id=decision["snapshot_id"])
        self.assertEqual(failure.exception.code, "file_content_target_unavailable")

    def test_readonly_store_and_cancellation_preserve_history_and_close_descriptors(self):
        self.record()
        before = self.store_files()
        with HostStore.open_readonly(self.store_path, HOST, owner_uid=os.geteuid()) as store:
            self.assertEqual(self.states(self.collect(ProtectedRecorder(store, self.policy))), [["same"], ["same"]])
        descriptors = []
        def interrupt(fd, maximum):
            descriptors.append(fd)
            raise KeyboardInterrupt
        with patch("mpkg_manager.protected_capture._read_bounded", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            self.collect()
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])
        self.assertEqual(self.store_files(), before)

    def test_malformed_requests_and_projection_fields_have_fixed_errors(self):
        self.record(consumer=True)
        for changes in ({"revision": True}, {"snapshot_id": "PRIVATE"}, {"observed_at": "PRIVATE"}):
            with self.assertRaises(FileContentError) as failure:
                self.collect(**changes)
            self.assertEqual(str(failure.exception), "invalid_file_content_request")
        good = self.collect().as_dict()
        variants = [{**good, "observed_at": None}, {**good, "source_input_freshness": "same"},
                    {**good, "application": "ready"}, {**good, "extra": "PRIVATE"},
                    {**good, "scopes": good["scopes"] + [good["scopes"][1]]},
                    {**good, "state": "unavailable", "reason": "target_changed"}]
        for field, value in (("classification", "other"), ("consumer_id", "unexpected"),
                             ("file_index", True), ("reason", "PRIVATE")):
            variant = deepcopy(good)
            variant["scopes"][0]["entries"][0][field] = value
            variants.append(variant)
        contradictory = deepcopy(good)
        contradictory["scopes"][1]["entries"][0].update(state="changed", reason="different_bytes")
        variants.append(contradictory)
        for value in variants:
            with self.assertRaises(FileContentError) as failure:
                FileContentEvidence(canonical_json(value))
            self.assertEqual(str(failure.exception), "invalid_file_content_evidence")
        manifest = self.manifest().as_dict()
        manifest["snapshot"]["id"] = "a" * 64
        with self.assertRaises(FileContentError) as failure:
            FileContentManifest(canonical_json(manifest))
        self.assertEqual(str(failure.exception), "invalid_file_content_manifest")


if __name__ == "__main__":
    unittest.main()
