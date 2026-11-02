"""Real private proposal persistence; no host configuration is published."""
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.effect_plans import (ProposalError, derive_sonarr_port_proposal,
    list_sonarr_port_proposals, read_sonarr_port_proposal)
from mpkg_manager import effect_plans as plans
from mpkg_manager import store_migration as migration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.store import HostStore, StoreError, _TRIGGERS, _json


HOST = "12345678-1234-4234-8234-123456789abc"
PRIVATE = "PRIVATE_PROPOSAL_SENTINEL"
RAW = b'<Config keep="yes"><ApiKey>PRIVATE_PROPOSAL_SENTINEL</ApiKey><Port>8989</Port><!--keep--></Config>\n'
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


class ProposalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "private-inputs"
        self.inputs.mkdir(mode=0o700)
        self.xml = self.inputs / "private-config.xml"
        self.xml.write_bytes(RAW)
        self.xml.chmod(0o600)
        self.policy_path = self.root / "private-policy.toml"
        self.policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                                    f'allowed_input_roots={json.dumps([str(self.inputs)])}\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.directory = self.root / "store"
        self.store = HostStore.create(self.directory, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)
        self.record(adopt=True)
        self.stable = next(item["stable_id"] for item in self.store.current()["resources"]
                           if item["logical_id"] == "xml")

    def source(self, reference, *, port=8990, logical="xml", manage=True,
               consumer_port=None, dependency=False, input_binding=True, unit="sonarr.service",
               dependency_input=False):
        component = (f'[[components]]\nid="consumer"\npurpose="Consumer"\nresources=["{logical}"]\n'
            f'requirements=[{{resource="{logical}",property="port",value={consumer_port}}}]\n'
            if consumer_port is not None else "components=[]\n")
        dependency_source = '''[[resources]]
id="service"
kind="service"
identity={manager="system",unit="sonarr.service"}
manage=["running"]
desired={running=true}
checks=["service-running"]
[[checks]]
id="service-running"
kind="service"
resource="service"
expected={running=true}
timeout_seconds=5
'''.replace("sonarr.service", unit) if dependency else ""
        if dependency_input:
            dependency_source = dependency_source.replace('checks=["service-running"]',
                'checks=["service-running"]\ninput={bundle="configuration"}')
        return load_declaration((f'''schema=1
{component}[[resources]]
id="{logical}"
kind="sonarr_xml"
identity={{path={json.dumps(str(self.xml))}}}
manage={json.dumps(["port"] if manage else [])}
desired={{port={port}}}
consumers={json.dumps(["consumer"] if consumer_port is not None else [])}
requires={json.dumps(["service"] if dependency else [])}
''' + ('input={bundle="configuration"}\n' if input_binding else "") +
f'''[[inputs]]
id="configuration"
base_directory={json.dumps(str(self.inputs))}
files=[{{path={json.dumps(self.xml.name)},classification="protected",reference="{reference}"}}]
''' + dependency_source).encode())

    def record(self, *, adopt=False, **kwargs):
        revision = self.store.current()["revision"]
        prepared = self.recorder.prepare(expected_revision=revision, input_id="configuration",
                                         base_directory=str(self.inputs), path=self.xml.name)
        declaration = self.source(prepared.reference, **kwargs)
        if adopt:
            result = self.recorder.adopt(declaration, revision,
                [resource["id"] for resource in declaration.model["resources"]], prepared_inputs=[prepared])
        else:
            result = self.recorder.record_intent(declaration, revision, prepared_inputs=[prepared])
        self.declaration = declaration
        return result

    def propose(self, **kwargs):
        current = self.store.current()
        return derive_sonarr_port_proposal(self.recorder,
            expected_revision=kwargs.pop("expected_revision", current["revision"]),
            snapshot_id=kwargs.pop("snapshot_id", current["snapshot_id"]),
            stable_resource_id=kwargs.pop("stable_resource_id", self.stable), **kwargs)

    def row(self):
        return self.store._db.execute("SELECT * FROM sonarr_port_proposals").fetchone()

    def assert_error(self, code, callback):
        with self.assertRaises((ProposalError, StoreError)) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)
        for private in (PRIVATE, str(self.root)):
            self.assertNotIn(private, str(raised.exception))
            self.assertNotIn(private, repr(raised.exception))

    def corrupt(self, statement, parameters=()):
        with sqlite3.connect(self.directory / "state.sqlite3") as db:
            db.execute("DROP TRIGGER sonarr_port_proposals_update")
            db.execute(statement, parameters)
            db.execute(_TRIGGERS["sonarr_port_proposals_update"])

    def test_real_candidate_is_private_persisted_immutable_and_always_blocked(self):
        before = self.store.current()
        proposal = self.propose()
        public, row = proposal.as_dict(), self.row()
        self.assertEqual(row[10], RAW.replace(b">8989<", b">8990<"))
        self.assertEqual((public["original_port"], public["port"], public["state"], public["executable"]),
                         (8989, 8990, "blocked", False))
        self.assertEqual(self.xml.read_bytes(), RAW)
        self.assertEqual(self.store.current(), before)
        self.assertEqual(read_sonarr_port_proposal(self.store, public["proposal_id"]).as_dict(), public)
        public["blockers"].clear()
        self.assertTrue(proposal.as_dict()["blockers"])
        with self.assertRaises(FrozenInstanceError):
            proposal._summary = b"{}"
        for sql in ("UPDATE sonarr_port_proposals SET state='blocked'", "DELETE FROM sonarr_port_proposals"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.store._db.execute(sql)

    def test_public_projection_omits_paths_references_tokens_digests_and_raw_bytes(self):
        proposal = self.propose()
        row = self.row()
        context = json.loads(row[9])
        public = repr(proposal) + json.dumps(proposal.as_dict())
        for private in (PRIVATE, str(self.root), row[5], row[11].hex(),
                        context["before"]["token"], hashlib.sha256(RAW).hexdigest()):
            self.assertNotIn(private, public)
        self.assertLess(len(public), 8192)

    def test_numerically_unchanged_candidate_keeps_original_bytes_but_no_execution_authority(self):
        self.record(port=8989)
        proposal = self.propose().as_dict()
        self.assertTrue(proposal["unchanged"])
        self.assertEqual(self.row()[10], RAW)
        self.assertFalse(proposal["executable"])

    def test_historical_proposal_remains_bound_after_rename_and_relinquishment(self):
        proposal = self.propose().as_dict()
        original = self.row()
        self.record(port=8991, logical="renamed")
        current = self.propose().as_dict()
        self.assertEqual(current["adoption_revision"], 1)
        self.store.relinquish([self.stable], 2)
        historical = read_sonarr_port_proposal(self.store, proposal["proposal_id"]).as_dict()
        self.assertEqual((historical["decision_state"], historical["port"]), ("superseded", 8990))
        self.assertEqual(self.store._db.execute("SELECT * FROM sonarr_port_proposals WHERE id=?",
                                              (proposal["proposal_id"],)).fetchone(), original)
        self.assert_error("proposal_authority_unavailable", self.propose)

    def test_removed_target_and_unaccepted_authority_do_not_produce_proposals(self):
        self.record(manage=False)
        self.assert_error("proposal_authority_conflict", self.propose)
        self.store.record_intent(EMPTY, 2)
        self.assert_error("proposal_target_unavailable", self.propose)
        self.assertIsNone(self.row())

    def test_retained_consumer_conflict_is_not_discarded_by_new_intent(self):
        self.record(adopt=True, consumer_port=8990)
        self.record(port=8991)
        self.assert_error("consumer_requirement_conflict", self.propose)
        self.assertIsNone(self.row())

    def test_missing_or_unbound_input_reference_fails(self):
        self.record(input_binding=False)
        self.assert_error("proposal_input_unavailable", self.propose)
        source = self.source("23456789-1234-4234-8234-123456789abc")
        self.store.record_intent(source, 2)
        self.assert_error("proposal_input_unavailable", self.propose)

    def test_changed_bytes_or_file_identity_are_rejected(self):
        self.xml.write_bytes(RAW.replace(b"8989", b"8999"))
        self.assert_error("proposal_input_changed", self.propose)
        self.xml.write_bytes(RAW)
        self.assert_error("proposal_input_changed", self.propose)
        self.assertIsNone(self.row())

    def test_input_capture_runs_outside_the_write_transaction(self):
        capture = ProtectedRecorder._capture
        def observe(recorder, entry, **kwargs):
            self.assertFalse(self.store._db.in_transaction)
            return capture(recorder, entry, **kwargs)
        with patch.object(ProtectedRecorder, "_capture", observe):
            self.propose()

    def test_revision_change_during_capture_publishes_no_proposal(self):
        capture = ProtectedRecorder._capture
        def change(recorder, entry, **kwargs):
            result = capture(recorder, entry, **kwargs)
            self.store.record_intent(EMPTY, 1)
            return result
        with patch.object(ProtectedRecorder, "_capture", change):
            self.assert_error("revision_conflict", self.propose)
        self.assertIsNone(self.row())

    def test_policy_replacement_during_capture_is_rejected(self):
        capture = ProtectedRecorder._capture
        def change(recorder, entry, **kwargs):
            result = capture(recorder, entry, **kwargs)
            self.policy_path.write_text(PRIVATE)
            return result
        with patch.object(ProtectedRecorder, "_capture", change):
            self.assert_error("proposal_input_unavailable", self.propose)
        self.assertIsNone(self.row())

    def test_accepted_dependency_checks_and_current_checks_remain_distinct(self):
        self.record(adopt=True, dependency=True)
        self.record(dependency=True)
        public = self.propose().as_dict()
        context = json.loads(self.row()[9])
        self.assertEqual((public["prerequisite_count"], public["accepted_check_count"],
                          public["current_check_count"]), (1, 1, 1))
        self.assertEqual(context["accepted_checks"][1]["adoption_revision"], 2)
        self.assertEqual(context["revision"], 3)
        self.assertIn("prerequisite_readiness_unverified", public["blockers"])

    def test_unaccepted_prerequisite_is_retained_as_a_blocker(self):
        self.record(dependency=True)
        public = self.propose().as_dict()
        self.assertEqual(public["prerequisite_count"], 1)
        self.assertIn("prerequisite_authority_unavailable", public["blockers"])

    def test_retained_prerequisite_scope_survives_removal_and_same_id_reuse(self):
        self.record(adopt=True, dependency=True)
        self.record(dependency=False)
        removed = self.propose().as_dict()
        row = self.store._db.execute("SELECT context FROM sonarr_port_proposals WHERE id=?",
                                    (removed["proposal_id"],)).fetchone()
        scopes = json.loads(row[0])["scopes"]
        self.assertEqual(len(scopes[0]["prerequisites"]), 0)
        self.assertEqual(scopes[1]["revision"], 2)
        self.assertEqual(scopes[1]["prerequisites"][0]["definition"]["identity"]["unit"], "sonarr.service")
        self.assertEqual(scopes[1]["inputs"][0]["origin_revision"], 2)
        self.record(dependency=True, unit="replacement.service")
        reused = self.propose().as_dict()
        raw = self.store._db.execute("SELECT context FROM sonarr_port_proposals WHERE id=?",
                                    (reused["proposal_id"],)).fetchone()[0]
        current, retained = json.loads(raw)["scopes"]
        self.assertEqual(current["prerequisites"][0]["definition"]["identity"]["unit"], "replacement.service")
        self.assertIsNone(current["prerequisites"][0]["stable_id"])
        self.assertEqual(retained["prerequisites"][0]["definition"]["identity"]["unit"], "sonarr.service")
        self.assertEqual(retained["accepted_checks"][0]["adoption_revision"], 2)

    def test_dependency_inputs_keep_their_own_earlier_adoption_snapshot(self):
        self.record(adopt=True, dependency=True, dependency_input=True)
        prepared = self.recorder.prepare(expected_revision=2, input_id="configuration",
                                         base_directory=str(self.inputs), path=self.xml.name)
        declaration = self.source(prepared.reference, dependency=True, dependency_input=True)
        self.recorder.adopt(declaration, 2, ["xml"], prepared_inputs=[prepared])
        self.record(dependency=False)
        self.propose()
        context = json.loads(self.row()[9])
        retained = context["scopes"][1]
        dependency = context["accepted_dependency_scopes"][0]
        self.assertEqual((retained["revision"], dependency["revision"]), (3, 2))
        self.assertNotEqual(retained["snapshot_id"], dependency["snapshot_id"])
        self.assertEqual(dependency["inputs"][0]["origin_revision"], 2)
        self.assertNotEqual(retained["inputs"][0]["entry"]["reference"],
                            dependency["inputs"][0]["entry"]["reference"])

    def test_scope_limit_and_no_process_or_network_effects(self):
        self.record(dependency=True)
        with patch.object(plans, "MAX_PREREQUISITES", 0):
            self.assert_error("proposal_scope_limit", self.propose)
        self.assertIsNone(self.row())
        with patch("subprocess.Popen", side_effect=AssertionError("process forbidden")), \
                patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.propose()
        self.assertEqual(self.xml.read_bytes(), RAW)

    def test_unsupported_xml_is_a_fixed_error_and_no_candidate_is_saved(self):
        self.xml.write_bytes(b"<!DOCTYPE Config><Config><Port>8989</Port></Config>")
        self.record()
        self.assert_error("proposal_transform_unsupported", self.propose)
        self.assertIsNone(self.row())

    def test_caller_payloads_cannot_select_candidate_or_graph(self):
        with self.assertRaises(TypeError):
            self.propose(candidate=b"arbitrary")
        self.assert_error("invalid_proposal_request", lambda: derive_sonarr_port_proposal({},
            expected_revision=1, snapshot_id=self.store.current()["snapshot_id"], stable_resource_id=self.stable))
        for revision in (True, 0, -1, 2**63, "1"):
            self.assert_error("invalid_proposal_request", lambda: self.propose(expected_revision=revision))
        self.assert_error("proposal_snapshot_mismatch", lambda: self.propose(snapshot_id="0" * 64))
        self.assertIsNone(self.row())

    def test_tampered_candidate_and_context_fail_all_store_reads(self):
        self.propose()
        original = self.row()
        for column, value in (("candidate", b"PRIVATE_PROPOSAL_SENTINEL"),
                              ("context", b"{}"), ("seal", b"x" * 32),
                              ("protected_id", "23456789-1234-4234-8234-123456789abc")):
            with self.subTest(column=column):
                self.corrupt("UPDATE sonarr_port_proposals SET " + column + "=?", (value,))
                self.assert_error("store_corrupt", self.store.current)
                self.corrupt("UPDATE sonarr_port_proposals SET candidate=?,context=?,seal=?,protected_id=?",
                             (original[10], original[9], original[11], original[5]))

    def test_even_resealed_context_cannot_change_historical_authority_or_candidate(self):
        self.propose()
        row = self.row()
        context = json.loads(row[9])
        context["target_definition"]["desired"]["port"] = 9999
        seal = plans._seal(self.store, row[0], row[6], context, row[10])
        self.corrupt("UPDATE sonarr_port_proposals SET context=?,seal=?", (_json(context), seal))
        self.assert_error("store_corrupt", self.store.current)

    def test_commit_uncertainty_can_be_inspected_after_reopening(self):
        commit = HostStore._commit
        def after(store):
            commit(store)
            raise OSError(PRIVATE)
        with patch.object(HostStore, "_commit", after):
            self.assert_error("commit_outcome_unknown", self.propose)
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as store:
            proposals = list_sonarr_port_proposals(store)
            self.assertEqual(len(proposals), 1)
            self.assertFalse(proposals[0].as_dict()["executable"])

    def test_bounded_listing_and_readonly_lookup_do_not_write(self):
        for _ in range(3):
            self.propose()
        before = (self.directory / "state.sqlite3").read_bytes()
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as store:
            page = list_sonarr_port_proposals(store, limit=2)
            rest = list_sonarr_port_proposals(store, after_id=page[-1].as_dict()["proposal_id"])
            self.assertEqual(len(page) + len(rest), 3)
            self.assert_error("proposal_missing", lambda: read_sonarr_port_proposal(
                store, "23456789-1234-4234-8234-123456789abc"))
            for limit in (True, 0, 101):
                self.assert_error("invalid_proposal_request", lambda: list_sonarr_port_proposals(store, limit=limit))
        self.assertEqual((self.directory / "state.sqlite3").read_bytes(), before)

    def test_verified_backup_preserves_proposals_independently_of_later_source_writes(self):
        proposal = self.propose().as_dict()
        destination = self.root / "private-backup"
        with self.store._locked(exclusive=True):
            self.store._db.execute("BEGIN IMMEDIATE")
            try:
                with migration._Backup(destination, os.geteuid()) as backup:
                    metadata = backup.capture(self.store, 1)
            finally:
                self.store._db.execute("ROLLBACK")
        self.assertEqual(metadata["schema_version"], 3)
        self.store.record_intent(EMPTY, 1)
        with HostStore.open_readonly(destination, HOST, owner_uid=os.geteuid()) as backup:
            restored = read_sonarr_port_proposal(backup, proposal["proposal_id"]).as_dict()
            self.assertEqual(restored, proposal)
        self.assertEqual(read_sonarr_port_proposal(self.store, proposal["proposal_id"]).as_dict()["decision_state"],
                         "superseded")


if __name__ == "__main__":
    unittest.main()
