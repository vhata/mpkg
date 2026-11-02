"""Bound-reference recording with real private temporary policy/store fixtures."""
from dataclasses import replace
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager.declarations import canonical_json, load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.protected_bindings import (BindingError, PreparedProtectedInput, ProtectedRecorder,
                                            MAX_PROTECTED_BYTES, MAX_PROTECTED_ENTRIES)
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

    def record(self):
        prepared = self.prepare()
        declaration = self.declaration(prepared.reference)
        return declaration, self.recorder.record_intent(declaration, 0, prepared_inputs=[prepared])

    def new_store(self, suffix):
        self.store.close()
        self.store_path = self.root / ("store-" + suffix)
        self.store = HostStore.create(self.store_path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)

    def corrupt(self, table, values, where="1=1"):
        with sqlite3.connect(self.store_path / "state.sqlite3") as db:
            sql = db.execute("SELECT sql FROM sqlite_schema WHERE name=?", (table + "_update",)).fetchone()[0]
            db.execute("DROP TRIGGER " + table + "_update")
            db.execute(f"UPDATE {table} SET " + ",".join(key + "=?" for key in values) + " WHERE " + where,
                       tuple(values.values()))
            db.execute(sql)

    def batch(self, count):
        prepared, files = [], []
        for index in range(count):
            path = f"private-{index}.env"
            (self.inputs / path).write_bytes(self.source.read_bytes())
            item = self.prepare(path=path)
            prepared.append(item)
            files.append(f'{{path="{path}",classification="protected",reference="{item.reference}"}}')
        raw = (f'schema=1\ncomponents=[]\nresources=[]\n[[inputs]]\nid="app-inputs"\n'
               f'base_directory={json.dumps(str(self.inputs))}\nfiles=[{",".join(files)}]\n')
        return load_declaration(raw.encode()), prepared

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

    def test_narrow_private_root_inside_public_bundle_uses_longest_component_ancestor(self):
        private = self.inputs / "private"
        private.mkdir()
        self.source.rename(private / "private.env")
        self.policy.close()
        self.policy_path.write_bytes(self.policy_raw.replace(
            json.dumps([str(self.inputs)]).encode(), json.dumps([str(self.root), str(private)]).encode()))
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)
        with patch("mpkg_manager.protected_bindings.capture_protected", wraps=capture_protected) as capture:
            prepared = self.prepare(path="private/private.env")
        self.assertEqual(capture.call_args.kwargs["root"], str(private))
        self.assertEqual(capture.call_args.kwargs["relative_path"], "private.env")
        declaration = self.declaration(prepared.reference, path="private/private.env")
        declaration = load_declaration(declaration.source_bytes.replace(
            b'files=[', b'files=[{path="public.yaml",classification="nonsecret"},'))
        result = self.recorder.record_intent(declaration, 0, prepared_inputs=[prepared])
        self.assertEqual(self.compare(result, path="private/private.env"), "same")
        sibling = self.root / "inputs-sibling"
        sibling.mkdir()
        (sibling / "private.env").write_bytes(b"private sibling")
        # A fresh narrow-only policy cannot authorize a textual prefix sibling.
        self.policy.close()
        self.policy_path.write_bytes(self.policy_raw)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        recorder = ProtectedRecorder(self.store, self.policy)
        self.assert_error(BindingError, "input_unavailable", lambda: recorder.prepare(
            expected_revision=1, input_id="app-inputs", base_directory=str(sibling), path="private.env"))

    def test_snapshot_comment_or_model_change_requires_fresh_references(self):
        declaration, first = self.record()
        comments = load_declaration(declaration.source_bytes + b"# changed exact source\n")
        model = load_declaration(declaration.source_bytes.replace(b'name="example"', b'name="different"'))
        self.assertEqual(comments.sha256, declaration.sha256)
        for changed in (comments, model):
            self.assert_error(BindingError, "binding_unavailable", lambda: self.recorder.record_intent(changed, 1))
        prepared = self.prepare(1)
        fresh = self.declaration(prepared.reference, comment="# accepted new source")
        second = self.recorder.record_intent(fresh, 1, prepared_inputs=[prepared])
        self.assertNotEqual(second["snapshot_id"], first["snapshot_id"])
        self.assertEqual(self.compare(first), "same")
        self.assertEqual(self.compare(second), "same")

    def test_old_binding_survives_new_intent_removal_relinquishment_and_reopen(self):
        declaration, first = self.record()
        adopted = self.recorder.adopt(declaration, 1, ["app"])
        stable = self.store.current()["resources"][0]["stable_id"]
        self.store.record_intent(EMPTY, 2)
        self.store.relinquish([stable], 3)
        self.store.close()
        self.store = HostStore.open_readonly(self.store_path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)
        self.assertEqual(self.compare(first), "same")
        self.assertEqual(self.compare(adopted), "same")
        self.assertEqual(len(self.store.history()), 4)

    def test_legacy_repeat_has_historical_availability_but_still_requires_fresh_read(self):
        declaration, first = self.record()
        repeated = self.store.record_intent(declaration, 1)
        self.assertEqual(self.compare(repeated), "same")
        self.source.write_bytes(b"new source")
        self.assertEqual(self.compare(first), "changed")
        self.assertEqual(self.compare(repeated), "changed")
        self.assert_error(BindingError, "protected_input_changed", lambda: self.recorder.adopt(declaration, 2, ["app"]))

    def test_future_origin_never_resolves_an_earlier_matching_snapshot(self):
        reference = "45cf305d-f35c-4ae0-9fc9-65843b1e56c7"
        declaration = self.declaration(reference)
        earlier = self.store.record_intent(declaration, 0)
        with patch("mpkg_manager.protected_bindings.uuid.uuid4", return_value=uuid.UUID(reference)):
            prepared = self.prepare(1)
        later = self.recorder.record_intent(declaration, 1, prepared_inputs=[prepared])
        self.assertEqual(earlier["snapshot_id"], later["snapshot_id"])
        self.assertEqual(self.compare(earlier), "unavailable")
        self.assertEqual(self.compare(later), "same")

    def test_missing_foreign_wrong_slot_and_wrong_snapshot_are_unavailable(self):
        declaration, decision = self.record()
        for values in ({"revision": 99}, {"snapshot_id": "f" * 64}, {"input_id": "other"},
                       {"path": "../private.env"}, {"revision": True}):
            self.assertEqual(self.compare(decision, **values), "unavailable")
        with HostStore.create(self.root / "foreign", HOST, owner_uid=os.geteuid()) as foreign:
            other = ProtectedRecorder(foreign, self.policy)
            unbound = foreign.record_intent(declaration, 0)
            self.assertEqual(other.compare_input(revision=1, snapshot_id=unbound["snapshot_id"],
                                                input_id="app-inputs", path="private.env"), "unavailable")

    def test_preparation_mutation_foreign_store_and_different_policy_handle_are_refused(self):
        prepared = self.prepare()
        declaration = self.declaration(prepared.reference)
        metadata = json.loads(prepared._metadata)
        altered = dict(metadata, reference=str(uuid.uuid4()))
        variants = [replace(prepared, _raw=b"FORGED_PRIVATE_BYTES"), replace(prepared, _seal=b"x" * 32),
                    replace(prepared, _metadata=json.dumps(altered, sort_keys=True, separators=(",", ":")).encode()),
                    replace(prepared, _metadata=b"PRIVATE_INVALID_METADATA")]
        for forged in variants:
            self.assert_error(BindingError, "invalid_preparation", lambda: self.recorder.record_intent(
                declaration, 0, prepared_inputs=[forged]))
        with HostStore.create(self.root / "foreign", HOST, owner_uid=os.geteuid()) as foreign:
            other = ProtectedRecorder(foreign, self.policy)
            self.assert_error(BindingError, "invalid_preparation", lambda: other.record_intent(
                declaration, 0, prepared_inputs=[prepared]))
        with load_host_policy(path=self.policy_path, owner_uid=os.geteuid()) as other_policy:
            other = ProtectedRecorder(self.store, other_policy)
            self.assert_error(BindingError, "invalid_preparation", lambda: other.record_intent(
                declaration, 0, prepared_inputs=[prepared]))
        other = ProtectedRecorder(self.store, self.policy)
        self.assert_error(BindingError, "invalid_preparation", lambda: other.record_intent(
            declaration, 0, prepared_inputs=[prepared]))
        self.assertEqual(self.store.history(), [])

    def test_incomplete_exact_type_preparation_reports_only_fixed_error(self):
        incomplete = object.__new__(PreparedProtectedInput)
        self.assert_error(BindingError, "invalid_preparation", lambda: incomplete.reference)
        declaration = self.declaration(str(uuid.uuid4()))
        self.assert_error(BindingError, "invalid_preparation", lambda: self.recorder.record_intent(
            declaration, 0, prepared_inputs=[incomplete]))
        # Even a partly populated instance cannot escape fixed diagnostics.
        object.__setattr__(incomplete, "_policy", self.policy)
        self.assert_error(BindingError, "invalid_preparation", lambda: self.recorder.record_intent(
            declaration, 0, prepared_inputs=[incomplete]))
        self.assertEqual(self.store.history(), [])

    def test_scope_swap_duplicate_unused_and_missing_preparations_publish_nothing(self):
        prepared = self.prepare()
        declaration = self.declaration(prepared.reference)
        (self.inputs / "other.env").write_bytes(self.source.read_bytes())
        changed = self.declaration(prepared.reference, path="other.env")
        self.assert_error(BindingError, "binding_scope_mismatch", lambda: self.recorder.record_intent(
            changed, 0, prepared_inputs=[prepared]))
        self.assert_error(BindingError, "ambiguous_reference", lambda: self.recorder.record_intent(
            declaration, 0, prepared_inputs=[prepared, prepared]))
        self.assert_error(BindingError, "unused_preparation", lambda: self.recorder.record_intent(
            EMPTY, 0, prepared_inputs=[prepared]))
        self.assert_error(BindingError, "binding_unavailable", lambda: self.recorder.record_intent(declaration, 0))
        duplicate = load_declaration(declaration.source_bytes.replace(b'files=[',
            ('files=[{path="other.env",classification="protected",reference="' + prepared.reference + '"},').encode()))
        self.assert_error(BindingError, "ambiguous_reference", lambda: self.recorder.record_intent(
            duplicate, 0, prepared_inputs=[prepared]))
        self.assertEqual(self.store.history(), [])

    def test_all_capture_reads_stay_outside_transactions_and_final_policy_is_checked(self):
        real_capture = capture_protected
        calls = []
        def checked_capture(*args, **kwargs):
            self.assertFalse(self.store._db.in_transaction)
            calls.append(kwargs["relative_path"])
            return real_capture(*args, **kwargs)
        with patch("mpkg_manager.protected_bindings.capture_protected", checked_capture):
            prepared = self.prepare()
            decision = self.recorder.record_intent(self.declaration(prepared.reference), 0, prepared_inputs=[prepared])
            self.assertEqual(self.compare(decision), "same")
        self.assertEqual(calls, ["private.env"] * 3)
        self.policy.close()
        self.assertEqual(self.compare(decision), "unavailable")
        self.assert_error(BindingError, "policy_unavailable", lambda: self.recorder.adopt(
            self.declaration(prepared.reference), 1, ["app"]))

    def test_policy_revocation_after_final_capture_blocks_commit(self):
        prepared = self.prepare()
        declaration = self.declaration(prepared.reference)
        def revoked(*args, **kwargs):
            captured = capture_protected(*args, **kwargs)
            self.policy_path.write_bytes(self.policy_raw + b"# revoked\n")
            return captured
        with patch("mpkg_manager.protected_bindings.capture_protected", revoked):
            self.assert_error(BindingError, "policy_unavailable", lambda: self.recorder.record_intent(
                declaration, 0, prepared_inputs=[prepared]))
        self.assertEqual(self.store.history(), [])

    def test_stale_revision_and_read_to_commit_competition_preserve_atomicity(self):
        prepared = self.prepare()
        declaration = self.declaration(prepared.reference)
        with HostStore.open_existing(self.store_path, HOST, owner_uid=os.geteuid()) as other:
            def competing(*args, **kwargs):
                captured = capture_protected(*args, **kwargs)
                other.record_intent(EMPTY, 0)
                return captured
            with patch("mpkg_manager.protected_bindings.capture_protected", competing):
                self.assert_error(StoreError, "revision_conflict", lambda: self.recorder.record_intent(
                    declaration, 0, prepared_inputs=[prepared]))
        self.assertEqual(len(self.store.history()), 1)
        self.assertEqual(self.store._db.execute("SELECT count(*) FROM protected_inputs").fetchone()[0], 0)

    def test_closed_busy_and_corrupt_store_comparisons_are_unavailable(self):
        _, decision = self.record()
        descriptor = os.open(self.store_path / "state.lock", os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.compare(decision), "unavailable")
        finally:
            os.close(descriptor)
        self.corrupt("protected_inputs", {"purpose": "PRIVATE_CHANGED_PURPOSE"})
        self.assertEqual(self.compare(decision), "unavailable")
        self.assert_error(StoreError, "store_corrupt", self.store.current)
        self.store.close()
        self.assertEqual(self.compare(decision), "unavailable")

    def test_public_projections_and_repr_exclude_protected_context(self):
        prepared = self.prepare()
        decision = self.recorder.record_intent(self.declaration(prepared.reference), 0, prepared_inputs=[prepared])
        public = json.dumps({"current": self.store.current(), "history": self.store.history(),
                             "comparison": self.compare(decision)})
        token = self.store._db.execute("SELECT token FROM protected_inputs").fetchone()[0]
        for private in (prepared.reference, str(self.source), self.source.read_text(), prepared._seal.hex(), token.hex()):
            self.assertNotIn(private, public)
            self.assertNotIn(private, repr(prepared))
        self.assertNotIn(hashlib.sha256(self.source.read_bytes()).hexdigest(), public)

    def test_unsupported_token_versions_lengths_and_tag_stripping_fail_closed(self):
        for index in range(4):
            if index:
                self.new_store(str(index))
            _, decision = self.record()
            token = self.store._db.execute("SELECT token FROM protected_inputs").fetchone()[0]
            changed = [b"MPKGBND\x00\x02" + token[9:], token + b"x", token[9:], token[:-1]][index]
            self.corrupt("protected_inputs", {"token": changed})
            self.assertEqual(self.compare(decision), "unavailable")
            self.assert_error(StoreError, "store_corrupt", self.store.current)

    def test_bound_origin_and_purpose_are_authenticated_not_just_content(self):
        for index, change in enumerate(("purpose", "origin")):
            if index:
                self.new_store(str(index))
            declaration, decision = self.record()
            if change == "purpose":
                self.corrupt("protected_inputs", {"purpose": "Different provenance"})
            else:
                self.recorder.record_intent(declaration, 1)
                self.corrupt("decision_inputs", {"revision": 2})
            self.assertEqual(self.compare(decision), "unavailable")
            self.assert_error(StoreError, "store_corrupt", self.store.current)

    def test_bound_tokens_cannot_be_used_as_legacy_content_macs(self):
        _, decision = self.record()
        raw, identity, token = self.store._db.execute("SELECT raw,source_identity,token FROM protected_inputs").fetchone()
        key = self.store._db.execute("SELECT private_key FROM host").fetchone()[0]
        legacy = hmac.digest(key, identity + b"\0" + raw, "sha256")
        self.assertNotEqual(token, legacy)  # The previous reader's exact legacy check fails closed.
        self.corrupt("protected_inputs", {"token": legacy})
        self.assertEqual(self.store.current()["revision"], 1)
        self.assertEqual(self.compare(decision), "unavailable")

    def test_semantically_valid_snapshot_replacement_cannot_rebind_a_capture(self):
        for index, variant in enumerate(("comment", "scope")):
            if index:
                self.new_store(str(index))
            declaration, decision = self.record()
            source = declaration.source_bytes
            if variant == "comment":
                source += b"# replaced exact source\n"
            else:
                source = source.replace(b"private.env", b"different.env")
                identity = json.loads(self.store._db.execute("SELECT source_identity FROM protected_inputs").fetchone()[0])
                identity["path"] = str(self.inputs / "different.env")
                self.corrupt("protected_inputs", {"source_identity": canonical_json(identity)})
                name = "declared-v1:" + hashlib.sha256(canonical_json(["app-inputs", "different.env"])).hexdigest()
                self.corrupt("decision_inputs", {"name": name})
            changed = load_declaration(source)
            snapshot_id = self.store._snapshot_id(changed)
            self.corrupt("snapshots", {"id": snapshot_id, "source": changed.source_bytes,
                                       "canonical": changed.canonical_bytes, "digest": changed.sha256})
            self.corrupt("decisions", {"snapshot_id": snapshot_id})
            self.assert_error(StoreError, "store_corrupt", self.store.current)
            self.assertEqual(self.compare(decision, snapshot_id=snapshot_id), "unavailable")

    def test_entry_limit_and_batch_replay_parse_each_snapshot_once(self):
        self.assertEqual(MAX_PROTECTED_ENTRIES, 64)
        declaration, prepared = self.batch(64)
        self.assert_error(BindingError, "protected_input_limit", self.prepare)
        with patch.object(self.store, "_load_snapshot", wraps=self.store._load_snapshot) as load:
            decision = self.recorder.record_intent(declaration, 0, prepared_inputs=prepared)
        self.assertEqual(load.call_count, 1)  # One saved snapshot, independent of 64 captures.
        with patch.object(self.store, "_load_snapshot", wraps=self.store._load_snapshot) as load:
            self.assertEqual(self.store.current()["revision"], 1)
        self.assertEqual(load.call_count, 2)  # One replay and one current projection.
        with patch.object(self.store, "_load_snapshot", wraps=self.store._load_snapshot) as load:
            self.store.history()
        self.assertEqual(load.call_count, 1)
        extra = ('{path="extra.env",classification="protected",reference="' + str(uuid.uuid4()) + '"},').encode()
        overflow = load_declaration(declaration.source_bytes.replace(b"files=[", b"files=[" + extra))
        with patch("mpkg_manager.protected_bindings.capture_protected") as capture:
            self.assert_error(BindingError, "protected_input_limit", lambda: self.recorder.record_intent(overflow, 1))
        capture.assert_not_called()
        self.assertEqual(self.compare(decision, path="private-63.env"), "same")

    def test_aggregate_budget_covers_preparation_recording_and_exact_snapshot_reuse(self):
        self.assertEqual(MAX_PROTECTED_BYTES, 64 * 1024 * 1024)
        size = len(self.source.read_bytes())
        with patch("mpkg_manager.protected_bindings.MAX_PROTECTED_BYTES", 2 * size):
            declaration, prepared = self.batch(2)
            self.assert_error(BindingError, "protected_input_limit", self.prepare)
        with patch("mpkg_manager.protected_bindings.MAX_PROTECTED_BYTES", size):
            self.assert_error(BindingError, "protected_input_limit", lambda: self.recorder.record_intent(
                declaration, 0, prepared_inputs=prepared))
        self.assertEqual(self.store.history(), [])
        decision = self.recorder.record_intent(declaration, 0, prepared_inputs=prepared)
        with patch("mpkg_manager.protected_bindings.MAX_PROTECTED_BYTES", size):
            self.assert_error(BindingError, "protected_input_limit", lambda: self.recorder.record_intent(declaration, 1))
        self.assertEqual(self.compare(decision, path="private-0.env"), "same")

    def test_same_bytes_replacement_or_metadata_change_is_changed_not_same(self):
        declaration, decision = self.record()
        original = self.source.stat()
        replacement = self.inputs / "replacement"
        replacement.write_bytes(self.source.read_bytes())
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        replacement.replace(self.source)
        self.assertEqual(self.compare(decision), "changed")
        self.assert_error(BindingError, "protected_input_changed", lambda: self.recorder.adopt(declaration, 1, ["app"]))
        prepared = self.prepare(1)
        declaration = self.declaration(prepared.reference)
        os.chmod(self.source, 0o400)
        self.assert_error(BindingError, "protected_input_changed", lambda: self.recorder.record_intent(
            declaration, 1, prepared_inputs=[prepared]))

    def test_stale_preparation_and_policy_revocation_during_prepare_publish_nothing(self):
        prepared = self.prepare()
        declaration = self.declaration(prepared.reference)
        self.store.record_intent(EMPTY, 0)
        self.assert_error(BindingError, "invalid_preparation", lambda: self.recorder.record_intent(
            declaration, 1, prepared_inputs=[prepared]))
        def revoked(*args, **kwargs):
            captured = capture_protected(*args, **kwargs)
            self.policy.close()
            return captured
        with patch("mpkg_manager.protected_bindings.capture_protected", revoked):
            self.assert_error(BindingError, "policy_unavailable", lambda: self.prepare(1))
        self.assertEqual(len(self.store.history()), 1)
        self.assertEqual(self.store._db.execute("SELECT count(*) FROM protected_inputs").fetchone()[0], 0)

    def test_capture_cancellation_leaves_no_transaction_or_partial_publication(self):
        prepared = self.prepare()
        declaration = self.declaration(prepared.reference)
        interruption = KeyboardInterrupt("fixture cancellation")
        with patch("mpkg_manager.protected_bindings.capture_protected", side_effect=interruption):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.recorder.record_intent(declaration, 0, prepared_inputs=[prepared])
        self.assertIs(caught.exception, interruption)
        self.assertFalse(self.store._db.in_transaction)
        self.assertEqual(self.store.history(), [])
        self.recorder.record_intent(declaration, 0, prepared_inputs=[prepared])

    def test_database_full_rolls_back_all_bound_bytes_references_and_authority(self):
        self.source.write_bytes(os.urandom(1024 * 1024))
        prepared = self.prepare()
        pages = self.store._db.execute("PRAGMA page_count").fetchone()[0]
        self.store._db.execute(f"PRAGMA max_page_count={pages}")
        self.assert_error(StoreError, "store_write_failed", lambda: self.recorder.adopt(
            self.declaration(prepared.reference), 0, ["app"], prepared_inputs=[prepared]))
        self.assertEqual(self.store.history(), [])
        for table in ("snapshots", "protected_inputs", "decision_inputs", "resources"):
            self.assertEqual(self.store._db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_bound_commit_failure_or_cancellation_requires_reopen_and_preserves_atomicity(self):
        for index, (interruption, persisted) in enumerate((
                (sqlite3.OperationalError, False), (sqlite3.OperationalError, True),
                (KeyboardInterrupt, False), (KeyboardInterrupt, True))):
            if index:
                self.new_store(str(index))
            prepared = self.prepare()
            declaration = self.declaration(prepared.reference)
            commit = self.store._commit
            failure = interruption("PRIVATE_COMMIT_DIAGNOSTIC")
            def fail():
                if persisted:
                    commit()
                raise failure
            with patch.object(self.store, "_commit", fail):
                if interruption is sqlite3.OperationalError:
                    self.assert_error(StoreError, "commit_outcome_unknown", lambda: self.recorder.adopt(
                        declaration, 0, ["app"], prepared_inputs=[prepared]))
                else:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        self.recorder.adopt(declaration, 0, ["app"], prepared_inputs=[prepared])
                    self.assertIs(caught.exception, failure)
            self.assertIsNone(self.store._db)
            self.assertIsNone(self.store._lockfd)
            self.assertFalse((self.store_path / "state.sqlite3-journal").exists())
            with HostStore.open_readonly(self.store_path, HOST, owner_uid=os.geteuid()) as reader:
                self.assertEqual(reader.current()["revision"], int(persisted))
                for table in ("snapshots", "protected_inputs", "decision_inputs", "resources"):
                    self.assertEqual(reader._db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], int(persisted))
                if persisted:
                    recorder = ProtectedRecorder(reader, self.policy)
                    self.assertEqual(recorder.compare_input(revision=1, snapshot_id=reader.current()["snapshot_id"],
                                                           input_id="app-inputs", path="private.env"), "same")


if __name__ == "__main__":
    unittest.main()
