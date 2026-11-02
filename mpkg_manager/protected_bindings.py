"""Trusted recorder primitives for authenticated declaration input bindings.

This library is not an installed helper or Python privilege containment.
Capture and freshness reads run outside SQLite write transactions.
"""
from dataclasses import dataclass, field
import hmac
import json
import os
import posixpath
import re
import uuid

from .declarations import DeclarationError, validate_model
from .host_policy import LoadedHostPolicy, PolicyError
from .protected_capture import CaptureError, capture_protected
from .store import (HostStore, ProtectedInput, StoreError, MAX_INPUT_BYTES,
                    _PREPARATION_DOMAIN, _bound_name, _captures, _declaration,
                    _declared_protected, _decode, _framed_mac, _json)


MAX_PROTECTED_ENTRIES = 64
MAX_PROTECTED_BYTES = 64 * 1024 * 1024
_MAX_PREPARATION_METADATA = 128 * 1024
_PURPOSE = "Declared protected input"
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class BindingError(RuntimeError):
    """A fixed diagnostic without references, paths, payloads or MACs."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PreparedProtectedInput:
    """Private immutable preparation; reference is a trusted accessor only."""
    _metadata: bytes = field(repr=False)
    _raw: bytes = field(repr=False)
    _seal: bytes = field(repr=False)
    _policy: LoadedHostPolicy = field(repr=False, compare=False)

    @property
    def reference(self):
        try:
            return json.loads(self._metadata)["reference"]
        except (AttributeError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise BindingError("invalid_preparation") from None


def _scope(input_id, base_directory, path, reference):
    try:
        normalized = validate_model({"schema": 1, "components": [], "resources": [], "inputs": [
            {"id": input_id, "base_directory": base_directory,
             "files": [{"path": path, "classification": "protected", "reference": reference}]}]})["inputs"][0]
    except DeclarationError:
        raise BindingError("invalid_binding_request") from None
    return {"input_id": normalized["id"], "base_directory": normalized["base_directory"],
            **normalized["files"][0]}


class ProtectedRecorder:
    """Use caller-owned store/policy handles; never export raw resolved inputs."""

    def __init__(self, store, policy):
        if type(store) is not HostStore or type(policy) is not LoadedHostPolicy:
            raise BindingError("invalid_recorder_context")
        self._store, self._policy = store, policy
        self._nonce = os.urandom(32).hex()
        self._budget_revision = None
        self._prepared_count = self._prepared_bytes = 0
        self._policy_context()

    def _policy_context(self):
        try:
            policy = self._policy.policy
            if (policy.host_id != self._store.host_id
                    or policy.engine_aliases != self._store.engine_aliases):
                raise BindingError("policy_store_mismatch")
            return {"host_id": policy.host_id, "engine_aliases": policy.engine_aliases,
                    "allowed_input_roots": list(policy.allowed_input_roots),
                    "identity": [str(value) for value in self._policy._identity]}
        except (PolicyError, AttributeError):
            raise BindingError("policy_unavailable") from None

    def _capture(self, entry):
        context = self._policy_context()
        source = posixpath.join(entry["base_directory"], entry["path"])
        roots = [root for root in context["allowed_input_roots"]
                 if posixpath.commonpath((root, source)) == root]
        if not roots:
            raise BindingError("input_unavailable")
        root = max(roots, key=lambda item: len(item.split("/")))
        relative = posixpath.relpath(source, root)
        try:
            return capture_protected(self._policy, root=root, relative_path=relative,
                                     name=_bound_name(entry["input_id"], entry["path"]), purpose=_PURPOSE)
        except CaptureError as error:
            code = "policy_unavailable" if error.code == "policy_unavailable" else "input_unavailable"
            raise BindingError(code) from None

    def _key(self):
        return self._store._db.execute("SELECT private_key FROM host").fetchone()[0]

    def _revision(self, expected_revision):
        if type(expected_revision) is not int or not 0 <= expected_revision < 2**63 - 1:
            raise BindingError("invalid_binding_request")
        if self._store._revision() != expected_revision:
            raise StoreError("revision_conflict")

    def prepare(self, *, expected_revision, input_id, base_directory, path):
        """Capture and issue a sealed reference before the caller writes TOML."""
        with self._store._read():
            self._revision(expected_revision)
        if self._budget_revision != expected_revision:
            self._budget_revision = expected_revision
            self._prepared_count = self._prepared_bytes = 0
        if self._prepared_count >= MAX_PROTECTED_ENTRIES:
            raise BindingError("protected_input_limit")
        reference = str(uuid.uuid4())
        entry = _scope(input_id, base_directory, path, reference)
        policy_context = self._policy_context()
        captured = self._capture(entry)
        if self._prepared_bytes + len(captured.raw) > MAX_PROTECTED_BYTES:
            raise BindingError("protected_input_limit")
        if self._policy_context() != policy_context:
            raise BindingError("policy_unavailable")
        metadata = {"version": 1, "host_id": self._store.host_id,
                    "expected_revision": expected_revision, "recorder_nonce": self._nonce,
                    "policy": policy_context, "purpose": _PURPOSE,
                    "source_identity": captured.source_identity, **entry}
        encoded = _json(metadata)
        if len(encoded) > _MAX_PREPARATION_METADATA:
            raise BindingError("protected_input_limit")
        with self._store._read():
            self._revision(expected_revision)
            if self._store._db.execute("SELECT 1 FROM protected_inputs WHERE id=?", (reference,)).fetchone():
                raise BindingError("reference_conflict")
            seal = _framed_mac(self._key(), _PREPARATION_DOMAIN, metadata, captured.raw)
        self._prepared_count += 1
        self._prepared_bytes += len(captured.raw)
        return PreparedProtectedInput(encoded, captured.raw, seal, self._policy)

    def _prepared(self, prepared, key, expected_revision, policy_context):
        try:
            if (type(prepared) is not PreparedProtectedInput or prepared._policy is not self._policy
                    or type(prepared._metadata) is not bytes or len(prepared._metadata) > _MAX_PREPARATION_METADATA
                    or type(prepared._raw) is not bytes or len(prepared._raw) > MAX_INPUT_BYTES
                    or type(prepared._seal) is not bytes or len(prepared._seal) != 32):
                raise BindingError("invalid_preparation")
            metadata = _decode(prepared._metadata)
            if not hmac.compare_digest(prepared._seal, _framed_mac(key, _PREPARATION_DOMAIN, metadata, prepared._raw)):
                raise BindingError("invalid_preparation")
            if (metadata["expected_revision"] != expected_revision
                    or metadata["recorder_nonce"] != self._nonce
                    or metadata["host_id"] != self._store.host_id
                    or metadata["policy"] != policy_context):
                raise BindingError("invalid_preparation")
            capture = ProtectedInput(_bound_name(metadata["input_id"], metadata["path"]), prepared._raw,
                                     metadata["source_identity"], metadata["purpose"])
            _captures([capture])
            return metadata, capture
        except (StoreError, AttributeError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise BindingError("invalid_preparation") from None

    @staticmethod
    def _same_capture(captured, raw, identity):
        return hmac.compare_digest(captured.raw, raw) and _json(captured.source_identity) == identity

    def record_intent(self, declaration, expected_revision, *, prepared_inputs=()):
        return self._record("intent", declaration, expected_revision, prepared_inputs, None)

    def adopt(self, declaration, expected_revision, resource_ids, *, prepared_inputs=()):
        return self._record("adopt", declaration, expected_revision, prepared_inputs, resource_ids)

    def _record(self, kind, declaration, expected_revision, prepared_inputs, resource_ids):
        declaration = _declaration(declaration)
        self._store._check_bound_identities(declaration)
        selected = self._store._adoption_selection(declaration, resource_ids) if kind == "adopt" else None
        entries = _declared_protected(declaration)
        if (type(prepared_inputs) not in (list, tuple) or len(entries) > MAX_PROTECTED_ENTRIES
                or len(prepared_inputs) > MAX_PROTECTED_ENTRIES):
            raise BindingError("protected_input_limit")
        if len({entry["reference"] for entry in entries}) != len(entries):
            raise BindingError("ambiguous_reference")
        snapshot_id = self._store._snapshot_id(declaration)
        policy_context = self._policy_context()
        prepared, reused = {}, {}
        total = 0
        with self._store._read():
            self._revision(expected_revision)
            key = self._key()
            for item in prepared_inputs:
                metadata, capture = self._prepared(item, key, expected_revision, policy_context)
                reference = metadata["reference"]
                if reference in prepared:
                    raise BindingError("ambiguous_reference")
                prepared[reference] = (item, metadata, capture)
                total += len(capture.raw)
            if set(prepared) - {entry["reference"] for entry in entries}:
                raise BindingError("unused_preparation")
            for entry in entries:
                reference = entry["reference"]
                if reference in prepared:
                    metadata = prepared[reference][1]
                    if any(metadata[field] != value for field, value in entry.items()):
                        raise BindingError("binding_scope_mismatch")
                    if self._store._db.execute("SELECT 1 FROM protected_inputs WHERE id=?", (reference,)).fetchone():
                        raise BindingError("reference_conflict")
                else:
                    row = self._store._bound_capture(reference, snapshot_id, expected_revision)
                    if row is None:
                        raise BindingError("binding_unavailable")
                    reused[reference] = row
                    total += len(row[0])
            if total > MAX_PROTECTED_BYTES:
                raise BindingError("protected_input_limit")
        # The store lock and SQLite transaction are released for all live reads.
        for entry in entries:
            reference = entry["reference"]
            fresh = self._capture(entry)
            if reference in prepared:
                capture = prepared[reference][2]
                raw, identity = capture.raw, _json(capture.source_identity)
            else:
                raw, identity = reused[reference][:2]
            if not self._same_capture(fresh, raw, identity):
                raise BindingError("protected_input_changed")
        if self._policy_context() != policy_context:
            raise BindingError("policy_unavailable")
        with self._store._write(expected_revision):
            key = self._key()
            captures, references = [], {}
            for reference, (item, metadata, capture) in prepared.items():
                self._prepared(item, key, expected_revision, policy_context)
                if self._store._db.execute("SELECT 1 FROM protected_inputs WHERE id=?", (reference,)).fetchone():
                    raise BindingError("reference_conflict")
                captures.extend(_captures([capture]))
                references[capture.name] = reference
            for reference, previous in reused.items():
                if self._store._bound_capture(reference, snapshot_id, expected_revision) != previous:
                    raise BindingError("binding_unavailable")
            result = self._store._decision(kind, declaration, expected_revision + 1, captures,
                                           binding_references=references)
            if selected is not None:
                self._store._save_adoptions(*selected, resource_ids, result["revision"])
        self._budget_revision = result["revision"]
        self._prepared_count = self._prepared_bytes = 0
        return result

    def compare_input(self, *, revision, snapshot_id, input_id, path):
        """Fresh comparison only; the caller never receives resolved raw input."""
        if (type(revision) is not int or not 1 <= revision < 2**63
                or type(snapshot_id) is not str or not _HASH.fullmatch(snapshot_id)
                or type(input_id) is not str or type(path) is not str):
            return "unavailable"
        try:
            self._policy_context()
            with self._store._read():
                decision = self._store._db.execute("SELECT snapshot_id FROM decisions WHERE revision=?", (revision,)).fetchone()
                if decision is None or decision[0] != snapshot_id:
                    return "unavailable"
                declaration = self._store._load_snapshot(snapshot_id)
                entries = [entry for entry in _declared_protected(declaration)
                           if entry["input_id"] == input_id and entry["path"] == path]
                if len(entries) != 1:
                    return "unavailable"
                entry = entries[0]
                row = self._store._bound_capture(entry["reference"], snapshot_id, revision)
                if row is None:
                    return "unavailable"
            fresh = self._capture(entry)
            self._policy_context()
            return self._store.compare_protected(row[4], row[5], fresh.raw, fresh.source_identity)
        except (BindingError, StoreError):
            return "unavailable"
