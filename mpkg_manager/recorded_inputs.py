"""Current and retained declared-file evidence; never rendered input closure.

Collection requires caller-owned trusted store/policy handles. Shape validation
is not authentication and this module exposes no host or application authority.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re
import uuid

from .declarations import canonical_json
from .input_evidence import collection_time
from .protected_bindings import BindingError, ProtectedRecorder
from .store import HostStore, StoreError, MAX_INPUT_BYTES, _decode, _json


SOURCE = "recorded_input_comparison"
MANIFEST_SOURCE = "recorded_input_history"
SCOPE = "current_and_retained_declared_files"
MAX_SCOPE_COUNT = 256
MAX_SLOT_COUNT = 4096
MAX_CAPTURE_COUNT = 64
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_REASONS = {"collected", "policy_unavailable", "target_changed", "store_unavailable", "input_limit"}


class RecordedInputError(RuntimeError):
    def __init__(self, code="invalid_recorded_input_evidence"):
        self.code = code
        super().__init__(code)


def _require(condition):
    if not condition:
        raise RecordedInputError()


def _revision(value):
    return type(value) is int and 0 < value < 2**63


def _snapshot(value):
    _require(type(value) is dict and set(value) == {
        "id", "source_sha256", "canonical_sha256", "schema_version", "normalization_version"})
    for name in ("id", "source_sha256", "canonical_sha256"):
        _require(type(value[name]) is str and _HASH.fullmatch(value[name]))
    for name in ("schema_version", "normalization_version"):
        _require(type(value[name]) is int and value[name] == 1)


def _snapshot_identity(value):
    envelope = canonical_json({"source": value["source_sha256"], "canonical": value["canonical_sha256"],
        "schema": value["schema_version"], "normalization": value["normalization_version"]})
    _require(hashlib.sha256(envelope).hexdigest() == value["id"])


def _uuid(value):
    return type(value) is str and str(uuid.UUID(value)) == value


def _validate(value, *, manifest=False):
    fields = {"schema_version", "host_id", "revision", "snapshot", "source", "scope", "scopes"}
    if not manifest:
        fields |= {"observed_at", "state", "reason", "full_input_closure"}
    _require(type(value) is dict and set(value) == fields)
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    _require(_uuid(value["host_id"]) and _revision(value["revision"]))
    _snapshot(value["snapshot"])
    if manifest:
        _snapshot_identity(value["snapshot"])
    _require(value["source"] == (MANIFEST_SOURCE if manifest else SOURCE) and value["scope"] == SCOPE)
    if not manifest:
        _require(type(value["observed_at"]) is str)
        collection_time(value["observed_at"])
        _require(value["full_input_closure"] == "unverified")
        _require(value["state"] in ("complete", "unavailable") and value["reason"] in _REASONS)
        _require((value["state"] == "complete") == (value["reason"] == "collected"))
    scopes = value["scopes"]
    _require(type(scopes) is list and 1 <= len(scopes) <= MAX_SCOPE_COUNT)
    current_count, total, seen, contexts = 0, 0, set(), {}
    for scope in scopes:
        _require(type(scope) is dict and set(scope) == {
            "role", "stable_id", "resource_id", "adoption_revision", "recorded_revision",
            "management", "snapshot", "entries"})
        _snapshot(scope["snapshot"])
        if manifest:
            _snapshot_identity(scope["snapshot"])
        _require(_revision(scope["recorded_revision"]) and scope["recorded_revision"] <= value["revision"])
        if scope["role"] == "current":
            current_count += 1
            _require(scope["snapshot"] == value["snapshot"] and scope["stable_id"] is None
                     and scope["resource_id"] is None and scope["adoption_revision"] is None
                     and scope["management"] is None)
        else:
            _require(scope["role"] == "accepted" and _uuid(scope["stable_id"]))
            _require(type(scope["resource_id"]) is str and _ID.fullmatch(scope["resource_id"]))
            _require(_revision(scope["adoption_revision"])
                     and scope["adoption_revision"] == scope["recorded_revision"])
            _require(scope["management"] in ("accepted", "relinquished"))
        key = (scope["role"], scope["stable_id"])
        _require(key not in seen)
        seen.add(key)
        _require(type(scope["entries"]) is list)
        slots = set()
        for entry in scope["entries"]:
            fields = {"input_id", "file_index", "classification"} | (set() if manifest else {"state"})
            _require(type(entry) is dict and set(entry) == fields)
            _require(type(entry["input_id"]) is str and _ID.fullmatch(entry["input_id"]))
            _require(type(entry["file_index"]) is int and 0 <= entry["file_index"] < 2**63)
            _require(entry["classification"] in ("nonsecret", "protected"))
            if not manifest:
                _require(entry["state"] in ("same", "changed", "unavailable"))
                _require(value["state"] == "complete" or entry["state"] == "unavailable")
            slot = (entry["input_id"], entry["file_index"])
            _require(slot not in slots)
            slots.add(slot)
            context = (scope["recorded_revision"], scope["snapshot"]["id"], *slot)
            _require(context not in contexts or contexts[context] == entry)
            contexts[context] = entry
            _require(len(contexts) <= MAX_CAPTURE_COUNT)
        total += len(slots)
        _require(total <= MAX_SLOT_COUNT)
    _require(current_count == 1)


@dataclass(frozen=True)
class RecordedInputEvidence:
    """Immutable redacted projection; only a trusted collector supplies evidence."""
    canonical_bytes: bytes = field(repr=False)

    def __post_init__(self):
        try:
            _require(type(self.canonical_bytes) is bytes and len(self.canonical_bytes) <= MAX_EVIDENCE_BYTES)
            value = json.loads(self.canonical_bytes)
            _require(canonical_json(value) == self.canonical_bytes)
            _validate(value)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            raise RecordedInputError() from None

    def as_dict(self):
        return json.loads(self.canonical_bytes)


@dataclass(frozen=True)
class RecordedInputManifest:
    """Expected slots from trusted history, independent of observation results."""
    canonical_bytes: bytes = field(repr=False)

    def __post_init__(self):
        try:
            _require(type(self.canonical_bytes) is bytes and len(self.canonical_bytes) <= MAX_EVIDENCE_BYTES)
            value = json.loads(self.canonical_bytes)
            _require(canonical_json(value) == self.canonical_bytes)
            _validate(value, manifest=True)
        except (RecordedInputError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            raise RecordedInputError("invalid_recorded_input_manifest") from None

    def as_dict(self):
        return json.loads(self.canonical_bytes)


def _metadata(store, declaration):
    return {"id": store._snapshot_id(declaration),
            "source_sha256": hashlib.sha256(declaration.source_bytes).hexdigest(),
            "canonical_sha256": declaration.sha256, "schema_version": declaration.schema_version,
            "normalization_version": declaration.normalization_version}


def _accepted_bundles(model, resource, requirements):
    """Follow the original adoption's declared dependencies, never current IDs."""
    resources = {item["id"]: item for item in model["resources"]}
    pending, seen, bundles = [resource["id"]], set(), set()
    while pending:
        identity = pending.pop()
        if identity in seen:
            continue
        seen.add(identity)
        item = resources[identity]
        pending.extend(item["requires"])
        if "input" in item:
            bundles.add(item["input"]["bundle"])
        if "content_input" in item["desired"]:
            bundles.add(item["desired"]["content_input"])
        for component in model["components"]:
            for requirement in component["requirements"]:
                if requirement["resource"] == identity and requirement["property"] == "content_input":
                    bundles.add(requirement["value"])
    # Persisted consumer constraints can survive a later adoption declaration
    # that omits that consumer; they still name inputs in its validated model.
    for requirement in requirements:
        if requirement["property"] == "content_input":
            bundles.add(requirement["value"])
    return bundles


def _manifest(store, revision, snapshot_id):
    """Load a consistent private manifest, releasing the store before file I/O."""
    scopes, bindings = [], {}
    total = 0

    def append(declaration, recorded_revision, *, resource=None, requirements=(), stable_id=None,
               active=None):
        nonlocal total
        model = declaration.model
        wanted = None if resource is None else _accepted_bundles(model, resource, requirements)
        entries = []
        scope = {"role": "current" if resource is None else "accepted", "stable_id": stable_id,
                 "resource_id": None if resource is None else resource["id"],
                 "adoption_revision": None if resource is None else recorded_revision,
                 "recorded_revision": recorded_revision,
                 "management": None if resource is None else ("accepted" if active else "relinquished"),
                 "snapshot": _metadata(store, declaration), "entries": entries}
        for bundle in model["inputs"]:
            if wanted is not None and bundle["id"] not in wanted:
                continue
            for index, item in enumerate(bundle["files"]):
                result = {"input_id": bundle["id"], "file_index": index,
                          "classification": item["classification"], "state": "unavailable"}
                entries.append(result)
                key = (recorded_revision, scope["snapshot"]["id"], bundle["id"], index)
                if key not in bindings:
                    bindings[key] = ({"input_id": bundle["id"], "base_directory": bundle["base_directory"], **item}, [])
                bindings[key][1].append(result)
                total += 1
                if total > MAX_SLOT_COUNT or len(bindings) > MAX_CAPTURE_COUNT:
                    raise RecordedInputError("recorded_input_coverage_limit")
        scopes.append(scope)
        if len(scopes) > MAX_SCOPE_COUNT:
            raise RecordedInputError("recorded_input_coverage_limit")

    with store._read():
        row = store._db.execute("SELECT snapshot_id FROM decisions WHERE revision=?", (revision,)).fetchone()
        if store._revision() != revision or row is None or row[0] != snapshot_id:
            raise RecordedInputError("recorded_input_target_unavailable")
        declaration = store._load_snapshot(snapshot_id)
        # A relinquishment changes responsibility, not the recorded byte baseline.
        baseline = store._db.execute("SELECT revision,snapshot_id FROM decisions WHERE revision<=? "
                                     "AND kind!='relinquish' ORDER BY revision DESC LIMIT 1", (revision,)).fetchone()
        if baseline is None or baseline[1] != snapshot_id:
            raise StoreError("store_corrupt")
        append(declaration, baseline[0])
        for current in store._current_resources():
            adopted = store._db.execute("""SELECT r.revision,d.snapshot_id,r.definition,r.requirements
                FROM resources r JOIN decisions d ON d.revision=r.revision
                WHERE r.stable_id=? AND d.kind='adopt' ORDER BY r.revision DESC LIMIT 1""",
                (current["stable_id"],)).fetchone()
            if adopted is None:
                raise StoreError("store_corrupt")
            append(store._load_snapshot(adopted[1]), adopted[0], resource=_decode(adopted[2]),
                   requirements=_decode(adopted[3]), stable_id=current["stable_id"], active=current["active"])
    return scopes, bindings


def recorded_input_manifest(store, *, revision, snapshot_id):
    """Project exact expected current/accepted slots without reading input files."""
    if (type(store) is not HostStore or not _revision(revision)
            or type(snapshot_id) is not str or not _HASH.fullmatch(snapshot_id)):
        raise RecordedInputError("invalid_recorded_input_manifest_request")
    try:
        scopes, _ = _manifest(store, revision, snapshot_id)
    except StoreError:
        raise RecordedInputError("recorded_input_store_unavailable") from None
    for scope in scopes:
        for entry in scope["entries"]:
            del entry["state"]
    return RecordedInputManifest(_json({"schema_version": 1, "host_id": store.host_id,
        "revision": revision, "snapshot": scopes[0]["snapshot"], "source": MANIFEST_SOURCE,
        "scope": SCOPE, "scopes": scopes}))


def collect_recorded_inputs(recorder, *, revision, snapshot_id, observed_at=None):
    """Compare all current slots and original adopted dependency slots.

    A complete batch means the declared coverage is represented, including any
    unavailable files. It does not prove an atomic filesystem view, Compose
    rendering closure, classified-content secrecy, or application readiness.
    """
    try:
        when = collection_time(observed_at)
        if (type(recorder) is not ProtectedRecorder or not _revision(revision)
                or type(snapshot_id) is not str or not _HASH.fullmatch(snapshot_id)):
            raise ValueError
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise RecordedInputError("invalid_recorded_input_request") from None
    store = recorder._store
    try:
        scopes, bindings = _manifest(store, revision, snapshot_id)
    except StoreError:
        raise RecordedInputError("recorded_input_store_unavailable") from None
    result = {"schema_version": 1, "host_id": store.host_id, "revision": revision,
              "snapshot": scopes[0]["snapshot"], "observed_at": when, "source": SOURCE, "scope": SCOPE,
              "state": "complete", "reason": "collected", "scopes": scopes,
              "full_input_closure": "unverified"}
    if len(_json(result)) > MAX_EVIDENCE_BYTES:
        raise RecordedInputError("recorded_input_coverage_limit")
    reason = "collected"
    try:
        policy_context = recorder._policy_context()
    except BindingError:
        policy_context, reason = None, "policy_unavailable"
    remaining = MAX_CAPTURE_BYTES
    for (recorded_revision, source_snapshot, input_id, _), (entry, outputs) in bindings.items():
        if reason != "collected":
            break
        try:
            with store._read():
                if entry["classification"] == "protected":
                    row = store._bound_capture(entry["reference"], source_snapshot, recorded_revision)
                else:
                    row = store._nonsecret_capture(recorded_revision, source_snapshot, input_id, entry["path"])
            if row is None:
                continue
            fresh = recorder._capture(entry, max_bytes=min(MAX_INPUT_BYTES, remaining))
            remaining -= len(fresh.raw)
            state = store.compare_protected(row[4], row[5], fresh.raw, fresh.source_identity)
            for output in outputs:
                output["state"] = state
        except BindingError as error:
            if error.code == "protected_input_limit":
                reason = "input_limit"
            elif error.code == "policy_unavailable":
                reason = "policy_unavailable"
            # Even a failed read can consume its byte allowance. Keep remaining
            # rows explicitly unavailable and stop rather than spend it again.
            break
        except StoreError:
            reason = "store_unavailable"
            break
    try:
        with store._read():
            if store._revision() != revision:
                reason = "target_changed"
    except StoreError:
        reason = "store_unavailable"
    try:
        if recorder._policy_context() != policy_context:
            reason = "policy_unavailable"
    except BindingError:
        reason = "policy_unavailable"
    if reason != "collected":
        result["state"], result["reason"] = "unavailable", reason
        for scope in scopes:
            for entry in scope["entries"]:
                entry["state"] = "unavailable"
    return RecordedInputEvidence(_json(result))
