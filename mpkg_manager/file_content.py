"""Private target-byte comparisons against authenticated recorded inputs.

Trusted caller-owned handles are required. Shape validation supplies neither
host authentication nor authority to write, adopt, restore or apply anything.
"""
from dataclasses import dataclass, field
import hmac
import json
import posixpath

from .declarations import canonical_json
from .input_evidence import collection_time
from .protected_bindings import BindingError, ProtectedRecorder
from .protected_capture import CaptureError, capture_protected
from .recorded_inputs import (_HASH, _ID, _metadata, _revision, _snapshot,
                              _snapshot_identity, _uuid, RecordedInputError)
from .store import HostStore, StoreError, MAX_INPUT_BYTES, _decode


SOURCE = "recorded_file_content_comparison"
MANIFEST_SOURCE = "recorded_file_content_history"
SCOPE = "current_and_retained_content_input_targets"
MAX_SCOPE_COUNT = 256
MAX_ENTRY_COUNT = 4096
MAX_TARGET_COUNT = 64
MAX_TARGET_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
_BATCH_REASONS = {"collected", "policy_unavailable", "target_changed",
                  "store_unavailable", "content_limit"}
_UNKNOWN_REASONS = {"not_observed", "baseline_unavailable", "target_unavailable",
                    "target_changed", "target_unsupported", "target_outside_policy",
                    "batch_unavailable"}


class FileContentError(RuntimeError):
    """Fixed diagnostics; never paths, references, bytes or content digests."""

    def __init__(self, code="invalid_file_content_evidence"):
        self.code = code
        super().__init__(code)


def _require(condition):
    if not condition:
        raise FileContentError()


def _validate(value, *, manifest):
    fields = {"schema_version", "host_id", "revision", "snapshot", "source", "scope", "scopes"}
    if not manifest:
        fields |= {"observed_at", "state", "reason", "source_input_freshness", "application"}
    _require(type(value) is dict and set(value) == fields)
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    _require(_uuid(value["host_id"]) and _revision(value["revision"]))
    _snapshot(value["snapshot"])
    _snapshot_identity(value["snapshot"])
    _require(value["source"] == (MANIFEST_SOURCE if manifest else SOURCE) and value["scope"] == SCOPE)
    if not manifest:
        _require(type(value["observed_at"]) is str)
        collection_time(value["observed_at"])
        _require(value["state"] in ("complete", "unavailable") and value["reason"] in _BATCH_REASONS)
        _require((value["state"] == "complete") == (value["reason"] == "collected"))
        _require(value["source_input_freshness"] == "not_observed" and value["application"] == "unverified")
    _require(type(value["scopes"]) is list and 1 <= len(value["scopes"]) <= MAX_SCOPE_COUNT)
    current_count, total, seen, contexts = 0, 0, set(), {}
    for scope in value["scopes"]:
        _require(type(scope) is dict and set(scope) == {
            "role", "stable_id", "resource_id", "adoption_revision", "recorded_revision",
            "management", "snapshot", "entries"})
        _snapshot(scope["snapshot"])
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
        obligations = set()
        for entry in scope["entries"]:
            fields = {"resource_id", "requirement", "consumer_id", "input_id", "file_index", "classification"}
            if not manifest:
                fields |= {"state", "reason"}
            _require(type(entry) is dict and set(entry) == fields)
            for name in ("resource_id", "input_id"):
                _require(type(entry[name]) is str and _ID.fullmatch(entry[name]))
            _require(type(entry["file_index"]) is int and entry["file_index"] == 0)
            _require(entry["classification"] in ("nonsecret", "protected"))
            if entry["requirement"] == "desired":
                _require(entry["consumer_id"] is None)
            else:
                _require(entry["requirement"] == "consumer" and type(entry["consumer_id"]) is str
                         and _ID.fullmatch(entry["consumer_id"]))
            if not manifest:
                _require(entry["state"] in ("same", "changed", "unavailable"))
                expected = {"same": {"matching_bytes"}, "changed": {"different_bytes"},
                            "unavailable": _UNKNOWN_REASONS}
                _require(entry["reason"] in expected[entry["state"]])
                _require(value["state"] == "complete" or (entry["state"] == "unavailable"
                         and entry["reason"] == "batch_unavailable"))
            obligation = (entry["resource_id"], entry["requirement"], entry["consumer_id"])
            _require(obligation not in obligations)
            obligations.add(obligation)
            context = (scope["recorded_revision"], scope["snapshot"]["id"], entry["resource_id"], entry["input_id"])
            projection = {key: item for key, item in entry.items() if key not in ("requirement", "consumer_id")}
            _require(context not in contexts or contexts[context] == projection)
            contexts[context] = projection
        total += len(obligations)
        _require(total <= MAX_ENTRY_COUNT and len(contexts) <= MAX_TARGET_COUNT)
    _require(current_count == 1)


def _decode_projection(raw, *, manifest):
    try:
        _require(type(raw) is bytes and len(raw) <= MAX_EVIDENCE_BYTES)
        value = json.loads(raw)
        _require(canonical_json(value) == raw)
        _validate(value, manifest=manifest)
    except (FileContentError, RecordedInputError, ValueError, TypeError, KeyError,
            AttributeError, OverflowError, RecursionError):
        raise FileContentError("invalid_file_content_manifest" if manifest
                               else "invalid_file_content_evidence") from None


@dataclass(frozen=True)
class FileContentManifest:
    """Immutable expected obligations from history, independent of observations."""
    canonical_bytes: bytes = field(repr=False)

    def __post_init__(self):
        _decode_projection(self.canonical_bytes, manifest=True)

    def as_dict(self):
        return json.loads(self.canonical_bytes)


@dataclass(frozen=True)
class FileContentEvidence:
    """Immutable sanitized results; constructors do not authenticate evidence."""
    canonical_bytes: bytes = field(repr=False)

    def __post_init__(self):
        _decode_projection(self.canonical_bytes, manifest=False)

    def as_dict(self):
        return json.loads(self.canonical_bytes)


def _request(store, revision, snapshot_id):
    if (type(store) is not HostStore or not _revision(revision)
            or type(snapshot_id) is not str or not _HASH.fullmatch(snapshot_id)):
        raise FileContentError("invalid_file_content_request")


def _manifest(store, revision, snapshot_id):
    scopes, bindings = [], {}
    total = 0

    def append(declaration, recorded_revision, *, resource=None, requirements=(), stable_id=None, active=None):
        nonlocal total
        model = declaration.model
        resources = {item["id"]: item for item in model["resources"]}
        wanted = set(resources) if resource is None else set()
        pending = [] if resource is None else [resource["id"]]
        if resource is not None:
            resources[resource["id"]] = resource
        while pending:
            identity = pending.pop()
            if identity not in wanted:
                wanted.add(identity)
                pending.extend(resources[identity]["requires"])
        scope = {"role": "current" if resource is None else "accepted", "stable_id": stable_id,
                 "resource_id": None if resource is None else resource["id"],
                 "adoption_revision": None if resource is None else recorded_revision,
                 "recorded_revision": recorded_revision,
                 "management": None if resource is None else ("accepted" if active else "relinquished"),
                 "snapshot": _metadata(store, declaration), "entries": []}
        bundles = {item["id"]: item for item in model["inputs"]}
        for identity in sorted(wanted):
            target = resources[identity]
            if target["kind"] != "file":
                continue
            obligations = {}
            if "content_input" in target["desired"]:
                obligations[("desired", None)] = target["desired"]["content_input"]
            for component in model["components"]:
                for item in component["requirements"]:
                    if item["resource"] == identity and item["property"] == "content_input":
                        obligations[("consumer", component["id"])] = item["value"]
            if resource is not None and identity == resource["id"]:
                for item in requirements:
                    if item["property"] == "content_input":
                        obligations[("consumer", item["consumer"])] = item["value"]
            for (role, consumer), input_id in obligations.items():
                bundle = bundles[input_id]
                item = bundle["files"][0]  # Validated content_input is exactly one file.
                entry = {"resource_id": identity, "requirement": role, "consumer_id": consumer,
                         "input_id": input_id, "file_index": 0, "classification": item["classification"],
                         "state": "unavailable", "reason": "not_observed"}
                scope["entries"].append(entry)
                key = (recorded_revision, scope["snapshot"]["id"], identity, input_id)
                if key not in bindings:
                    bindings[key] = ({"input_id": input_id, "base_directory": bundle["base_directory"],
                                      "target_path": target["identity"]["path"], **item}, [])
                bindings[key][1].append(entry)
                total += 1
                if total > MAX_ENTRY_COUNT or len(bindings) > MAX_TARGET_COUNT:
                    raise FileContentError("file_content_coverage_limit")
        scopes.append(scope)
        if len(scopes) > MAX_SCOPE_COUNT:
            raise FileContentError("file_content_coverage_limit")

    with store._read():
        row = store._db.execute("SELECT snapshot_id FROM decisions WHERE revision=?", (revision,)).fetchone()
        if store._revision() != revision or row is None or row[0] != snapshot_id:
            raise FileContentError("file_content_target_unavailable")
        baseline = store._db.execute("SELECT revision,snapshot_id FROM decisions WHERE revision<=? "
                                    "AND kind!='relinquish' ORDER BY revision DESC LIMIT 1", (revision,)).fetchone()
        if baseline is None or baseline[1] != snapshot_id:
            raise StoreError("store_corrupt")
        append(store._load_snapshot(snapshot_id), baseline[0])
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


def _envelope(store, revision, scopes, source):
    return {"schema_version": 1, "host_id": store.host_id, "revision": revision,
            "snapshot": scopes[0]["snapshot"], "source": source, "scope": SCOPE, "scopes": scopes}


def file_content_manifest(store, *, revision, snapshot_id):
    """Derive complete expected content_input obligations from verified history."""
    _request(store, revision, snapshot_id)
    try:
        scopes, _ = _manifest(store, revision, snapshot_id)
    except StoreError:
        raise FileContentError("file_content_store_unavailable") from None
    for scope in scopes:
        for entry in scope["entries"]:
            del entry["state"], entry["reason"]
    encoded = canonical_json(_envelope(store, revision, scopes, MANIFEST_SOURCE))
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise FileContentError("file_content_coverage_limit")
    return FileContentManifest(encoded)


def _capture_target(recorder, binding, maximum):
    context = recorder._policy_context()
    target = binding["target_path"]
    roots = [root for root in context["allowed_input_roots"]
             if posixpath.commonpath((root, target)) == root and target != root]
    if not roots:
        raise CaptureError("target_outside_policy")
    root = max(roots, key=lambda item: len(item.split("/")))
    return capture_protected(recorder._policy, root=root, relative_path=posixpath.relpath(target, root),
                             name="declared-target-content", purpose="Compare declared target content",
                             max_bytes=maximum)


def collect_file_content(recorder, *, revision, snapshot_id, observed_at=None):
    """Read declared targets only, comparing bytes privately with recorded inputs.

    No source file is reread: source freshness is a separate evidence stream.
    Coverage completion is not application authority or even agreement.
    """
    if type(recorder) is not ProtectedRecorder:
        raise FileContentError("invalid_file_content_request")
    _request(recorder._store, revision, snapshot_id)
    try:
        when = collection_time(observed_at)
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise FileContentError("invalid_file_content_request") from None
    store = recorder._store
    try:
        scopes, bindings = _manifest(store, revision, snapshot_id)
    except StoreError:
        raise FileContentError("file_content_store_unavailable") from None
    result = _envelope(store, revision, scopes, SOURCE) | {
        "observed_at": when, "state": "complete", "reason": "collected",
        "source_input_freshness": "not_observed", "application": "unverified"}
    if len(canonical_json(result)) > MAX_EVIDENCE_BYTES:
        raise FileContentError("file_content_coverage_limit")
    reason, policy_context = "collected", None
    try:
        policy_context = recorder._policy_context()
    except BindingError:
        reason = "policy_unavailable"
    remaining = MAX_TARGET_BYTES
    for (recorded_revision, source_snapshot, _, input_id), (binding, outputs) in bindings.items():
        if reason != "collected":
            break
        try:
            with store._read():
                if binding["classification"] == "protected":
                    row = store._bound_capture(binding["reference"], source_snapshot, recorded_revision)
                else:
                    row = store._nonsecret_capture(recorded_revision, source_snapshot, input_id, binding["path"])
            if row is None:
                for output in outputs:
                    output["reason"] = "baseline_unavailable"
                continue
            captured = _capture_target(recorder, binding, min(MAX_INPUT_BYTES, remaining))
            remaining -= len(captured.raw)
            same = hmac.compare_digest(row[0], captured.raw)
            for output in outputs:
                output["state"] = "same" if same else "changed"
                output["reason"] = "matching_bytes" if same else "different_bytes"
        except CaptureError as error:
            if error.code == "input_too_large":
                reason = "content_limit"
            elif error.code == "policy_unavailable":
                reason = "policy_unavailable"
            else:
                code = {"input_changed": "target_changed", "input_path_changed": "target_changed",
                        "input_not_regular": "target_unsupported", "input_hardlinked": "target_unsupported",
                        "input_metadata_unsupported": "target_unsupported",
                        "input_device_changed": "target_unsupported",
                        "target_outside_policy": "target_outside_policy"}.get(error.code, "target_unavailable")
                for output in outputs:
                    output["reason"] = code
            # A failed read may consume its allowance; never spend it again.
            break
        except BindingError:
            reason = "policy_unavailable"
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
                entry["state"], entry["reason"] = "unavailable", "batch_unavailable"
    return FileContentEvidence(canonical_json(result))
