"""Private immutable Sonarr Port proposals, never application authority.

Only this trusted adapter derives the fixed effect and candidate. No public
function accepts a report, candidate bytes, an executable or an action graph.
Installed integration, worker and mutation prerequisites remain unimplemented.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
import json
import posixpath
import re
import uuid

from .host_policy import _absolute
from .protected_bindings import BindingError, ProtectedRecorder
from .sonarr_xml import SonarrXmlError, transform_port
from .store import (HostStore, StoreError, MAX_INPUT_BYTES, _decode,
                    _declared_nonsecret, _declared_protected, _framed_mac, _json)


ADAPTER = "sonarr_xml_port_v1"
MAX_CONTEXT_BYTES = 1024 * 1024
MAX_PREREQUISITES = 64
_DOMAIN = b"MPKGSONARRPROPOSAL\x00\x01"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_BLOCKERS = ("installed_integration_unverified", "worker_unimplemented",
             "attempt_history_unavailable", "maintenance_interval_unaccepted",
             "writer_exclusion_unverified", "container_identity_unbound",
             "atomic_publication_unimplemented", "full_input_closure_unverified",
             "required_after_checks_unverified")


class ProposalError(RuntimeError):
    """Fixed diagnostic codes without private candidate or input material."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SonarrPortProposal:
    """Redacted inspection result; constructing one grants no authority."""
    _summary: bytes = field(repr=False)

    def as_dict(self):
        return json.loads(self._summary)


def _require(condition, code="invalid_proposal_request"):
    if not condition:
        raise ProposalError(code)


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _arguments(revision, snapshot_id, stable_id):
    _require(type(revision) is int and 1 <= revision < 2**63 - 1)
    _require(type(snapshot_id) is str and _HASH.fullmatch(snapshot_id))
    _require(_uuid(stable_id))


def _records(store, revision):
    rows = store._db.execute("""SELECT r.stable_id,r.revision,r.logical_id,r.physical_key,
        r.definition,r.requirements,r.active FROM resources r JOIN
        (SELECT stable_id,max(revision) revision FROM resources WHERE revision<=? GROUP BY stable_id) x
        ON r.stable_id=x.stable_id AND r.revision=x.revision ORDER BY r.stable_id""", (revision,))
    return [{"stable_id": row[0], "revision": row[1], "logical_id": row[2],
             "physical_key": _decode(row[3]), "definition": _decode(row[4]),
             "requirements": _decode(row[5]), "active": bool(row[6])} for row in rows]


def _checks(store, record):
    row = store._db.execute("SELECT kind,snapshot_id FROM decisions WHERE revision=?",
                            (record["revision"],)).fetchone()
    _require(row is not None and row[0] == "adopt", "proposal_authority_unavailable")
    checks = store._load_snapshot(row[1]).model["checks"]
    return {"stable_id": record["stable_id"], "adoption_revision": record["revision"],
            "snapshot_id": row[1], "definitions": [check for check in checks
                if check["id"] in record["definition"]["checks"]]}


def _policy_context(value, store, entry):
    _require(type(value) is dict and set(value) == {
        "host_id", "engine_aliases", "allowed_input_roots", "identity"}, "proposal_policy_unavailable")
    _require(value["host_id"] == store.host_id and value["engine_aliases"] == store.engine_aliases,
             "proposal_policy_unavailable")
    roots = value["allowed_input_roots"]
    _require(type(roots) is list and 1 <= len(roots) <= 64
             and all(_absolute(root) for root in roots) and len(set(roots)) == len(roots),
             "proposal_policy_unavailable")
    _require(type(value["identity"]) is list and len(value["identity"]) == 9
             and all(type(part) is str and re.fullmatch(r"[0-9]{1,32}", part)
                     for part in value["identity"]), "proposal_policy_unavailable")
    target = posixpath.join(entry["base_directory"], entry["path"])
    _require(any(posixpath.commonpath((root, target)) == root for root in roots),
             "proposal_policy_unavailable")


def _scope(store, declaration, snapshot_id, revision, target, records, role):
    """Resolve each role only through its own exact snapshot and historical records."""
    by_id = {resource["id"]: resource for resource in declaration.model["resources"]}
    pending, seen, prerequisites, checks = list(target["requires"]), set(), [], []
    resources, missing = [target], False
    while pending:
        name = pending.pop(0)
        if name in seen:
            continue
        seen.add(name)
        _require(len(seen) <= MAX_PREREQUISITES, "proposal_scope_limit")
        resource = by_id[name]
        resources.append(resource)
        try:
            physical = store._physical(resource)
        except StoreError:
            physical = None
        record = next((item for item in records if item["physical_key"] == physical), None)
        bound = record is not None and record["active"]
        prerequisites.append({"resource_id": name, "definition": resource, "physical_key": physical,
                              "stable_id": record["stable_id"] if bound else None,
                              "adoption_revision": record["revision"] if bound else None,
                              "accepted_definition": record["definition"] if bound else None,
                              "accepted_requirements": record["requirements"] if bound else None})
        if bound:
            checks.append(_checks(store, record))
        else:
            missing = True
        pending.extend(resource["requires"])
    bundles = {resource["input"]["bundle"] for resource in resources if "input" in resource}
    entries = [entry for entry in _declared_protected(declaration) + _declared_nonsecret(declaration)
               if entry["input_id"] in bundles]
    _require(len(entries) <= 256, "proposal_scope_limit")
    inputs = []
    for entry in entries:
        if entry["classification"] == "protected":
            capture = store._bound_capture(entry["reference"], snapshot_id, revision)
        else:
            capture = store._nonsecret_capture(revision, snapshot_id, entry["input_id"], entry["path"])
        inputs.append({"entry": entry, "state": "bound" if capture is not None else "unavailable",
                       "origin_revision": None if capture is None else capture[4],
                       "token": None if capture is None else capture[3].hex(),
                       "source_identity": None if capture is None else _decode(capture[1])})
    return {"role": role, "revision": revision, "snapshot_id": snapshot_id,
            "prerequisites": prerequisites, "inputs": inputs, "accepted_checks": checks,
            "declared_checks": declaration.model["checks"], "missing_authority": missing}


def _accepted_dependency_scopes(store, scopes, target):
    pending = [item for scope in scopes for item in scope["prerequisites"]]
    seen, result = {(target["stable_id"], target["revision"])}, []
    while pending:
        item = pending.pop(0)
        key = (item["stable_id"], item["adoption_revision"])
        if key[0] is None or key in seen:
            continue
        seen.add(key)
        _require(len(seen) <= MAX_PREREQUISITES, "proposal_scope_limit")
        records = _records(store, key[1])
        record = next(record for record in records if record["stable_id"] == key[0])
        checks = _checks(store, record)
        declaration = store._load_snapshot(checks["snapshot_id"])
        scope = _scope(store, declaration, checks["snapshot_id"], key[1], record["definition"],
                       records, "accepted_dependency")
        scope["stable_id"] = key[0]
        scope["target_checks"] = checks
        result.append(scope)
        _require(len(_json(result)) <= MAX_CONTEXT_BYTES, "proposal_scope_limit")
        pending.extend(scope["prerequisites"])
    return result


def _derive(store, revision, snapshot_id, stable_id, policy):
    """Historical derivation only; caller holds a verified store transaction."""
    _arguments(revision, snapshot_id, stable_id)
    decision = store._db.execute("SELECT snapshot_id FROM decisions WHERE revision=?", (revision,)).fetchone()
    _require(decision is not None and decision[0] == snapshot_id, "proposal_snapshot_mismatch")
    declaration = store._load_snapshot(snapshot_id)
    model, records = declaration.model, _records(store, revision)
    accepted = next((record for record in records if record["stable_id"] == stable_id), None)
    _require(accepted is not None and accepted["active"], "proposal_authority_unavailable")
    _require(accepted["definition"]["kind"] == "sonarr_xml"
             and accepted["definition"]["manage"] == ["port"], "proposal_authority_unavailable")
    targets = [resource for resource in model["resources"]
               if resource["kind"] == "sonarr_xml" and store._physical(resource) == accepted["physical_key"]]
    _require(len(targets) == 1, "proposal_target_unavailable")
    target = targets[0]
    _require(target["kind"] == "sonarr_xml" and target["manage"] == ["port"]
             and set(target["desired"]) == {"port"}, "proposal_authority_conflict")
    # Reuse the actual adoption invariant checks without recording adoption.
    # Current consumer constraints never erase retained accepted constraints.
    combined = store._adoption_record(model, target, records)
    entries = [entry for entry in _declared_protected(declaration)
               if "input" in target and entry["input_id"] == target["input"]["bundle"]
               and posixpath.join(entry["base_directory"], entry["path"]) == target["identity"]["path"]]
    _require(len(entries) == 1, "proposal_input_unavailable")
    entry = entries[0]
    capture = store._bound_capture(entry["reference"], snapshot_id, revision)
    _require(capture is not None, "proposal_input_unavailable")
    _policy_context(policy, store, entry)
    try:
        candidate = transform_port(capture[0], target["desired"]["port"], expected_original=capture[0])
    except SonarrXmlError:
        raise ProposalError("proposal_transform_unsupported") from None
    accepted_target_checks = _checks(store, accepted)
    accepted_snapshot = accepted_target_checks["snapshot_id"]
    retained_declaration = store._load_snapshot(accepted_snapshot)
    scopes = [_scope(store, declaration, snapshot_id, revision, target, records, "current"),
              _scope(store, retained_declaration, accepted_snapshot, accepted["revision"],
                     accepted["definition"], _records(store, accepted["revision"]), "accepted")]
    dependency_scopes = _accepted_dependency_scopes(store, scopes, accepted)
    accepted_checks = [accepted_target_checks]
    for scope in scopes + dependency_scopes:
        for check_role in scope["accepted_checks"] + ([scope["target_checks"]] if "target_checks" in scope else []):
            if check_role not in accepted_checks:
                accepted_checks.append(check_role)
    blockers = list(_BLOCKERS)
    for scope in scopes + dependency_scopes:
        if scope["missing_authority"] and "prerequisite_authority_unavailable" not in blockers:
            blockers.append("prerequisite_authority_unavailable")
        if any(item["state"] == "unavailable" for item in scope["inputs"]):
            reason = scope["role"] + "_input_obligations_unavailable"
            if reason not in blockers:
                blockers.append(reason)
    if any(scope["prerequisites"] for scope in scopes):
        blockers.append("prerequisite_readiness_unverified")
    context = {"version": 1, "host_id": store.host_id, "revision": revision,
               "snapshot_id": snapshot_id, "stable_id": stable_id,
               "adoption_revision": accepted["revision"], "physical_key": accepted["physical_key"],
               "accepted_definition": accepted["definition"], "target_definition": target,
               "accepted_requirements": accepted["requirements"],
               "combined_requirements": combined["requirements"], "scopes": scopes,
               "accepted_dependency_scopes": dependency_scopes,
               "accepted_checks": accepted_checks, "current_checks": model["checks"],
               "before": {"entry": entry, "origin_revision": capture[4],
                          "source_identity": _decode(capture[1]), "token": capture[3].hex()},
               "capture_policy": policy, "candidate": candidate.as_dict(), "blockers": blockers,
               "effect": {"kind": "sonarr_port_change", "adapter": ADAPTER,
                          "timeout_seconds": 30, "interruption": "requires_accepted_maintenance_interval"}}
    _require(len(_json(context)) <= MAX_CONTEXT_BYTES, "proposal_scope_limit")
    return context, candidate.candidate_bytes, capture, entry


def _seal(store, identity, created_at, context, candidate):
    key = store._db.execute("SELECT private_key FROM host").fetchone()[0]
    return _framed_mac(key, _DOMAIN, {"id": identity, "created_at": created_at,
                       "adapter": ADAPTER, "state": "blocked", "context": context}, candidate)


def _verified_row(store, row):
    identity, revision, snapshot, stable, adoption, reference, when, adapter, state, raw, candidate, seal = row
    _require(_uuid(identity), "proposal_corrupt")
    timestamp = datetime.fromisoformat(when)
    _require(timestamp.tzinfo == timezone.utc and timestamp.isoformat(timespec="microseconds") == when,
             "proposal_corrupt")
    _require(adapter == ADAPTER and state == "blocked" and type(raw) is bytes
             and len(raw) <= MAX_CONTEXT_BYTES and type(candidate) is bytes
             and len(candidate) <= MAX_INPUT_BYTES, "proposal_corrupt")
    context = _decode(raw)
    _require(_json(context) == raw, "proposal_corrupt")
    expected, transformed, _, _ = _derive(store, revision, snapshot, stable, context["capture_policy"])
    _require(_json(expected) == raw and transformed == candidate
             and expected["adoption_revision"] == adoption
             and expected["before"]["entry"]["reference"] == reference,
             "proposal_corrupt")
    _require(type(seal) is bytes and hmac.compare_digest(seal, _seal(store, identity, when, context, candidate)),
             "proposal_corrupt")
    return context


def _verify_proposals(store):
    try:
        for row in store._db.execute("SELECT * FROM sonarr_port_proposals ORDER BY id"):
            _verified_row(store, row)
    except (ProposalError, SonarrXmlError, ValueError, TypeError, KeyError, AttributeError,
            OverflowError, RecursionError):
        raise StoreError("store_corrupt") from None


def _projection(row, context, current_revision):
    return SonarrPortProposal(_json({"proposal_id": row[0], "host_id": context["host_id"],
        "revision": row[1], "snapshot_id": row[2], "stable_resource_id": row[3],
        "adoption_revision": row[4], "created_at": row[6], "adapter": ADAPTER,
        "state": "blocked", "executable": False, "effect": "sonarr_port_change",
        "original_port": context["candidate"]["original_port"],
        "port": context["candidate"]["port"], "unchanged": context["candidate"]["unchanged"],
        "input_comparison": "matched_at_proposal", "live_prerequisites": "unverified",
        "decision_state": "current" if row[1] == current_revision else "superseded",
        "prerequisite_count": len(context["scopes"][0]["prerequisites"]),
        "retained_prerequisite_count": len(context["scopes"][1]["prerequisites"]),
        "current_input_count": len(context["scopes"][0]["inputs"]),
        "retained_input_count": len(context["scopes"][1]["inputs"]),
        "accepted_dependency_scope_count": len(context["accepted_dependency_scopes"]),
        "accepted_check_count": sum(len(role["definitions"]) for role in context["accepted_checks"]),
        "current_check_count": len(context["current_checks"]), "blockers": context["blockers"]}))


def derive_sonarr_port_proposal(recorder, *, expected_revision, snapshot_id, stable_resource_id):
    """Persist a blocked proposal from authenticated history and a fresh capture.

    Filesystem capture runs outside the write transaction. This is a recording
    precondition, not writer exclusion or authority to publish the candidate.
    """
    _require(type(recorder) is ProtectedRecorder)
    _arguments(expected_revision, snapshot_id, stable_resource_id)
    store = recorder._store
    try:
        policy = recorder._policy_context()
        with store._read():
            recorder._revision(expected_revision)
            _require(store._schema_version >= 3, "proposal_migration_required")
            context, candidate, capture, entry = _derive(store, expected_revision, snapshot_id,
                                                         stable_resource_id, policy)
        fresh = recorder._capture(entry)
        _require(recorder._same_capture(fresh, capture[0], capture[1]), "proposal_input_changed")
        _require(recorder._policy_context() == policy, "proposal_policy_unavailable")
        identity = str(uuid.uuid4())
        when = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        with store._write(expected_revision):
            _require(recorder._policy_context() == policy, "proposal_policy_unavailable")
            again, transformed, _, _ = _derive(store, expected_revision, snapshot_id, stable_resource_id, policy)
            _require(_json(again) == _json(context) and transformed == candidate, "proposal_context_changed")
            row = (identity, expected_revision, snapshot_id, stable_resource_id,
                   context["adoption_revision"], entry["reference"], when, ADAPTER, "blocked",
                   _json(context), candidate, _seal(store, identity, when, context, candidate))
            store._db.execute("INSERT INTO sonarr_port_proposals VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", row)
            _verified_row(store, row)
        return _projection(row, context, expected_revision)
    except BindingError:
        raise ProposalError("proposal_input_unavailable") from None
    except SonarrXmlError:
        raise ProposalError("proposal_transform_unsupported") from None


def read_sonarr_port_proposal(store, proposal_id):
    """Read verified historical proposal evidence; never refresh execution gates."""
    _require(type(store) is HostStore and _uuid(proposal_id))
    with store._read():
        _require(store._schema_version >= 3, "proposal_migration_required")
        row = store._db.execute("SELECT * FROM sonarr_port_proposals WHERE id=?", (proposal_id,)).fetchone()
        _require(row is not None, "proposal_missing")
        context = _verified_row(store, row)
        return _projection(row, context, store._revision())


def list_sonarr_port_proposals(store, *, limit=100, after_id=None):
    """Bounded UUID-ordered inspection, including recovery after commit errors."""
    _require(type(store) is HostStore and type(limit) is int and 1 <= limit <= 100)
    _require(after_id is None or _uuid(after_id))
    with store._read():
        _require(store._schema_version >= 3, "proposal_migration_required")
        rows = store._db.execute("SELECT * FROM sonarr_port_proposals WHERE id>? ORDER BY id LIMIT ?",
                                ("" if after_id is None else after_id, limit)).fetchall()
        return [_projection(row, _verified_row(store, row), store._revision()) for row in rows]
