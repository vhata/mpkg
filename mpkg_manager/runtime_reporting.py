"""Pure runtime/access comparisons against independently supplied history."""
from datetime import datetime
import json

from .declarations import canonical_json
from .runtime_checks import (RuntimeCheckManifest, RuntimeCheckBatch, LIMITATIONS,
                             _context, _public_scope)


SUMMARY_REASONS = frozenset({"collected", "history_unavailable", "intent_not_recorded",
    "manifest_unavailable", "manifest_context_mismatch", "not_observed", "context_mismatch",
    "from_future", "stale", "collection_modes_mismatch"})


def validate_inputs(manifest, evidence):
    if manifest is not None:
        if type(manifest) is not RuntimeCheckManifest:
            raise ValueError
        manifest.__post_init__()
    if evidence is not None:
        if type(evidence) is not RuntimeCheckBatch:
            raise ValueError
        evidence.__post_init__()


def _expected_scopes(model, current, host_id, aliases, included, *, retained_only=False):
    scopes = []

    def append(check, resource, record=None):
        if check["kind"] not in ("endpoint", "access"):
            return
        scopes.append(canonical_json({
            "role": "accepted" if record else "current",
            "context": _context(check, resource, host_id, aliases),
            "snapshot_id": record["accepted_checks"]["snapshot_id"] if record else current["snapshot_id"],
            "stable_id": record["stable_id"] if record else None,
            "adoption_revision": record["accepted_checks"]["adoption_revision"] if record else None,
            "management": record["management"] if record else None,
            "selected": True if record else resource["id"] in included}))

    for record in current["resources"]:
        for check in record["accepted_checks"]["definitions"]:
            append(check, record["definition"], record)
    if not retained_only:
        checks = {check["id"]: check for check in model["checks"]}
        for resource in model["resources"]:
            for name in resource["checks"]:
                append(checks[name], resource)
    return tuple(scopes)


def summarize(model, current, manifest, evidence, *, recorded, host_id, aliases,
              selection, included, now, max_age, attribute_endpoints, check_consumer_access):
    """Typed values are not authentication; callers own trusted live provenance."""
    reason = "collected"
    context_valid = False
    if current is None:
        reason = "history_unavailable"
    elif manifest is None:
        reason = "manifest_unavailable"
    else:
        expected_selection = None if selection is None or not recorded else tuple(sorted(selection))
        context_valid = (manifest.matches_context(host_id=host_id, revision=current["revision"],
                            snapshot_id=current["snapshot_id"])
                         and manifest._selection == expected_selection)
        try:
            expected = _expected_scopes(model, current, host_id, aliases, included,
                                        retained_only=not recorded)
            supplied = (manifest._scopes if recorded else tuple(raw for raw in manifest._scopes
                         if json.loads(raw)["role"] == "accepted"))
            context_valid = context_valid and expected == supplied
        except (KeyError, ValueError, TypeError, AttributeError):
            context_valid = False
        if not context_valid:
            reason = "manifest_context_mismatch"
        elif not recorded:
            reason = "intent_not_recorded"
        elif evidence is None:
            reason = "not_observed"
        elif (evidence.probe_endpoints != attribute_endpoints
              or evidence.check_access != check_consumer_access):
            reason = "collection_modes_mismatch"
        else:
            age = (now - datetime.fromisoformat(evidence.observed_at)).total_seconds()
            if age < 0:
                reason = "from_future"
            elif age > max_age:
                reason = "stale"
            elif not evidence.matches_manifest(manifest, now=now, max_age_seconds=max_age):
                reason = "context_mismatch"
    # Invalid expected scope is never used as a purported complete inventory.
    scopes = manifest._scopes if context_valid else ()
    rows, by_role = [], {}
    observed = {row._scope: row for row in evidence.checks} if reason == "collected" else {}
    for raw in scopes:
        private = json.loads(raw)
        row = _public_scope(private)
        if raw in observed:
            row = observed[raw].as_dict()
        else:
            row.update(reason=reason, functional_result="unverified")
            if row["check_kind"] == "endpoint":
                row.update(attribution="unavailable", route_result="not_observed")
            else:
                row.update(access_result="unavailable")
        rows.append(row)
        by_role[row["role"], row["stable_id"], row["check_id"]] = row
    available = reason == "collected"
    summary = {"state": "available" if available else "unavailable", "reason": reason,
        "source": "recorded_runtime_and_consumer_checks" if available else None,
        "observed_at": evidence.observed_at if available else None,
        "scope": "current_and_retained_runtime_and_consumer_checks",
        "coverage": "complete" if available else "unavailable",
        "required_checks": len(scopes) if context_valid else None, "entries": rows,
        "attribute_endpoints": attribute_endpoints, "check_consumer_access": check_consumer_access,
        "endpoint_count": evidence.endpoint_count if available else 0,
        "access_count": evidence.access_count if available else 0,
        "query_count": evidence.query_count if available else 0,
        "query_output_bytes_reserved": evidence.query_output_bytes_reserved if available else 0,
        "query_limits": list(evidence.query_limits) if available else [],
        "functional_result": "unverified", "executable": False, "limitations": list(LIMITATIONS)}
    return summary, by_role
