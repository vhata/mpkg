"""Closed public status response schema; validation grants no host authority."""
from datetime import datetime, timezone
import hashlib
import re
import uuid

from .declarations import load_declaration
from ._endpoint_process import PROBE_CODES


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_KINDS = frozenset({"package", "compose", "volume", "network", "service", "user", "group",
                    "file", "directory", "symlink", "sonarr_xml"})
_PROPERTIES = frozenset({"present", "source", "version", "running", "profiles", "services", "images",
    "enabled", "home", "shell", "primary_group", "groups", "members", "owner", "group", "mode",
    "content", "content_input", "target", "port"})
_SOURCES = frozenset({"pacman_installed_inventory", "pacman_dependency_satisfaction",
    "systemd_unit_properties", "docker_selected_project_inventory", "filesystem_metadata",
    "local_account_properties", "unsupported_adapter", "provided_observation"})
_INPUT_REASONS = frozenset({"collected", "history_unavailable", "intent_not_recorded", "not_observed",
    "host_mismatch", "target_mismatch", "from_future", "stale", "coverage_incomplete", "policy_unavailable",
    "target_changed", "store_unavailable", "protected_input_limit", "input_limit", "manifest_unavailable",
    "manifest_context_mismatch", "scope_mismatch"})
_ENDPOINT_REASONS = _INPUT_REASONS | frozenset({"accepted_check_definition_unavailable", "coverage_limit",
    "context_mismatch", "status_matches", "status_differs", "collection_budget_exhausted",
    "collection_probe_limit", "collection_probe_timeout", "physical_identity_unbound",
    "invalid_endpoint_context", "endpoint_runner_failed", "invalid_endpoint_result"}) | (PROBE_CODES - {"ok"})
_BLOCKERS = frozenset({"application_not_implemented", "attempt_history_unavailable",
    "history_unavailable", "history_host_mismatch", "intent_not_recorded", "recorded_input_unavailable",
    "recorded_input_changed", "protected_input_changed", "protected_input_unavailable",
    "observations_unavailable", "observations_host_mismatch", "observations_from_future", "observations_stale",
    "physical_identity_unbound", "resource_not_adopted", "accepted_resource_kind_changed",
    "recorded_disposition_pending", "consumer_change_requires_recording", "consumer_requirement_conflict",
    "consumer_context_conflict", "pending_property_difference", "property_authority_missing",
    "required_check_unverified", "accepted_check_definition_unavailable", "no_desired_properties",
    "native_resolution_not_performed", "functional_health_not_established", "input_freshness_unverified",
    "retained_resource_disposition_required", "resource_not_inspected", "property_not_inspected",
    "observation_identity_mismatch", "observation_source_unsupported", "compose_observation_context_missing",
    "compose_observed_engine_mismatch", "compose_observed_service_scope_mismatch",
    "observation_property_unsupported", "observation_unknown", "observation_unavailable", "observation_stale",
    "package_request_resolution_unknown", "local_account_presence_unverified", "observation_type_mismatch",
    "recipe_provenance_unverified", "observation_scope_limited", "observation_unavailable",
    "observation_host_mismatch", "observation_from_future"})
_COLLECTION_REASONS = frozenset({"status_logical_identity_conflict", "status_resource_kind_conflict",
    "status_compose_service_scope_conflict", "status_physical_identity_unbound",
    "status_resource_kind_unsupported", "status_collection_budget_exhausted", "status_query_limit",
    "status_query_byte_limit", "status_query_failed", "status_query_result_invalid", "status_query_output_limit",
    "status_query_timeout", "status_resource_limit", "status_adapter_unavailable", "status_no_recorded_snapshot",
    "status_input_observation_unavailable", "status_endpoint_collection_not_requested", "status_target_not_recorded",
    "status_endpoint_collection_unavailable"})
_ENDPOINT_LIMITATIONS = ["listener_attribution_unavailable", "application_identity_unverified"]
_REPORT_LIMITATIONS = ["time_bounded_observation_not_atomic_host_snapshot",
    "no_attempt_history_or_input_replay_verification", "no_native_resolution_or_executable_effects",
    "projections_require_trusted_host_boundary"]
_COLLECTION_LIMITATIONS = ["time_bounded_observation_not_atomic_host_snapshot",
    "filesystem_nss_policy_and_store_latency_have_no_deadline",
    "protected_input_reads_have_separate_byte_bounds_and_no_deadline",
    "query_output_budget_reserves_combined_stdout_stderr_capacity",
    "endpoint_transport_has_separate_per_probe_byte_bounds",
    "complete_input_closure_and_functional_health_unverified", "no_application_or_management_authority_inferred"]


def _require(condition):
    if not condition:
        raise ValueError("invalid_status_response")


def _validate(value, schema):
    if type(schema) is dict:
        _require(type(value) is dict and set(value) == set(schema))
        for key, nested in schema.items():
            _validate(value[key], nested)
    elif type(schema) is frozenset:
        _require(type(value) is str and value in schema)
    elif callable(schema):
        schema(value)
    else:
        _require(type(value) is type(schema) and value == schema)


def _nullable(schema):
    return lambda value: None if value is None else _validate(value, schema)


def _list(schema, limit=4096):
    def check(value):
        _require(type(value) is list and len(value) <= limit)
        for item in value:
            _validate(item, schema)
    return check


def _integer(value):
    _require(type(value) is int and 0 <= value < 2**63)


def _boolean(value):
    _require(type(value) is bool)


def _identifier(value):
    _require(type(value) is str and _ID.fullmatch(value))


def _hash(value):
    _require(type(value) is str and _HASH.fullmatch(value))


def _uuid(value):
    _require(type(value) is str and str(uuid.UUID(value)) == value)


def _time(value):
    _require(type(value) is str and len(value) == 27 and value.endswith("Z"))
    parsed = datetime.fromisoformat(value)
    _require(parsed.tzinfo == timezone.utc
             and parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") == value)


_ROLE = frozenset({"current", "accepted"})
_MANAGEMENT = frozenset({"accepted", "relinquished"})
_COVERAGE = frozenset({"complete", "unavailable"})
_INPUT_STATE = frozenset({"same", "changed", "unavailable"})
_SUMMARY = {"state": frozenset({"available", "unavailable"}), "reason": _INPUT_REASONS,
    "source": _nullable(frozenset({"recorded_input_comparison"})), "observed_at": _nullable(_time),
    "coverage": _COVERAGE, "full_input_closure": "unverified"}
_INPUT_ENTRY = {"input_id": _identifier, "file_index": _integer, "state": _INPUT_STATE}
_INPUT_SCOPE = {"role": _ROLE, "stable_id": _nullable(_uuid), "resource_id": _nullable(_identifier),
    "adoption_revision": _nullable(_integer), "recorded_revision": _nullable(_integer),
    "management": _nullable(_MANAGEMENT), "snapshot_id": _nullable(_hash), "coverage": _COVERAGE,
    "entries": _list(_INPUT_ENTRY | {"classification": frozenset({"protected", "nonsecret"})})}
_ROUTE = {"route_result": frozenset({"match", "mismatch", "unavailable"}), "route_reason": _ENDPOINT_REASONS,
    "functional_result": "unverified", "limitations": _ENDPOINT_LIMITATIONS}


def _check(value):
    _require(type(value) is dict)
    schema = {"id": _identifier, "role": _ROLE, "result": frozenset({"passed", "failed", "unknown"}),
              "reason": frozenset({"property_predicates_only", "functional_verification_unavailable",
                                   "check_not_implemented", "accepted_check_unavailable"})}
    if "route_result" in value:
        schema |= _ROUTE
    if "adoption_revision" in value:
        schema |= {"adoption_revision": _integer, "snapshot_id": _hash}
    _validate(value, schema)
    if value["role"] == "current":
        _require("adoption_revision" not in value)
    if "route_result" in value:
        _require(value["result"] == "unknown")


_REPORT = {
    "schema_version": 1, "host_id": _uuid, "created_at": _time,
    "target": {"source_sha256": _hash, "canonical_sha256": _hash, "schema_version": 1,
               "normalization_version": 1, "recorded": _boolean},
    "management": {"state": "available", "revision": _integer, "snapshot_id": _nullable(_hash)},
    "observation": {"state": frozenset({"available", "unavailable", "host_mismatch", "from_future", "stale"}),
                    "observed_at": _nullable(_time), "covered_resources": _list(_identifier), "scope_limited": _boolean},
    "selected_components": _list(_identifier),
    "resources": _list({"resource_id": _identifier, "kind": _KINDS, "stable_id": _nullable(_uuid),
        "management": _MANAGEMENT | frozenset({"identity_mismatch", "unadopted"}),
        "properties": _list({"property": _PROPERTIES, "comparison": frozenset({"agreement", "difference", "unknown", "conflict"}),
            "authority": _boolean, "evidence_source": _SOURCES, "limitations": _list(_BLOCKERS)}, 32),
        "checks": _list(_check), "known_consumers": _list(_identifier), "blockers": _list(_BLOCKERS)}),
    "retained_resources": _list({"stable_id": _uuid, "logical_id": _identifier, "management": _MANAGEMENT,
        "required_decision": _nullable(frozenset({"identity_unresolved", "retire_or_relinquish"})), "checks": _list(_check)}),
    "unselected_resources": _list({"stable_id": _uuid, "logical_id": _identifier, "management": _MANAGEMENT,
        "pending_disposition": _boolean, "checks": _list(_check)}),
    "protected_inputs": _SUMMARY | {"scope": "current_recorded_snapshot", "entries": _list(_INPUT_ENTRY),
        "historical_coverage": "unavailable", "nonsecret_entries_unchecked": _integer},
    "recorded_inputs": _SUMMARY | {"scope": "current_and_retained_declared_files",
        "historical_coverage": _COVERAGE, "required_slots": _integer, "scopes": _list(_INPUT_SCOPE, 256)},
    "endpoint_checks": {"state": frozenset({"available", "unavailable"}), "reason": _ENDPOINT_REASONS,
        "observed_at": _nullable(_time), "source": _nullable(frozenset({"recorded_loopback_endpoint_checks"})),
        "scope": "current_and_retained_required_endpoint_checks", "coverage": _COVERAGE, "required_checks": _integer,
        "entries": _list({"id": _identifier, "resource_id": _identifier, "role": _ROLE,
            "stable_id": _nullable(_uuid), "management": _nullable(_MANAGEMENT),
            "adoption_revision": _nullable(_integer)} | _ROUTE),
        "functional_result": "unverified", "limitations": _ENDPOINT_LIMITATIONS},
    "executable": False, "blockers": _list(_BLOCKERS), "limitations": _REPORT_LIMITATIONS,
}
_COLLECTION = {"host_id": _uuid, "revision": _integer, "snapshot_id": _nullable(_hash), "observed_at": _time,
    "targets": _list({"resource_id": _identifier, "kind": _KINDS, "current": _boolean,
        "stable_ids": _list(_uuid), "state": frozenset({"collected", "unavailable"}),
        "reason": _nullable(_COLLECTION_REASONS)}, 1024),
    "coverage_complete": True, "query_count": _integer, "query_output_bytes_reserved": _integer,
    "query_limits": _list(_COLLECTION_REASONS), "recorded_input_reason": _nullable(_COLLECTION_REASONS),
    "endpoint_reason": _nullable(_COLLECTION_REASONS), "limitations": _COLLECTION_LIMITATIONS, "executable": False}


def validate_status(value, request):
    """Reject unknown fields, free-form diagnostics and unsafe success claims.

    This checks public protocol shape/context, not the authenticity of a
    report or its suitability for host effects. Only the fixed helper sends
    production responses; no imported response is an authorization token.
    """
    _validate(value, {"report": _REPORT, "collection": _COLLECTION})
    report, collection = value["report"], value["collection"]
    _require(report["host_id"] == collection["host_id"]
             and report["management"]["revision"] == collection["revision"]
             and report["management"]["snapshot_id"] == collection["snapshot_id"]
             and report["observation"]["observed_at"] == collection["observed_at"])
    _require((collection["revision"] == 0) == (collection["snapshot_id"] is None))
    _require({"application_not_implemented", "attempt_history_unavailable"} <= set(report["blockers"]))
    _require(request.expected_revision is None or request.expected_revision == collection["revision"])
    if request.selected_components is not None:
        _require(list(request.selected_components) == report["selected_components"])
    if request.source is None:
        _require(report["target"]["recorded"] and collection["revision"] > 0)
    else:
        declaration = load_declaration(request.source)
        _require(report["target"]["source_sha256"] == hashlib.sha256(request.source).hexdigest()
                 and report["target"]["canonical_sha256"] == declaration.sha256)
    if not request.probe_endpoints:
        _require(collection["endpoint_reason"] == "status_endpoint_collection_not_requested")
        _require(all(item["route_result"] == "unavailable" for item in report["endpoint_checks"]["entries"]))
    if not report["target"]["recorded"]:
        _require("intent_not_recorded" in report["blockers"]
                 and report["recorded_inputs"]["state"] == "unavailable")
