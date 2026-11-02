"""Pure comparisons, never an executable plan or a privilege boundary."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid

from .declarations import (Declaration, DeclarationError, canonical_json, load_declaration,
                           physical_key, validate_model)
from .observations import ComposeContext
from .input_evidence import input_evidence
from .endpoint_checks import (EndpointCheckBatch, EndpointCollectionError, MAX_CHECKS,
                              LIMITATIONS as ENDPOINT_LIMITATIONS, _scopes as _endpoint_scopes)


MAX_PROJECTION_BYTES = 16 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_KINDS = {"package", "compose", "volume", "network", "service", "user", "group",
          "file", "directory", "symlink", "sonarr_xml"}
_SOURCES = {"pacman_installed_inventory", "pacman_dependency_satisfaction", "systemd_unit_properties",
            "docker_selected_project_inventory", "filesystem_metadata", "local_account_properties",
            "unsupported_adapter"}


class PlanningError(ValueError):
    """A fixed diagnostic, without source, projection or underlying errors."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ComparisonReport:
    canonical_bytes: bytes
    sha256: str

    def as_dict(self):
        return json.loads(self.canonical_bytes)


def _require(condition):
    if not condition:
        raise ValueError


def _uuid(value):
    _require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def _strings(value):
    _require(type(value) is list and all(type(item) is str for item in value))
    _require(len(set(value)) == len(value))
    return value


def _table(value, keys):
    _require(type(value) is dict and set(value) == set(keys))


def _time(value):
    _require(type(value) is str and value.endswith("Z"))
    result = datetime.fromisoformat(value)
    _require(result.utcoffset().total_seconds() == 0)
    return result


def _copy(value):
    raw = canonical_json(value)
    _require(len(raw) <= MAX_PROJECTION_BYTES)
    return json.loads(raw)


def _identity(resource):
    """Validate the identity schema before the validated-only key helper."""
    model = validate_model({"schema": 1, "components": [], "resources": [
        {"id": "identity", "kind": resource["kind"], "identity": resource["identity"]}]})
    return model["resources"][0]


def _management(value, aliases):
    if value is None:
        return None
    result = _copy(value)
    _table(result, ("host_id", "revision", "snapshot_id", "snapshot", "resources"))
    _uuid(result["host_id"])
    _require(type(result["revision"]) is int and result["revision"] >= 0)
    snapshot = result["snapshot"]
    if snapshot is None:
        _require(result["revision"] == 0 and result["snapshot_id"] is None)
    else:
        _table(snapshot, ("id", "source_sha256", "canonical_sha256", "schema_version",
                          "normalization_version"))
        for key in ("id", "source_sha256", "canonical_sha256"):
            _require(type(snapshot[key]) is str and _HASH.fullmatch(snapshot[key]))
        _require(result["snapshot_id"] == snapshot["id"] and result["revision"] > 0)
        for key in ("schema_version", "normalization_version"):
            _require(type(snapshot[key]) is int and snapshot[key] == 1)
    _require(type(result["resources"]) is list)
    seen_ids, seen_keys = set(), set()
    for resource in result["resources"]:
        fields = ("stable_id", "logical_id", "physical_key", "definition", "requirements",
                  "management", "declaration_state", "pending_disposition", "observation")
        _table(resource, fields + (("accepted_checks",) if "accepted_checks" in resource else ()))
        stable = _uuid(resource["stable_id"])
        _require(stable not in seen_ids)
        seen_ids.add(stable)
        key = resource["physical_key"]
        _require(type(key) is list and len(key) >= 3 and all(type(item) is str for item in key))
        _require(key[0] == result["host_id"] and tuple(key) not in seen_keys)
        seen_keys.add(tuple(key))
        _require(type(resource["logical_id"]) is str)
        _require(resource["management"] in ("accepted", "relinquished"))
        _require(resource["declaration_state"] in ("present", "absent", "unknown"))
        _require(type(resource["pending_disposition"]) is bool)
        _require(resource["observation"] == {"state": "unknown", "reason": "not_observed"})
        definition = resource["definition"]
        _require(type(definition) is dict and definition.get("kind") in _KINDS)
        _require(definition.get("id") == resource["logical_id"])
        _require(type(definition.get("identity")) is dict and type(definition.get("desired")) is dict)
        _require(all(type(k) is str and type(v) is str for k, v in definition["identity"].items()))
        for field in ("manage", "consumers", "checks", "requires"):
            _strings(definition[field])
        _require(set(definition["manage"]) <= set(definition["desired"]))
        identity = _identity(definition)
        if "engine" not in identity["identity"] or identity["identity"]["engine"] in aliases:
            _require(list(physical_key(identity, result["host_id"], aliases)) == key)
        _require(type(resource["requirements"]) is list)
        for requirement in resource["requirements"]:
            _table(requirement, ("consumer", "property", "value"))
            _require(type(requirement["consumer"]) is str and type(requirement["property"]) is str)
        if "accepted_checks" in resource:
            _accepted_check_projection(resource, result)
    _require(snapshot is not None or not result["resources"])
    return result


def _accepted_check_projection(resource, current):
    binding = resource["accepted_checks"]
    _table(binding, ("adoption_revision", "snapshot_id", "definitions"))
    revision = binding["adoption_revision"]
    _require(type(revision) is int and 0 < revision <= current["revision"])
    _require(type(binding["snapshot_id"]) is str and _HASH.fullmatch(binding["snapshot_id"]))
    if revision == current["revision"]:
        _require(binding["snapshot_id"] == current["snapshot_id"])
    definition = resource["definition"]
    # Validate the closed predicate schema without recreating authority or
    # requiring unrelated input/dependency definitions in this projection.
    minimal = {key: definition[key] for key in ("id", "kind", "identity", "consumers", "checks")}
    components = [{"id": consumer, "purpose": "Accepted check context",
                   "resources": [definition["id"]]}
                  for consumer in definition["consumers"] if not consumer.startswith("external:")]
    checked = validate_model({"schema": 1, "resources": [minimal], "components": components,
                              "checks": binding["definitions"]})
    _require(_same(checked["checks"], binding["definitions"]))
    _require([check["id"] for check in checked["checks"]] == definition["checks"])


def _observation(value):
    if value is None:
        return None
    result = _copy(value)
    _table(result, ("host_id", "observed_at", "facts", "coverage", "limitations"))
    _uuid(result["host_id"])
    _time(result["observed_at"])
    _strings(result["coverage"])
    _strings(result["limitations"])
    _require(type(result["facts"]) is list)
    seen = set()
    for fact in result["facts"]:
        _table(fact, ("host_id", "resource_id", "kind", "identity", "property", "state", "value",
                      "observed_at", "evidence_source", "limitations")
               + (("compose_context",) if "compose_context" in fact else ()))
        _require(fact["host_id"] == result["host_id"] and fact["observed_at"] == result["observed_at"])
        _require(type(fact["resource_id"]) is str and fact["resource_id"] in result["coverage"])
        _require(type(fact["kind"]) is str and type(fact["property"]) is str)
        _require(type(fact["identity"]) is dict and
                 all(type(k) is str and type(v) is str for k, v in fact["identity"].items()))
        _identity(fact)
        _require(fact["state"] in ("known", "absent", "unknown"))
        _require(type(fact["value"]) in (str, int, bool, type(None)))
        _require(fact["state"] == "known" or fact["value"] is None)
        _require(type(fact["evidence_source"]) is str)
        _strings(fact["limitations"])
        if "compose_context" in fact:
            context = ComposeContext.from_dict(fact["compose_context"]).for_fact(fact["kind"], fact["property"])
            fact["compose_context"] = context.as_dict()
        _require(fact["state"] != "unknown" or fact["limitations"])
        key = (fact["resource_id"], fact["property"])
        _require(key not in seen)
        seen.add(key)
    return result


def _same(left, right):
    return canonical_json(left) == canonical_json(right)


def _key(resource, host_id, aliases):
    try:
        return tuple(physical_key(_identity(resource), host_id, aliases))
    except (DeclarationError, KeyError, TypeError):
        return None


def _constraints_valid(model, resource, constraints):
    # A validation-only component combines retained/current constraints with
    # the complete target context, including input definitions. It grants no
    # authority and is never returned or recorded as a real consumer.
    context = _copy(model)
    names = {item["id"] for item in context["components"]}
    suffix = 0
    name = "retained-validation-0"
    while name in names:
        suffix += 1
        name = f"retained-validation-{suffix}"
    requirements = {}
    for item in constraints:
        requirement = {"resource": resource["id"], "property": item["property"], "value": item["value"]}
        requirements[canonical_json(requirement)] = requirement
    context["components"].append({"id": name, "purpose": "Validation-only retained constraints",
                                  "resources": [resource["id"]],
                                  "requirements": list(requirements.values())})
    try:
        validate_model(context)
        return True
    except DeclarationError:
        return False


def build_report(declaration, current, observations, *, host_id, engine_aliases=None,
                 selected_components=None, now=None, max_age_seconds=60, input_observations=None,
                 endpoint_observations=None):
    """Compare trusted helper projections without reading, recording or applying.

    Projection dictionaries are not authentication. A caller must obtain them
    through its trusted host boundary; this API never produces executable plans.
    """
    try:
        _uuid(host_id)
        _require(type(max_age_seconds) is int and 0 < max_age_seconds <= 3600)
        now = datetime.now(timezone.utc) if now is None else now
        _require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None)
        now = now.astimezone(timezone.utc)
        aliases = {} if engine_aliases is None else _copy(engine_aliases)
        _require(type(aliases) is dict and all(type(k) is str and type(v) is str and v
                                             for k, v in aliases.items()))
    except (ValueError, TypeError, AttributeError, OverflowError, DeclarationError, RecursionError):
        raise PlanningError("invalid_report_context") from None
    try:
        _require(isinstance(declaration, Declaration))
        validated = load_declaration(declaration.source_bytes)
        _require(validated == declaration)
        model = validated.model
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise PlanningError("invalid_declaration_snapshot") from None
    try:
        current = _management(current, aliases)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise PlanningError("invalid_management_projection") from None
    try:
        observations = _observation(observations)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise PlanningError("invalid_observation_projection") from None
    try:
        inputs = None if input_observations is None else input_evidence(input_observations).as_dict()
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise PlanningError("invalid_input_observation_projection") from None
    try:
        endpoints = endpoint_observations
        if endpoints is not None:
            _require(type(endpoints) is EndpointCheckBatch)
            endpoints = EndpointCheckBatch(endpoints.host_id, endpoints.revision, endpoints._snapshot_id,
                                           endpoints.observed_at, endpoints.checks, endpoints.probe_count)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise PlanningError("invalid_endpoint_observation") from None
    try:
        return _build(validated, model, current, observations, host_id, aliases,
                      selected_components, now, max_age_seconds, inputs, endpoints)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise PlanningError("invalid_report_inputs") from None


def _input_summary(model, current, evidence, recorded, host_id, now, max_age):
    slots = [(bundle["id"], index) for bundle in model["inputs"]
             for index, item in enumerate(bundle["files"]) if item["classification"] == "protected"]
    reason = "collected"
    if current is None:
        reason = "history_unavailable"
    elif not recorded:
        reason = "intent_not_recorded"
    elif evidence is None:
        reason = "not_observed"
    elif evidence["host_id"] != host_id:
        reason = "host_mismatch"
    elif evidence["revision"] != current["revision"] or evidence["snapshot"] != current["snapshot"]:
        reason = "target_mismatch"
    elif evidence["state"] != "complete":
        reason = evidence["reason"]
    else:
        age = (now - _time(evidence["observed_at"])).total_seconds()
        if age < 0:
            reason = "from_future"
        elif age > max_age:
            reason = "stale"
        elif set(slots) != {(entry["input_id"], entry["file_index"]) for entry in evidence["entries"]}:
            reason = "coverage_incomplete"
    found = {(entry["input_id"], entry["file_index"]): entry["state"]
             for entry in evidence["entries"]} if reason == "collected" else {}
    entries = [{"input_id": name, "file_index": index, "state": found.get((name, index), "unavailable")}
               for name, index in slots]
    return {"state": "available" if reason == "collected" else "unavailable", "reason": reason,
            "observed_at": evidence["observed_at"] if evidence else None,
            "source": evidence["source"] if evidence else None,
            "scope": "current_recorded_snapshot", "coverage": "complete" if reason == "collected" else "unavailable",
            "entries": entries, "historical_coverage": "unavailable",
            "nonsecret_entries_unchecked": sum(item["classification"] == "nonsecret"
                for bundle in model["inputs"] for item in bundle["files"]),
            "full_input_closure": "unverified"}



def _endpoint_summary(model, current, evidence, recorded, host_id, aliases, now, max_age):
    # Scope is global even for selected-component reports. Keep original
    # accepted labels here; native property comparison may use a renamed label.
    expected, required_count, missing_definitions = [], 0, False

    def append(check, role, record=None):
        nonlocal required_count
        if check["kind"] != "endpoint":
            return
        required_count += 1
        if required_count <= MAX_CHECKS:
            expected.append((check, role, record))

    for record in current["resources"] if current else ():
        if "accepted_checks" not in record:
            missing_definitions = True
            continue
        for check in record["accepted_checks"]["definitions"]:
            append(check, "accepted", record)
    checks = {check["id"]: check for check in model["checks"]}
    for resource in model["resources"]:
        for name in resource["checks"]:
            append(checks[name], "current")

    reason = "collected"
    if current is None:
        reason = "history_unavailable"
    elif not recorded:
        reason = "intent_not_recorded"
    elif evidence is None:
        reason = "not_observed"
    elif evidence.host_id != host_id:
        reason = "host_mismatch"
    elif not evidence.matches_context(host_id=host_id, revision=current["revision"],
                                      snapshot_id=current["snapshot_id"]):
        reason = "target_mismatch"
    elif missing_definitions:
        reason = "accepted_check_definition_unavailable"
    else:
        age = (now - _time(evidence.observed_at)).total_seconds()
        if age < 0:
            reason = "from_future"
        elif age > max_age:
            reason = "stale"
    if required_count > MAX_CHECKS:
        reason = "coverage_limit"
        expected = []  # No truncated inventory can claim complete coverage.

    found = {}
    if reason == "collected":
        try:
            scopes = _endpoint_scopes(current, model, aliases)
        except EndpointCollectionError as error:
            reason = "coverage_limit" if error.code == "endpoint_coverage_limit" else "context_mismatch"
        else:
            supplied = {row._scope: row for row in evidence.checks}
            if set(scopes) != set(supplied):
                def role_key(raw):
                    scope = json.loads(raw)
                    return scope["role"], scope["stable_id"], scope["context"]["check"]["id"]
                reason = ("coverage_incomplete" if {role_key(raw) for raw in scopes}
                          != {role_key(raw) for raw in supplied} else "context_mismatch")
            else:
                # ID lookup is safe only after complete private scopes matched,
                # including every predicate, physical target and adoption.
                for raw, row in supplied.items():
                    scope = json.loads(raw)
                    key = scope["role"], scope["stable_id"], scope["context"]["check"]["id"]
                    found[key] = row.as_dict()
    entries, by_role = [], {}
    for check, role, record in expected:
        stable_id = record["stable_id"] if record else None
        key = role, stable_id, check["id"]
        value = found.get(key)
        entry = {"id": check["id"], "resource_id": check["resource"], "role": role,
                 "stable_id": stable_id, "management": record["management"] if record else None,
                 "adoption_revision": record["accepted_checks"]["adoption_revision"] if record else None,
                 "route_result": value["route_result"] if value else "unavailable",
                 "route_reason": value["reason"] if value else reason,
                 "functional_result": "unverified", "limitations": list(ENDPOINT_LIMITATIONS)}
        entries.append(entry)
        by_role[key] = entry
    summary = {"state": "available" if reason == "collected" else "unavailable", "reason": reason,
               "observed_at": evidence.observed_at if evidence else None,
               "source": "recorded_loopback_endpoint_checks" if evidence else None,
               "scope": "current_and_retained_required_endpoint_checks",
               "coverage": "complete" if reason == "collected" else "unavailable",
               "required_checks": required_count, "entries": entries,
               "functional_result": "unverified", "limitations": list(ENDPOINT_LIMITATIONS)}
    return summary, by_role


def _build(declaration, model, current, observations, host_id, aliases, selection, now, max_age, inputs, endpoints):
    resources = {item["id"]: item for item in model["resources"]}
    components = {item["id"]: item for item in model["components"]}
    if selection is None:
        selected = list(components)
        included = set(resources)
    else:
        selected = list(_strings(selection))
        _require(set(selected) <= set(components))
        included = {reference for name in selected for reference in components[name]["resources"]}
        pending = list(included)
        while pending:
            for reference in resources[pending.pop()]["requires"]:
                if reference not in included:
                    included.add(reference)
                    pending.append(reference)
    blocks = {"application_not_implemented", "attempt_history_unavailable"}
    history_state = "available"
    if current is None or current["host_id"] != host_id:
        history_state = "unavailable" if current is None else "host_mismatch"
        blocks.add("history_" + history_state)
        current = None
    source_hash = hashlib.sha256(declaration.source_bytes).hexdigest()
    snapshot = current["snapshot"] if current else None
    recorded = bool(snapshot and snapshot["source_sha256"] == source_hash
                    and snapshot["canonical_sha256"] == declaration.sha256
                    and snapshot["schema_version"] == declaration.schema_version
                    and snapshot["normalization_version"] == declaration.normalization_version)
    if not recorded:
        blocks.add("intent_not_recorded")
    input_summary = _input_summary(model, current, inputs, recorded, host_id, now, max_age)
    endpoint_summary, endpoint_results = _endpoint_summary(
        model, current, endpoints, recorded, host_id, aliases, now, max_age)
    for entry in input_summary["entries"]:
        if entry["state"] != "same":
            blocks.add("protected_input_" + entry["state"])
    observation_state = "available"
    if observations is None:
        observation_state = "unavailable"
    elif observations["host_id"] != host_id:
        observation_state = "host_mismatch"
    else:
        age = (now - _time(observations["observed_at"])).total_seconds()
        if age < 0:
            observation_state = "from_future"
        elif age > max_age:
            observation_state = "stale"
    if observation_state != "available":
        blocks.add("observations_" + observation_state)
    facts = ({(item["resource_id"], item["property"]): item for item in observations["facts"]}
             if observations else {})
    coverage = set(observations["coverage"]) if observations else set()
    record_keys = {item["stable_id"]: _key(item["definition"], host_id, aliases)
                   for item in current["resources"]} if current else {}
    accepted = {tuple(item["physical_key"]): item for item in current["resources"]
                if record_keys[item["stable_id"]] is not None} if current else {}
    if any(key is None for key in record_keys.values()):
        blocks.add("physical_identity_unbound")
    keys = {name: _key(resource, host_id, aliases) for name, resource in resources.items()}
    bound = [key for key in keys.values() if key is not None]
    _require(len(set(bound)) == len(bound))
    requirements = {name: [] for name in resources}
    for component in components.values():
        for requirement in component["requirements"]:
            requirements[requirement["resource"]].append({"consumer": component["id"],
                "property": requirement["property"], "value": requirement["value"]})

    def fact_for(resource, prop, *, expected_key=None):
        if observation_state != "available":
            return None, "observations_" + observation_state
        if resource["id"] not in coverage:
            return None, "resource_not_inspected"
        fact = facts.get((resource["id"], prop))
        if fact is None:
            return None, "property_not_inspected"
        target_key = _key(resource, host_id, aliases) if expected_key is None else tuple(expected_key)
        if (fact["kind"] != resource["kind"] or target_key is None
                or _key(fact, host_id, aliases) != target_key):
            return None, "observation_identity_mismatch"
        source = {"package": "pacman_installed_inventory", "service": "systemd_unit_properties",
                  "compose": "docker_selected_project_inventory", "file": "filesystem_metadata",
                  "directory": "filesystem_metadata", "symlink": "filesystem_metadata",
                  "user": "local_account_properties", "group": "local_account_properties"}.get(resource["kind"])
        if resource["kind"] == "package" and fact["evidence_source"] == "pacman_dependency_satisfaction":
            source = "pacman_dependency_satisfaction"
        if source is None or fact["evidence_source"] != source:
            return fact, "observation_source_unsupported"
        if source == "docker_selected_project_inventory":
            context = fact.get("compose_context")
            if context is None:
                return fact, "compose_observation_context_missing"
            if context["engine_id"] != target_key[2]:
                return fact, "compose_observed_engine_mismatch"
            if prop == "running":
                services = resource["desired"].get("services", [])
                if not services or context.get("services") != sorted(services):
                    return fact, "compose_observed_service_scope_mismatch"
            if prop not in {"present", "container_count", "running"}:
                return fact, "observation_property_unsupported"
        if source == "pacman_dependency_satisfaction" and prop != "present":
            return fact, "observation_property_unsupported"
        if (source == "pacman_installed_inventory"
                and prop not in {"present", "version", "install_reason"}):
            return fact, "observation_property_unsupported"
        if (source == "filesystem_metadata"
                and prop not in ({"present", "mode", "owner", "group"}
                                 | ({"target"} if resource["kind"] == "symlink" else set()))):
            return fact, "observation_property_unsupported"
        if (source == "local_account_properties"
                and prop not in ({"present", "home", "shell", "primary_group"}
                                 if resource["kind"] == "user" else {"present"})):
            return fact, "observation_property_unsupported"
        if fact["state"] != "known":
            return fact, "observation_" + fact["state"]
        if source == "pacman_dependency_satisfaction" and fact["value"] is not True:
            return fact, "package_request_resolution_unknown"
        if source == "local_account_properties" and prop == "present" and fact["value"] is not True:
            return fact, "local_account_presence_unverified"
        return fact, None

    def compare(resource, prop, expected, *, expected_key=None):
        fact, reason = fact_for(resource, prop, expected_key=expected_key)
        source = (fact["evidence_source"] if fact and fact["evidence_source"] in _SOURCES
                  else "provided_observation")
        if reason:
            return "unknown", [reason], source
        if resource["kind"] == "user" and prop != "present":
            present, present_reason = fact_for(resource, "present", expected_key=expected_key)
            if present_reason or present["value"] is not True:
                return "unknown", ["local_account_presence_unverified"], source
        if resource["kind"] == "package" and prop == "present" and fact["value"] is False:
            return "unknown", ["package_request_resolution_unknown"], source
        if resource["kind"] == "package" and prop in ("version", "install_reason"):
            present, present_reason = fact_for(resource, "present", expected_key=expected_key)
            if (present_reason or present["value"] is not True
                    or present["evidence_source"] != "pacman_installed_inventory"):
                return "unknown", ["package_request_resolution_unknown"], source
        if resource["kind"] == "package" and prop == "version" and type(expected) is dict:
            if type(fact["value"]) is not str:
                return "unknown", ["observation_type_mismatch"], source
            same = expected["policy"] == "any" or expected["value"] == fact["value"]
            if same and "recipe_revision" in expected:
                return "unknown", ["recipe_provenance_unverified"], source
        else:
            same = _same(expected, fact["value"])
        limitations = ["observation_scope_limited"] if fact["limitations"] else []
        return ("agreement" if same else "difference"), limitations, source

    def check_results(resource, definitions, role, binding=None, expected_key=None, endpoint_record=None):
        results, reasons = [], set()
        for check in sorted(definitions, key=lambda item: item["id"]):
            if check["kind"] == "endpoint":
                result, reason = "unknown", "functional_verification_unavailable"
            elif check["kind"] not in ("package", "service"):
                result, reason = "unknown", "check_not_implemented"
            else:
                states = [compare(resource, "install_reason" if prop == "reason" else prop,
                                  value, expected_key=expected_key)[0]
                          for prop, value in check["expected"].items()]
                result = ("failed" if "difference" in states else
                          "unknown" if any(state != "agreement" for state in states) else "passed")
                reason = "property_predicates_only"
            entry = {"id": check["id"], "role": role, "result": result, "reason": reason}
            if check["kind"] == "endpoint":
                key = role, endpoint_record["stable_id"] if endpoint_record else None, check["id"]
                route = endpoint_results.get(key)
                entry.update({"route_result": route["route_result"] if route else "unavailable",
                              "route_reason": route["route_reason"] if route else endpoint_summary["reason"],
                              "functional_result": "unverified", "limitations": list(ENDPOINT_LIMITATIONS)})
            if binding is not None:
                entry.update({"adoption_revision": binding["adoption_revision"],
                              "snapshot_id": binding["snapshot_id"]})
            results.append(entry)
            if result != "passed":
                reasons.add("required_check_unverified")
        return results, reasons

    def accepted_check_results(record, resource=None):
        if record is None:
            return [], set()
        binding = record.get("accepted_checks")
        if binding is None:
            results = [{"id": identity, "role": "accepted", "result": "unknown",
                        "reason": "accepted_check_unavailable"}
                       for identity in sorted(record["definition"]["checks"])]
            return results, {"accepted_check_definition_unavailable", "required_check_unverified"}
        target = record["definition"]
        if resource is not None:
            # The stable physical key binds historical predicates to the
            # current observation label without replacing their expectations.
            target = target | {"id": resource["id"]}
        return check_results(target, binding["definitions"], "accepted", binding,
                             tuple(record["physical_key"]), endpoint_record=record)

    check_definitions = {item["id"]: item for item in model["checks"]}
    rows = []
    for name, resource in resources.items():
        if name not in included:
            continue
        record = accepted.get(keys[name])
        compatible = record is not None and record["definition"]["kind"] == resource["kind"]
        managed = compatible and record["management"] == "accepted"
        reasons = set()
        if keys[name] is None:
            reasons.add("physical_identity_unbound")
        if not managed:
            reasons.add("resource_not_adopted")
        if record is not None and not compatible:
            reasons.add("accepted_resource_kind_changed")
        if managed and record["pending_disposition"]:
            reasons.add("recorded_disposition_pending")
        expected = {prop: [value] for prop, value in resource["desired"].items()}
        retained_constraints = record["requirements"] if compatible else []
        constraints = requirements[name] + retained_constraints
        valid_context = not retained_constraints or _constraints_valid(model, resource, constraints)
        for requirement in constraints:
            expected.setdefault(requirement["property"], []).append(requirement["value"])
        accepted_manage = set(record["definition"]["manage"]) if managed else set()
        accepted_consumers = set(record["definition"]["consumers"]) if compatible else set()
        consumers = accepted_consumers | set(resource["consumers"])
        if compatible and accepted_consumers != set(resource["consumers"]):
            reasons.add("consumer_change_requires_recording")
        properties = []
        for prop, values in sorted(expected.items()):
            authority = prop in accepted_manage and prop in resource["manage"]
            if len({canonical_json(value) for value in values}) > 1:
                state, limits, source = "conflict", ["consumer_requirement_conflict"], "provided_observation"
            elif not valid_context:
                state, limits, source = "conflict", ["consumer_context_conflict"], "provided_observation"
            else:
                state, limits, source = compare(resource, prop, values[0])
            reasons.update(limits)
            if state != "agreement":
                if not limits:
                    reasons.add("pending_property_difference")
                if not authority:
                    reasons.add("property_authority_missing")
            properties.append({"property": prop, "comparison": state, "authority": authority,
                               "evidence_source": source, "limitations": limits})
        checks, check_reasons = accepted_check_results(record, resource)
        reasons.update(check_reasons)
        current_checks, check_reasons = check_results(
            resource, [check_definitions[identity] for identity in resource["checks"]], "current")
        checks.extend(current_checks)
        reasons.update(check_reasons)
        if not properties:
            reasons.add("no_desired_properties")
        if resource["kind"] == "package":
            reasons.add("native_resolution_not_performed")
        if resource["kind"] in ("service", "compose"):
            reasons.add("functional_health_not_established")
        if resource.get("input") or any(prop in expected for prop in ("content_input", "images")):
            reasons.add("input_freshness_unverified")
        rows.append({"resource_id": name, "kind": resource["kind"],
                     "stable_id": record["stable_id"] if record else None,
                     "management": (record["management"] if compatible else
                                    "identity_mismatch" if record else "unadopted"),
                     "properties": properties, "checks": checks, "known_consumers": sorted(consumers),
                     "blockers": sorted(reasons)})
        blocks.update(reasons)
    retained, unselected = [], []
    if current:
        selected_keys = {keys[name] for name in included}
        for record in current["resources"]:
            record_key = record_keys[record["stable_id"]]
            if record_key is not None and tuple(record["physical_key"]) in bound:
                if tuple(record["physical_key"]) not in selected_keys:
                    declared_resource = next(resource for name, resource in resources.items()
                                             if keys[name] == tuple(record["physical_key"]))
                    checks, check_reasons = accepted_check_results(record, declared_resource)
                    blocks.update(check_reasons)
                    unselected.append({"stable_id": record["stable_id"],
                                       "logical_id": record["logical_id"],
                                       "management": record["management"],
                                       "pending_disposition": record["pending_disposition"],
                                       "checks": checks})
                    if record["pending_disposition"] and record["management"] == "accepted":
                        blocks.add("recorded_disposition_pending")
                continue
            uncertain = record_key is None
            active = record["management"] == "accepted"
            decision = ("identity_unresolved" if uncertain else "retire_or_relinquish") if active else None
            checks, check_reasons = accepted_check_results(record)
            blocks.update(check_reasons)
            retained.append({"stable_id": record["stable_id"], "logical_id": record["logical_id"],
                             "management": record["management"], "required_decision": decision,
                             "checks": checks})
            if active:
                blocks.add("retained_resource_disposition_required" if not uncertain else "physical_identity_unbound")
    report = {"schema_version": 1, "host_id": host_id,
              "created_at": now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
              "target": {"source_sha256": source_hash, "canonical_sha256": declaration.sha256,
                         "schema_version": declaration.schema_version,
                         "normalization_version": declaration.normalization_version,
                         "recorded": recorded},
              "management": {"state": history_state, "revision": current["revision"] if current else None,
                             "snapshot_id": current["snapshot_id"] if current else None},
              "observation": {"state": observation_state,
                              "observed_at": observations["observed_at"] if observations else None,
                              "covered_resources": sorted(included & coverage),
                              "scope_limited": bool(observations and observations["limitations"])},
              "selected_components": selected, "resources": rows, "retained_resources": retained,
              "unselected_resources": unselected,
              "protected_inputs": input_summary, "endpoint_checks": endpoint_summary,
              "executable": False, "blockers": sorted(blocks),
              "limitations": ["time_bounded_observation_not_atomic_host_snapshot",
                              "no_attempt_history_or_input_replay_verification",
                              "no_native_resolution_or_executable_effects",
                              "projections_require_trusted_host_boundary"]}
    raw = canonical_json(report)
    return ComparisonReport(raw, hashlib.sha256(raw).hexdigest())
