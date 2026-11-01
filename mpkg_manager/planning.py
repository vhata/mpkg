"""Pure comparisons, never an executable plan or a privilege boundary."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid

from .declarations import Declaration, DeclarationError, canonical_json, load_declaration, physical_key


MAX_PROJECTION_BYTES = 16 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_KINDS = {"package", "compose", "volume", "network", "service", "user", "group",
          "file", "directory", "symlink", "sonarr_xml"}
_SOURCES = {"pacman_installed_inventory", "systemd_unit_properties", "unsupported_adapter"}


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


def _management(value):
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
        _table(resource, ("stable_id", "logical_id", "physical_key", "definition", "requirements",
                          "management", "declaration_state", "pending_disposition", "observation"))
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
        if "engine" not in definition["identity"]:
            _require(list(physical_key(definition, result["host_id"], {})) == key)
        _require(type(resource["requirements"]) is list)
        for requirement in resource["requirements"]:
            _table(requirement, ("consumer", "property", "value"))
            _require(type(requirement["consumer"]) is str and type(requirement["property"]) is str)
    _require(snapshot is not None or not result["resources"])
    return result


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
                      "observed_at", "evidence_source", "limitations"))
        _require(fact["host_id"] == result["host_id"] and fact["observed_at"] == result["observed_at"])
        _require(type(fact["resource_id"]) is str and fact["resource_id"] in result["coverage"])
        _require(type(fact["kind"]) is str and type(fact["property"]) is str)
        _require(type(fact["identity"]) is dict and
                 all(type(k) is str and type(v) is str for k, v in fact["identity"].items()))
        _require(fact["state"] in ("known", "absent", "unknown"))
        _require(type(fact["value"]) in (str, int, bool, type(None)))
        _require(fact["state"] == "known" or fact["value"] is None)
        _require(type(fact["evidence_source"]) is str)
        _strings(fact["limitations"])
        _require(fact["state"] != "unknown" or fact["limitations"])
        key = (fact["resource_id"], fact["property"])
        _require(key not in seen)
        seen.add(key)
    return result


def _same(left, right):
    return canonical_json(left) == canonical_json(right)


def _key(resource, host_id, aliases):
    try:
        return tuple(physical_key(resource, host_id, aliases))
    except (DeclarationError, KeyError, TypeError):
        return None


def build_report(declaration, current, observations, *, host_id, engine_aliases=None,
                 selected_components=None, now=None, max_age_seconds=60):
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
        current = _management(current)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise PlanningError("invalid_management_projection") from None
    try:
        observations = _observation(observations)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise PlanningError("invalid_observation_projection") from None
    try:
        return _build(validated, model, current, observations, host_id, aliases,
                      selected_components, now, max_age_seconds)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise PlanningError("invalid_report_inputs") from None


def _build(declaration, model, current, observations, host_id, aliases, selection, now, max_age):
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
    accepted = {tuple(item["physical_key"]): item for item in current["resources"]} if current else {}
    keys = {name: _key(resource, host_id, aliases) for name, resource in resources.items()}
    bound = [key for key in keys.values() if key is not None]
    _require(len(set(bound)) == len(bound))
    requirements = {name: [] for name in resources}
    for component in components.values():
        for requirement in component["requirements"]:
            requirements[requirement["resource"]].append({"consumer": component["id"],
                "property": requirement["property"], "value": requirement["value"]})

    def fact_for(resource, prop):
        if observation_state != "available":
            return None, "observations_" + observation_state
        if resource["id"] not in coverage:
            return None, "resource_not_inspected"
        fact = facts.get((resource["id"], prop))
        if fact is None:
            return None, "property_not_inspected"
        if (fact["kind"] != resource["kind"] or keys[resource["id"]] is None
                or _key(fact, host_id, aliases) != keys[resource["id"]]):
            return None, "observation_identity_mismatch"
        source = {"package": "pacman_installed_inventory",
                  "service": "systemd_unit_properties"}.get(resource["kind"])
        if source and fact["evidence_source"] != source:
            return fact, "observation_source_unsupported"
        if fact["state"] != "known":
            return fact, "observation_" + fact["state"]
        return fact, None

    def compare(resource, prop, expected):
        fact, reason = fact_for(resource, prop)
        source = (fact["evidence_source"] if fact and fact["evidence_source"] in _SOURCES
                  else "provided_observation")
        if reason:
            return "unknown", [reason], source
        if resource["kind"] == "package" and prop == "present" and fact["value"] is False:
            return "unknown", ["package_request_resolution_unknown"], source
        if resource["kind"] == "package" and prop in ("version", "install_reason"):
            present, present_reason = fact_for(resource, "present")
            if present_reason or present["value"] is not True:
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
        constraints = requirements[name] + (record["requirements"] if managed else [])
        for requirement in constraints:
            expected.setdefault(requirement["property"], []).append(requirement["value"])
        accepted_manage = set(record["definition"]["manage"]) if managed else set()
        accepted_consumers = set(record["definition"]["consumers"]) if managed else set()
        consumers = accepted_consumers | set(resource["consumers"])
        if managed and accepted_consumers != set(resource["consumers"]):
            reasons.add("consumer_change_requires_recording")
        properties = []
        for prop, values in sorted(expected.items()):
            authority = prop in accepted_manage and prop in resource["manage"]
            if len({canonical_json(value) for value in values}) > 1:
                state, limits, source = "conflict", ["consumer_requirement_conflict"], "provided_observation"
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
        accepted_checks = set(record["definition"]["checks"]) if managed else set()
        check_ids = set(resource["checks"]) | accepted_checks
        if accepted_checks:
            # The current store projection retains check IDs but not their
            # original predicates. Same-ID replacement cannot silently weaken
            # the accepted check; current predicates and this gap coexist.
            reasons.add("accepted_check_definition_unavailable")
        checks = []
        for identity in sorted(check_ids):
            check = check_definitions.get(identity)
            if check is None or check["resource"] != name:
                checks.append({"id": identity, "result": "unknown", "reason": "accepted_check_unavailable"})
            elif check["kind"] not in ("package", "service"):
                checks.append({"id": identity, "result": "unknown", "reason": "check_not_implemented"})
            else:
                states = [compare(resource, "install_reason" if prop == "reason" else prop, value)[0]
                          for prop, value in check["expected"].items()]
                result = ("failed" if "difference" in states else
                          "unknown" if any(state != "agreement" for state in states) else "passed")
                checks.append({"id": identity, "result": result, "reason": "property_predicates_only"})
            if checks[-1]["result"] != "passed":
                reasons.add("required_check_unverified")
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
        unresolved = any(key is None for key in keys.values())
        selected_keys = {keys[name] for name in included}
        for record in current["resources"]:
            if tuple(record["physical_key"]) in bound:
                if tuple(record["physical_key"]) not in selected_keys:
                    unselected.append({"stable_id": record["stable_id"],
                                       "logical_id": record["logical_id"],
                                       "management": record["management"],
                                       "pending_disposition": record["pending_disposition"]})
                    if record["pending_disposition"] and record["management"] == "accepted":
                        blocks.add("recorded_disposition_pending")
                continue
            uncertain = unresolved and "engine" in record["definition"]["identity"]
            active = record["management"] == "accepted"
            decision = ("identity_unresolved" if uncertain else "retire_or_relinquish") if active else None
            retained.append({"stable_id": record["stable_id"], "logical_id": record["logical_id"],
                             "management": record["management"], "required_decision": decision})
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
              "executable": False, "blockers": sorted(blocks),
              "limitations": ["time_bounded_observation_not_atomic_host_snapshot",
                              "no_attempt_history_or_input_replay_verification",
                              "no_native_resolution_or_executable_effects",
                              "projections_require_trusted_host_boundary"]}
    raw = canonical_json(report)
    return ComparisonReport(raw, hashlib.sha256(raw).hexdigest())
