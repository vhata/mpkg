"""Read-only, byte-bounded projections of authenticated historical attempts.

This module is a trusted journal consumer, never an execution capability. Raw
context stays private; public fields are constructed explicitly, not filtered.
"""
from datetime import datetime, timezone
import re
import uuid

from . import attempt_journal as journal
from .store import HostStore, _decode, _json

MAX_PAGE_BYTES = 1024 * 1024
MAX_PAGE_ITEMS = 100
DEFAULT_PAGE_ITEMS = 20
_STATES = frozenset({"planned", "unknown", "failed", "unverified", "observed-complete"})
_KINDS = frozenset({"package", "service", "file", "directory", "symlink", "sonarr_xml",
                    "compose", "volume", "network", "user", "group"})
_PROPERTIES = frozenset({"present", "source", "version", "running", "profiles", "services", "images",
    "enabled", "home", "shell", "primary_group", "groups", "members", "owner", "group", "mode",
    "content", "content_input", "target", "port", "reason", "expected_status", "operation", "as_user",
    "consumer", "url"})
# Even nonsecret declaration strings can contain private paths. Only bounded
# version/name tokens and boolean/integer predicates are rendered as values.
_PUBLIC_STRINGS = frozenset({"version", "reason", "operation", "as_user", "consumer"})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+~\-]{0,127}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")


class AttemptReportError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition):
    if not condition:
        raise ValueError("invalid_attempt_response")


def _integer(value):
    _require(type(value) is int and 0 <= value < 2**63 - 1)


def _uuid(value):
    _require(type(value) is str and str(uuid.UUID(value)) == value)


def _identifier(value):
    _require(type(value) is str and _ID.fullmatch(value) is not None)


def _hash(value):
    _require(type(value) is str and _HASH.fullmatch(value) is not None)


def _time(value):
    _require(type(value) is str)
    stamp = datetime.fromisoformat(value)
    _require(stamp.tzinfo == timezone.utc and stamp.isoformat(timespec="microseconds") == value)


def _validate(value, schema):
    if type(schema) is dict:
        _require(type(value) is dict and value.keys() == schema.keys())
        for key, spec in schema.items():
            _validate(value[key], spec)
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


def _boolean(value):
    _require(type(value) is bool)


def _public_version(value):
    return (type(value) is dict and value.get("policy") in {"any", "exact"}
            and set(value) == ({"policy"} if value["policy"] == "any" else
                              {"policy", "value"} | ({"recipe_revision"} if "recipe_revision" in value else set()))
            and all(type(item) is str and _TOKEN.fullmatch(item) for item in value.values()))


def _property(name, value):
    public = (type(value) is bool or type(value) is int and 0 <= value < 2**63 - 1
              or name in _PUBLIC_STRINGS and type(value) is str and _TOKEN.fullmatch(value)
              or name == "version" and _public_version(value))
    return {"property": name, "redacted": not bool(public), "value": value if public else None}


def _property_schema(value):
    _require(type(value) is dict and set(value) == {"property", "redacted", "value"})
    _validate(value["property"], _PROPERTIES)
    _boolean(value["redacted"])
    if value["redacted"]:
        _require(value["value"] is None)
    else:
        raw = value["value"]
        _require(type(raw) is bool or type(raw) is int and 0 <= raw < 2**63 - 1
                 or value["property"] in _PUBLIC_STRINGS and type(raw) is str and _TOKEN.fullmatch(raw)
                 or value["property"] == "version" and _public_version(raw))


def _check(check, role, revision, snapshot):
    predicates = check.get("expected", {}) if check["kind"] in {"package", "service"} else {
        name: check[name] for name in ({"url", "expected_status"} if check["kind"] == "endpoint"
                                       else {"as_user", "operation", "consumer"})}
    return {"id": check["id"], "kind": check["kind"], "resource_id": check["resource"],
            "role": role, "revision": revision, "snapshot_id": snapshot,
            "timeout_seconds": check["timeout_seconds"],
            "predicates": [_property(name, value) for name, value in sorted(predicates.items())],
            "result": "not_individually_recorded"}


def _target(record):
    definition = record["definition"]
    return {"stable_id": record["stable_id"], "resource_id": record["logical_id"],
            "kind": definition["kind"], "adoption_revision": record["adoption_revision"],
            "snapshot_id": record["snapshot_id"], "managed_properties": definition["manage"],
            "desired": [_property(name, value) for name, value in sorted(definition["desired"].items())],
            "consumers": definition["consumers"],
            "requirements": [{"consumer_id": item["consumer"],
                              "predicate": _property(item["property"], item["value"])}
                             for item in record["requirements"]],
            "required_checks": [_check(check, "accepted", record["adoption_revision"], record["snapshot_id"])
                                for check in record["checks"]]}


def _decision_target(context, resource_id):
    model = next(item["declaration"] for item in context["snapshots"]
                 if item["revision"] == context["revision"] and item["snapshot_id"] == context["snapshot_id"])
    resource = next((item for item in model["resources"] if item["id"] == resource_id), None)
    return {"resource_id": resource_id, "declared": resource is not None,
        "kind": None if resource is None else resource["kind"],
        "managed_properties": [] if resource is None else resource["manage"],
        "desired": [] if resource is None else [_property(name, value)
            for name, value in sorted(resource["desired"].items())],
        "consumers": [] if resource is None else resource["consumers"],
        "requirements": [{"consumer_id": component["id"],
                          "predicate": _property(item["property"], item["value"])}
                         for component in model["components"] for item in component["requirements"]
                         if item["resource"] == resource_id]}


def _entry(store, identity, revision):
    # _read verifies all authenticated rows before this private seam is used.
    # Journal ownership explicitly permits this seam; never use raw event
    # outcomes, which can contain private recovery evidence in later schemas.
    rows = journal._rows(store, identity)
    context = _decode(rows[0][6])["target"]
    summary = journal._projection(*rows, revision).as_dict()
    actions = []
    for action, resource in zip(summary["actions"], context["resources"]):
        actions.append({name: action[name] for name in (
            "action_id", "ordinal", "state", "attempted", "command_outcome", "observation_outcome")} | {
                "work": "attempted" if action["attempted"] else "not_attempted", "target": _target(resource),
                "decision_target": _decision_target(context, resource["logical_id"])})
    inputs, counters = [], {}
    for item in context["declared_inputs"]:
        key = (item["revision"], item["snapshot_id"], item["entry"]["input_id"])
        index = counters.get(key, 0)
        counters[key] = index + 1
        inputs.append({"revision": item["revision"], "snapshot_id": item["snapshot_id"],
            "input_id": item["entry"]["input_id"], "file_index": index,
            "classification": item["entry"]["classification"], "state": item["state"],
            "origin_revision": item["origin_revision"]})
    result = {name: summary[name] for name in ("attempt_id", "plan_id", "host_id", "revision", "snapshot_id",
        "predecessor", "created_at", "ordinal", "authority", "executable", "finished", "state",
        "decision_state", "sequence")}
    result.update(supervision=summary["supervision"] | {
        "recovery": summary["supervision"].get("recovery", "not_recorded")}, actions=actions, inputs=inputs,
        decision_checks=[_check(check, "decision", context["revision"], context["snapshot_id"])
                         for check in context["current_checks"]],
        event_details={"operation": "attempt", "attempt_id": identity, "after_event": 0})
    return result, summary["events"]


def _page_options(limit, after_id):
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE_ITEMS:
        raise AttemptReportError("invalid_attempt_page")
    if after_id is not None:
        try:
            _uuid(after_id)
        except (ValueError, TypeError, AttributeError):
            raise AttemptReportError("invalid_attempt_page") from None


def _size(value):
    return len(_json(value))


def attempt_page(store, *, limit=DEFAULT_PAGE_ITEMS, after_id=None):
    """One consistent read; explicit cursor and byte bound, no application lock.

    Pagination is an advancing append feed, not a frozen snapshot across calls.
    Revisit an attempt's detail endpoint to see events appended to older items.
    """
    _page_options(limit, after_id)
    if type(store) is not HostStore:
        raise AttemptReportError("invalid_attempt_page")
    with store._read():
        if store._schema_version < 4:
            raise AttemptReportError("attempt_history_requires_migration")
        after = 0
        if after_id is not None:
            row = store._db.execute("SELECT ordinal FROM attempts WHERE id=?", (after_id,)).fetchone()
            if row is None:
                raise AttemptReportError("attempt_cursor_missing")
            after = row[0]
        revision = store._revision()
        maximum = store._db.execute("SELECT coalesce(max(ordinal),0) FROM attempts").fetchone()[0]
        rows = store._db.execute("SELECT id FROM attempts WHERE ordinal>? ORDER BY ordinal LIMIT ?",
                                 (after, limit + 1)).fetchall()
        result = {"host_id": store.host_id, "revision": revision, "after_id": after_id, "limit": limit,
                  "attempts": [], "next_after": after_id, "has_more": False,
                  "observed_through_ordinal": maximum, "consistency": "advancing_history", "executable": False}
        for (identity,) in rows[:limit]:
            entry, _ = _entry(store, identity, revision)
            candidate = result | {"attempts": result["attempts"] + [entry], "next_after": identity}
            if _size(candidate) > MAX_PAGE_BYTES:
                if not result["attempts"]:
                    raise AttemptReportError("attempt_history_size_limit")
                break
            result = candidate
        result["has_more"] = len(rows) > len(result["attempts"])
        validate_attempt_page(result)
        return result


def attempt_detail(store, attempt_id, *, after_event=0, event_limit=DEFAULT_PAGE_ITEMS):
    """Read an exact original target and one complete, resumable event page."""
    _page_options(event_limit, attempt_id)
    if type(store) is not HostStore or attempt_id is None or type(after_event) is not int or not 0 <= after_event < 2**63 - 1:
        raise AttemptReportError("invalid_attempt_page")
    with store._read():
        if store._schema_version < 4:
            raise AttemptReportError("attempt_history_requires_migration")
        if store._db.execute("SELECT 1 FROM attempts WHERE id=?", (attempt_id,)).fetchone() is None:
            raise AttemptReportError("attempt_missing")
        revision = store._revision()
        entry, events = _entry(store, attempt_id, revision)
        if after_event > entry["sequence"]:
            raise AttemptReportError("attempt_event_cursor_missing")
        result = {"host_id": store.host_id, "revision": revision, "attempt": entry,
                  "after_event": after_event, "event_limit": event_limit, "events": [],
                  "next_event": after_event, "has_more": False,
                  "observed_through_sequence": entry["sequence"], "consistency": "advancing_history",
                  "executable": False}
        if _size(result) > MAX_PAGE_BYTES:
            raise AttemptReportError("attempt_history_size_limit")
        for event in events[after_event:after_event + event_limit]:
            candidate = result | {"events": result["events"] + [event], "next_event": event["sequence"]}
            if _size(candidate) > MAX_PAGE_BYTES:
                if not result["events"]:
                    raise AttemptReportError("attempt_history_size_limit")
                break
            result = candidate
        result["has_more"] = result["next_event"] < entry["sequence"]
        validate_attempt_detail(result)
        return result


def _check_schema(value):
    _validate(value, _CHECK)
    _require(1 <= value["timeout_seconds"] <= 60 and value["revision"] > 0)
    names = [predicate["property"] for predicate in value["predicates"]]
    _require(len(set(names)) == len(names))
    allowed = {"package": {"present", "version", "reason"}, "service": {"running", "enabled"},
               "endpoint": {"url", "expected_status"}, "access": {"as_user", "operation", "consumer"}}
    _require(bool(names) and set(names) <= allowed[value["kind"]])
    if value["kind"] in {"endpoint", "access"}:
        _require(set(names) == allowed[value["kind"]])
    for item in value["predicates"]:
        name, raw = item["property"], item["value"]
        if name == "url":
            _require(item["redacted"])
        elif not item["redacted"]:
            if name in {"present", "running", "enabled"}:
                _boolean(raw)
            elif name == "expected_status":
                _require(type(raw) is int and 100 <= raw <= 599)
            elif name == "reason":
                _require(raw in {"explicit", "dependency"})
            elif name == "operation":
                _require(raw in {"read", "list"})
            else:
                _require(type(raw) is str)


_CHECK = {"id": _identifier, "kind": frozenset({"package", "service", "endpoint", "access"}),
          "resource_id": _identifier, "role": frozenset({"accepted", "decision"}), "revision": _integer,
          "snapshot_id": _hash, "timeout_seconds": _integer, "predicates": _list(_property_schema, 4),
          "result": "not_individually_recorded"}
_TARGET = {"stable_id": _uuid, "resource_id": _identifier, "kind": _KINDS,
           "adoption_revision": _integer, "snapshot_id": _hash, "managed_properties": _list(_PROPERTIES, 32),
           "desired": _list(_property_schema, 32), "consumers": _list(_identifier),
           "requirements": _list({"consumer_id": _identifier, "predicate": _property_schema}),
           "required_checks": _list(_check_schema)}
_DECISION_TARGET = {"resource_id": _identifier, "declared": _boolean, "kind": _nullable(_KINDS),
    "managed_properties": _list(_PROPERTIES, 32), "desired": _list(_property_schema, 32),
    "consumers": _list(_identifier),
    "requirements": _list({"consumer_id": _identifier, "predicate": _property_schema})}
_ENTRY = {"attempt_id": _uuid, "plan_id": _uuid, "host_id": _uuid, "revision": _integer,
    "snapshot_id": _hash, "predecessor": _nullable(_uuid), "created_at": _time, "ordinal": _integer,
    "authority": "fixture_only", "executable": False, "finished": _boolean, "state": _STATES,
    "decision_state": frozenset({"current", "superseded"}), "sequence": _integer,
    "supervision": {"reserved": _boolean, "dispatch": frozenset({"not_recorded", "accepted", "rejected", "unknown"}),
        "worker": frozenset({"not_started", "owned", "verified_complete", "unresolved"}), "released": _boolean,
        "recovery": frozenset({"not_recorded", "blocked", "quiescent"})},
    "actions": _list({"action_id": _uuid, "ordinal": _integer, "state": _STATES, "attempted": _boolean,
        "command_outcome": frozenset({"not_recorded", "succeeded", "failed", "timeout", "unknown"}),
        "observation_outcome": frozenset({"not_recorded", "satisfied", "failed", "unavailable"}),
        "work": frozenset({"attempted", "not_attempted"}), "target": _TARGET, "decision_target": _DECISION_TARGET}, journal.MAX_ACTIONS),
    "inputs": _list({"revision": _integer, "snapshot_id": _hash, "input_id": _identifier,
        "file_index": _integer, "classification": frozenset({"nonsecret", "protected"}),
        "state": frozenset({"bound", "unavailable"}), "origin_revision": _nullable(_integer)}),
    "decision_checks": _list(_check_schema),
    "event_details": {"operation": "attempt", "attempt_id": _uuid, "after_event": 0}}
_EVENT_OUTCOMES = {"action_started": {"started"}, "command_completed": {"succeeded", "failed", "timeout", "unknown"},
    "observation_completed": {"satisfied", "failed", "unavailable"},
    "attempt_finished": {"observed-complete", "failed", "unverified"}, "launch_reserved": {"reserved"},
    "launch_result": {"accepted", "rejected", "unknown"}, "worker_started": {"owned"},
    "worker_completed": {"verified_complete", "unresolved"}, "recovery_recorded": {"blocked", "quiescent"}}


def _event(value):
    _validate(value, {"event_id": _uuid, "sequence": _integer, "action_id": _nullable(_uuid),
                     "kind": frozenset(_EVENT_OUTCOMES), "created_at": _time,
                     "outcome": frozenset().union(*_EVENT_OUTCOMES.values())})
    _require(value["outcome"] in _EVENT_OUTCOMES[value["kind"]])


def _entry_context(entry, host, revision):
    _require(entry["host_id"] == host and 0 < entry["revision"] <= revision and entry["ordinal"] > 0)
    _require(entry["event_details"]["attempt_id"] == entry["attempt_id"])
    _require(entry["decision_state"] == ("current" if entry["revision"] == revision else "superseded"))
    _require(bool(entry["actions"]))
    _require(len({item["action_id"] for item in entry["actions"]}) == len(entry["actions"]))
    expected_state = journal._overall([{"started": item["attempted"],
        "command_outcome": item["command_outcome"], "observation_outcome": item["observation_outcome"]}
        for item in entry["actions"]])
    _require(entry["state"] == expected_state)
    _require(not entry["finished"] or entry["state"] in {"observed-complete", "failed", "unverified"})
    _require(entry["predecessor"] != entry["attempt_id"])
    for ordinal, action in enumerate(entry["actions"]):
        _require(action["ordinal"] == ordinal and action["attempted"] == (action["work"] == "attempted"))
        _require(action["state"] == journal._action_state({"started": action["attempted"],
            "command_outcome": action["command_outcome"], "observation_outcome": action["observation_outcome"]}))
        _require(action["attempted"] or (action["command_outcome"] == "not_recorded"
                                         and action["observation_outcome"] == "not_recorded"))
        target = action["target"]
        decision = action["decision_target"]
        _require(decision["resource_id"] == target["resource_id"])
        _require(decision["declared"] == (decision["kind"] is not None))
        _require(decision["declared"] or not any(decision[name] for name in
            ("managed_properties", "desired", "consumers", "requirements")))
        _require(0 < target["adoption_revision"] <= entry["revision"])
        for check in target["required_checks"]:
            _require(check["role"] == "accepted" and check["revision"] == target["adoption_revision"]
                     and check["snapshot_id"] == target["snapshot_id"] and check["resource_id"] == target["resource_id"])
    for check in entry["decision_checks"]:
        _require(check["role"] == "decision" and check["revision"] == entry["revision"]
                 and check["snapshot_id"] == entry["snapshot_id"])


def validate_attempt_page(value, request=None):
    _validate(value, {"host_id": _uuid, "revision": _integer, "after_id": _nullable(_uuid), "limit": _integer,
        "attempts": _list(_ENTRY, MAX_PAGE_ITEMS), "next_after": _nullable(_uuid), "has_more": _boolean,
        "observed_through_ordinal": _integer, "consistency": "advancing_history", "executable": False})
    _require(1 <= value["limit"] <= MAX_PAGE_ITEMS and len(value["attempts"]) <= value["limit"])
    _require(_size(value) <= MAX_PAGE_BYTES)
    if request is not None:
        _require(value["limit"] == request.page_limit and value["after_id"] == request.after_id)
    identities = [entry["attempt_id"] for entry in value["attempts"]]
    _require(len(set(identities)) == len(identities) and value["after_id"] not in identities)
    previous = 0
    for entry in value["attempts"]:
        _entry_context(entry, value["host_id"], value["revision"])
        _require(previous < entry["ordinal"] <= value["observed_through_ordinal"])
        _require(not previous or entry["ordinal"] == previous + 1)
        _require(value["after_id"] is not None or previous or entry["ordinal"] == 1)
        previous = entry["ordinal"]
    _require(value["next_after"] == (value["attempts"][-1]["attempt_id"] if value["attempts"] else value["after_id"]))
    _require(not value["has_more"] or bool(value["attempts"]))
    if value["attempts"]:
        _require(value["has_more"] == (value["attempts"][-1]["ordinal"] < value["observed_through_ordinal"]))
    elif value["after_id"] is None:
        _require(value["observed_through_ordinal"] == 0)


def validate_attempt_detail(value, request=None):
    _validate(value, {"host_id": _uuid, "revision": _integer, "attempt": _ENTRY, "after_event": _integer,
        "event_limit": _integer, "events": _list(_event, MAX_PAGE_ITEMS), "next_event": _integer,
        "has_more": _boolean, "observed_through_sequence": _integer, "consistency": "advancing_history",
        "executable": False})
    _require(1 <= value["event_limit"] <= MAX_PAGE_ITEMS and len(value["events"]) <= value["event_limit"]
             and _size(value) <= MAX_PAGE_BYTES)
    _entry_context(value["attempt"], value["host_id"], value["revision"])
    _require(value["observed_through_sequence"] == value["attempt"]["sequence"]
             and value["after_event"] <= value["observed_through_sequence"])
    if request is not None:
        _require(value["attempt"]["attempt_id"] == request.attempt_id and value["after_event"] == request.after_event
                 and value["event_limit"] == request.page_limit)
    actions = {action["action_id"] for action in value["attempt"]["actions"]}
    _require(len({event["event_id"] for event in value["events"]}) == len(value["events"]))
    for sequence, event in enumerate(value["events"], value["after_event"] + 1):
        _require(event["sequence"] == sequence and event["sequence"] <= value["observed_through_sequence"])
        _require(event["action_id"] in actions if event["kind"] in {
            "action_started", "command_completed", "observation_completed"} else event["action_id"] is None)
    _require(value["next_event"] == value["after_event"] + len(value["events"]))
    _require(value["has_more"] == (value["next_event"] < value["observed_through_sequence"]))
    _require(not value["has_more"] or bool(value["events"]))
