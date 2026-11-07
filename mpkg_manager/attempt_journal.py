"""Authenticated attempt history, with no production creation or execution API.

The private fixture writer exercises journal boundaries using inert effects.
Its records carry fixture_only authority forever. Neither a PlanReference nor
an Attempt is an executable plan, a launch reservation or recovery evidence.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
import uuid

from .store import (HostStore, StoreError, _decode, _declared_nonsecret,
                    _declared_protected, _framed_mac, _json)


MAX_ACTIONS = 128
MAX_EVENTS = 4 * MAX_ACTIONS + 1
MAX_CONTEXT_BYTES = 4 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_DOMAIN = b"MPKGATTEMPT\x00\x01"


class JournalError(RuntimeError):
    """Fixed codes only; never child output, paths, inputs or raw exceptions."""
    def __init__(self, code="invalid_attempt_request"):
        self.code = code
        super().__init__(code)


def _require(condition, code="invalid_attempt_request"):
    if not condition:
        raise JournalError(code)


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _revision(value):
    return type(value) is int and 1 <= value < 2**63 - 1


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _time(value):
    _require(type(value) is str)
    parsed = datetime.fromisoformat(value)
    _require(parsed.tzinfo == timezone.utc and parsed.isoformat(timespec="microseconds") == value)
    return parsed


@dataclass(frozen=True)
class PlanReference:
    """Internal versioned binding contract; this version conveys no authority."""
    plan_id: str
    host_id: str
    decision_revision: int
    snapshot_id: str
    target_digest: str = field(repr=False)
    contract_version: int = 1
    authority: str = "fixture_only"

    def __post_init__(self):
        _require(_uuid(self.plan_id) and _uuid(self.host_id) and _revision(self.decision_revision))
        _require(type(self.contract_version) is int and self.contract_version == 1
                 and self.authority == "fixture_only")
        _require(all(type(value) is str and _HASH.fullmatch(value)
                     for value in (self.snapshot_id, self.target_digest)))


@dataclass(frozen=True)
class WorkerIdentity:
    """Identity supplied by a trusted fixture, never read from a host request."""
    operator_uid: int
    worker_uid: int
    boot_id: str
    worker_id: str

    def __post_init__(self):
        _require(all(type(value) is int and 0 <= value < 2**32 - 1
                     for value in (self.operator_uid, self.worker_uid)))
        _require(_uuid(self.boot_id) and _uuid(self.worker_id))


@dataclass(frozen=True)
class Attempt:
    """Detached redacted projection; editing the returned dict changes nothing."""
    _summary: bytes = field(repr=False)

    def as_dict(self):
        return json.loads(self._summary)


def _seal(store, kind, values, previous=None):
    key = store._db.execute("SELECT private_key FROM host").fetchone()[0]
    return _framed_mac(key, _DOMAIN, {"host_id": store.host_id, "kind": kind,
        "previous": None if previous is None else previous.hex()}, _json(values))


def _target(store, revision, snapshot_id, selected):
    """Re-derive original context from history, independent of current intent."""
    _require(_revision(revision) and type(snapshot_id) is str and _HASH.fullmatch(snapshot_id))
    _require(type(selected) is list and 1 <= len(selected) <= MAX_ACTIONS
             and all(_uuid(item) for item in selected) and len(set(selected)) == len(selected))
    row = store._db.execute("SELECT snapshot_id FROM decisions WHERE revision=?", (revision,)).fetchone()
    _require(row is not None and row[0] == snapshot_id, "attempt_target_unavailable")
    declaration = store._load_snapshot(snapshot_id)
    records = []
    inputs = []
    scopes = {(revision, snapshot_id)}
    for stable_id in selected:
        row = store._db.execute("""SELECT revision,logical_id,physical_key,definition,requirements,active
            FROM resources WHERE stable_id=? AND revision<=? ORDER BY revision DESC LIMIT 1""",
                               (stable_id, revision)).fetchone()
        _require(row is not None and row[5] == 1, "attempt_target_unavailable")
        adopted, logical, physical, definition, requirements, _ = row
        accepted = store._db.execute("SELECT kind,snapshot_id FROM decisions WHERE revision=?",
                                     (adopted,)).fetchone()
        _require(accepted[0] == "adopt", "attempt_target_unavailable")
        original = store._load_snapshot(accepted[1])
        definition = _decode(definition)
        checks = [check for check in original.model["checks"] if check["id"] in definition["checks"]]
        records.append({"stable_id": stable_id, "adoption_revision": adopted,
            "snapshot_id": accepted[1], "logical_id": logical, "physical_key": _decode(physical),
            "definition": definition, "requirements": _decode(requirements), "checks": checks})
        scopes.add((adopted, accepted[1]))
    # Bind complete declared snapshots and original capture references, including
    # missing legacy baselines. Private bytes remain in protected_inputs only.
    snapshots, declared_inputs = [], []
    for source_revision, source_snapshot in sorted(scopes):
        source = store._load_snapshot(source_snapshot)
        snapshots.append({"revision": source_revision, "snapshot_id": source_snapshot,
                          "declaration": source.model})
        for name, capture, purpose, identity, token in store._db.execute("""SELECT d.name,p.id,
                p.purpose,p.source_identity,p.token FROM decision_inputs d JOIN protected_inputs p
                ON p.id=d.protected_id WHERE d.revision=? ORDER BY d.name""", (source_revision,)):
            inputs.append({"revision": source_revision, "name": name, "capture_id": capture,
                           "purpose": purpose, "source_identity": _decode(identity), "token": token.hex()})
        for entry in _declared_protected(source) + _declared_nonsecret(source):
            if entry["classification"] == "protected":
                capture_id = entry["reference"]
                capture = store._bound_capture(capture_id, source_snapshot, source_revision)
            else:
                capture = store._nonsecret_capture(source_revision, source_snapshot,
                                                    entry["input_id"], entry["path"])
                capture_id = None if capture is None else store._db.execute(
                    "SELECT protected_id FROM decision_inputs WHERE revision=? AND name=?",
                    (capture[4], capture[5])).fetchone()[0]
            declared_inputs.append({"revision": source_revision, "snapshot_id": source_snapshot,
                "entry": entry, "state": "unavailable" if capture is None else "bound",
                "origin_revision": None if capture is None else capture[4],
                "capture_id": None if capture is None else capture_id})
            if capture is not None:
                binding = {"revision": capture[4], "name": capture[5], "capture_id": capture_id,
                           "purpose": capture[2], "source_identity": _decode(capture[1]),
                           "token": capture[3].hex()}
                if binding not in inputs:
                    inputs.append(binding)
    target = {"version": 1, "host_id": store.host_id, "revision": revision,
              "snapshot_id": snapshot_id, "selected": selected, "resources": records,
              "snapshots": snapshots, "inputs": inputs, "declared_inputs": declared_inputs,
              "current_checks": declaration.model["checks"]}
    _require(len(_json(target)) <= MAX_CONTEXT_BYTES, "attempt_scope_limit")
    return target


def _fixture_plan(store, *, expected_revision, stable_resource_ids):
    """Create a non-executable internal plan reference for inert test assembly."""
    _require(type(store) is HostStore and _revision(expected_revision))
    selected = list(stable_resource_ids) if type(stable_resource_ids) in (tuple, list) else None
    with store._read():
        _require(store._schema_version >= 4, "attempt_migration_required")
        _require(store._revision() == expected_revision, "attempt_revision_conflict")
        row = store._db.execute("SELECT snapshot_id FROM decisions WHERE revision=?",
                                (expected_revision,)).fetchone()
        _require(row is not None, "attempt_target_unavailable")
        target = _target(store, expected_revision, row[0], selected)
        return PlanReference(str(uuid.uuid4()), store.host_id, expected_revision, row[0],
                             hashlib.sha256(_json(target)).hexdigest())


def _action_state(action):
    if not action["started"]:
        return "planned"
    if action["command_outcome"] in ("not_recorded", "unknown"):
        return "unknown"
    if action["command_outcome"] in ("failed", "timeout") or action["observation_outcome"] == "failed":
        return "failed"
    if action["observation_outcome"] == "satisfied":
        return "observed-complete"
    return "unverified"


def _overall(actions):
    states = [_action_state(action) for action in actions]
    if "unknown" in states:
        return "unknown"
    if "failed" in states:
        return "failed"
    if "unverified" in states:
        return "unverified"
    if all(state == "observed-complete" for state in states):
        return "observed-complete"
    return "planned" if all(state == "planned" for state in states) else "unverified"


def _replay(actions, events):
    """Verify the state machine separately from row authentication."""
    state = [{"action_id": row[1], "ordinal": row[2], "started": False,
              "command_outcome": "not_recorded", "observation_outcome": "not_recorded"}
             for row in actions]
    by_id = {action["action_id"]: action for action in state}
    finished, previous_time, seen = False, None, set()
    for expected, row in enumerate(events, 1):
        _, sequence, event_id, action_id, kind, created_at, outcome, _ = row
        _require(type(sequence) is int and sequence == expected and _uuid(event_id)
                 and event_id not in seen and not finished, "attempt_transition_invalid")
        seen.add(event_id)
        timestamp = _time(created_at)
        _require(previous_time is None or timestamp >= previous_time, "attempt_transition_invalid")
        previous_time = timestamp
        if kind == "attempt_finished":
            _require(action_id is None and outcome == _overall(state)
                     and outcome in ("observed-complete", "failed", "unverified")
                     and not any(action["started"] and action["command_outcome"] == "not_recorded"
                                 for action in state), "attempt_transition_invalid")
            finished = True
            continue
        _require(action_id in by_id, "attempt_transition_invalid")
        action = by_id[action_id]
        if kind == "action_started":
            _require(outcome == "started" and not action["started"]
                     and all(_action_state(item) == "observed-complete"
                             for item in state[:action["ordinal"]]), "attempt_transition_invalid")
            action["started"] = True
        elif kind == "command_completed":
            _require(action["started"] and action["command_outcome"] == "not_recorded"
                     and outcome in ("succeeded", "failed", "timeout", "unknown"), "attempt_transition_invalid")
            action["command_outcome"] = outcome
        elif kind == "observation_completed":
            _require(action["command_outcome"] != "not_recorded"
                     and action["observation_outcome"] == "not_recorded"
                     and outcome in ("satisfied", "failed", "unavailable"), "attempt_transition_invalid")
            action["observation_outcome"] = outcome
        else:
            raise JournalError("attempt_transition_invalid")
    return state, finished


def _rows(store, attempt_id):
    row = store._db.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
    _require(row is not None, "attempt_missing")
    actions = store._db.execute("SELECT * FROM attempt_actions WHERE attempt_id=? ORDER BY ordinal",
                                (attempt_id,)).fetchall()
    events = store._db.execute("SELECT * FROM attempt_events WHERE attempt_id=? ORDER BY sequence",
                               (attempt_id,)).fetchall()
    return row, actions, events


def _verified(store, row, actions, events):
    identity, plan_id, revision, snapshot, predecessor, created_at, raw, seal, ordinal = row
    _require(_uuid(identity) and _uuid(plan_id) and (predecessor is None or _uuid(predecessor)))
    _require(type(ordinal) is int and 1 <= ordinal < 2**63 - 1)
    _time(created_at)
    _require(type(raw) is bytes and len(raw) <= MAX_CONTEXT_BYTES)
    context = _decode(raw)
    _require(type(context) is dict and set(context) == {"version", "authority", "target", "worker"}
             and _json(context) == raw and type(context["version"]) is int and context["version"] == 1
             and context["authority"] == "fixture_only")
    target = context["target"]
    _require(_json(target) == _json(_target(store, revision, snapshot, target["selected"])))
    worker = context["worker"]
    _require(type(worker) is dict and set(worker) == {
        "operator_uid", "worker_uid", "boot_id", "worker_id", "unit"})
    WorkerIdentity(*(worker[name] for name in ("operator_uid", "worker_uid", "boot_id", "worker_id")))
    _require(worker["unit"] == f"mpkg-attempt-{identity}.service")
    values = [identity, plan_id, revision, snapshot, predecessor, created_at, context, ordinal]
    _require(type(seal) is bytes and hmac.compare_digest(seal, _seal(store, "attempt", values)))
    if predecessor is not None:
        previous = store._db.execute("SELECT plan_id,created_at,ordinal FROM attempts WHERE id=?", (predecessor,)).fetchone()
        _require(previous is not None and previous[0] != plan_id and previous[1] <= created_at
                 and previous[2] < ordinal)
        terminal = store._db.execute("SELECT kind,outcome,created_at FROM attempt_events WHERE attempt_id=? "
                                    "ORDER BY sequence DESC LIMIT 1", (predecessor,)).fetchone()
        _require(terminal is not None and terminal[0] == "attempt_finished"
                 and terminal[1] in ("failed", "unverified") and terminal[2] <= created_at)
    _require(len(actions) == len(target["resources"]) and len(events) <= MAX_EVENTS)
    for ordinal, action in enumerate(actions):
        attempt, action_id, number, encoded, action_seal = action
        definition = {"operation": "inert_fixture", "resource": target["resources"][ordinal]}
        _require(attempt == identity and _uuid(action_id) and type(number) is int and number == ordinal
                 and type(encoded) is bytes and encoded == _json(definition)
                 and type(action_seal) is bytes
                 and hmac.compare_digest(action_seal, _seal(store, "action",
                    [attempt, action_id, ordinal, definition], seal)))
    previous_seal = seal
    for event in events:
        _require(event[0] == identity and event[5] >= created_at and type(event[-1]) is bytes
                 and hmac.compare_digest(event[-1], _seal(store, "event", list(event[:-1]), previous_seal)))
        previous_seal = event[-1]
    return context, *_replay(actions, events)


def _verify_journal(store):
    try:
        for expected, row in enumerate(store._db.execute("SELECT * FROM attempts ORDER BY ordinal"), 1):
            _require(row[8] == expected)
            _verified(store, *_rows(store, row[0]))
    except (JournalError, ValueError, TypeError, KeyError, AttributeError,
            OverflowError, RecursionError):
        raise StoreError("store_corrupt") from None


def _projection(row, actions, events, current_revision):
    context = _decode(row[6])
    state, finished = _replay(actions, events)
    for action, record in zip(state, context["target"]["resources"]):
        action.update({"stable_resource_id": record["stable_id"], "state": _action_state(action),
                       "attempted": action["started"], "required_check_count": len(record["checks"])})
    return Attempt(_json({"attempt_id": row[0], "plan_id": row[1], "host_id": context["target"]["host_id"],
        "revision": row[2], "snapshot_id": row[3], "predecessor": row[4], "created_at": row[5],
        "ordinal": row[8],
        "authority": "fixture_only", "executable": False, "finished": finished,
        "state": _overall(state), "decision_state": "current" if row[2] == current_revision else "superseded",
        "sequence": len(events), "actions": state,
        "events": [{"event_id": event[2], "sequence": event[1], "action_id": event[3],
                    "kind": event[4], "created_at": event[5], "outcome": event[6]} for event in events]}))


def read_attempt(store, attempt_id):
    _require(type(store) is HostStore and _uuid(attempt_id))
    with store._read():
        _require(store._schema_version >= 4, "attempt_migration_required")
        rows = _rows(store, attempt_id)
        return _projection(*rows, store._revision())


def list_attempts(store, *, limit=100, after_id=None):
    """Append-ordered pagination; cursors remain valid across concurrent inserts.

    Continue after the last returned attempt UUID. The cursor resolves to its
    durable ordinal, so later UUIDs cannot sort behind an already-read page.
    This is an advancing history feed, not a frozen cross-page snapshot.
    """
    _require(type(store) is HostStore and type(limit) is int and 1 <= limit <= 100
             and (after_id is None or _uuid(after_id)))
    with store._read():
        _require(store._schema_version >= 4, "attempt_migration_required")
        after = 0
        if after_id is not None:
            cursor = store._db.execute("SELECT ordinal FROM attempts WHERE id=?", (after_id,)).fetchone()
            _require(cursor is not None, "attempt_cursor_missing")
            after = cursor[0]
        rows = store._db.execute("SELECT id FROM attempts WHERE ordinal>? ORDER BY ordinal LIMIT ?",
                                 (after, limit)).fetchall()
        return [_projection(*_rows(store, row[0]), store._revision()) for row in rows]


class _FixtureJournal:
    """Inert assembly only. No helper verb or native adapter exposes this API."""
    def __init__(self, store):
        _require(type(store) is HostStore)
        self.store = store

    def create(self, plan, worker, *, stable_resource_ids, predecessor=None):
        _require(type(plan) is PlanReference and type(worker) is WorkerIdentity)
        plan.__post_init__()
        worker.__post_init__()
        _require(plan.host_id == self.store.host_id and (predecessor is None or _uuid(predecessor)))
        selected = list(stable_resource_ids) if type(stable_resource_ids) in (tuple, list) else None
        identity, created_at = str(uuid.uuid4()), _now()
        with self.store._write(plan.decision_revision):
            target = _target(self.store, plan.decision_revision, plan.snapshot_id, selected)
            _require(hashlib.sha256(_json(target)).hexdigest() == plan.target_digest, "attempt_target_changed")
            _require(self.store._db.execute("SELECT 1 FROM attempts WHERE plan_id=?", (plan.plan_id,)).fetchone()
                     is None, "attempt_plan_already_used")
            context = {"version": 1, "authority": "fixture_only", "target": target,
                       "worker": {"operator_uid": worker.operator_uid, "worker_uid": worker.worker_uid,
                                  "boot_id": worker.boot_id, "worker_id": worker.worker_id,
                                  "unit": f"mpkg-attempt-{identity}.service"}}
            _require(len(_json(context)) <= MAX_CONTEXT_BYTES, "attempt_scope_limit")
            ordinal = self.store._db.execute("SELECT coalesce(max(ordinal),0)+1 FROM attempts").fetchone()[0]
            values = [identity, plan.plan_id, plan.decision_revision, plan.snapshot_id, predecessor, created_at,
                      context, ordinal]
            seal = _seal(self.store, "attempt", values)
            row = tuple(values[:6]) + (_json(context), seal, ordinal)
            self.store._db.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?,?)", row)
            for ordinal, record in enumerate(target["resources"]):
                action_id = str(uuid.uuid4())
                definition = {"operation": "inert_fixture", "resource": record}
                action_seal = _seal(self.store, "action", [identity, action_id, ordinal, definition], seal)
                self.store._db.execute("INSERT INTO attempt_actions VALUES(?,?,?,?,?)",
                                       (identity, action_id, ordinal, _json(definition), action_seal))
            rows = _rows(self.store, identity)
            _verified(self.store, *rows)
            result = _projection(*rows, self.store._revision())
        return result

    def append(self, attempt_id, *, expected_sequence, action_id, kind, outcome):
        _require(_uuid(attempt_id) and type(expected_sequence) is int and 0 <= expected_sequence < MAX_EVENTS
                 and (action_id is None or _uuid(action_id)) and type(kind) is str and type(outcome) is str)
        # Journal transitions preserve the original attempt revision while new
        # intent may exist. The store's short write transaction serializes both.
        with self.store._read():
            revision = self.store._revision()
        with self.store._write(revision):
            row, actions, events = _rows(self.store, attempt_id)
            _require(len(events) == expected_sequence, "attempt_sequence_conflict")
            values = [attempt_id, expected_sequence + 1, str(uuid.uuid4()), action_id, kind, _now(), outcome]
            previous = events[-1][-1] if events else row[7]
            event = tuple(values) + (_seal(self.store, "event", values, previous),)
            _replay(actions, events + [event])
            self.store._db.execute("INSERT INTO attempt_events VALUES(?,?,?,?,?,?,?,?)", event)
            rows = _rows(self.store, attempt_id)
            _verified(self.store, *rows)
            result = _projection(*rows, revision)
        return result

    def run_inert(self, attempt_id, action_id, *, expected_sequence, effect, observe):
        """Test-only ordering harness: commit start before invoking inert callbacks.

        Interruption leaves the durable start. Ordinary callback failures become
        fixed outcomes; callback text is never retained or returned.
        """
        started = self.append(attempt_id, expected_sequence=expected_sequence,
                              action_id=action_id, kind="action_started", outcome="started")
        sequence = started.as_dict()["sequence"]
        try:
            effect()
            command = "succeeded"
        except Exception:
            command = "failed"
        completed = self.append(attempt_id, expected_sequence=sequence,
                                action_id=action_id, kind="command_completed", outcome=command)
        try:
            observation = observe()
            if type(observation) is not str or observation not in ("satisfied", "failed", "unavailable"):
                observation = "unavailable"
        except Exception:
            observation = "unavailable"
        return self.append(attempt_id, expected_sequence=completed.as_dict()["sequence"],
                           action_id=action_id, kind="observation_completed", outcome=observation)
