"""Immutable accepted plans derived by registered adapters, never request graphs.

The sole current adapter is private and inert. Production construction and
attempt dispatch remain unavailable; accepted fixture records never acquire
production authority. Descriptor bytes and evidence stay in private history.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import json
from types import MappingProxyType
import uuid

from .attempt_journal import (JournalError, PlanReference, WorkerIdentity, _FixtureJournal,
    _target, _uuid, _now, _time, read_attempt)
from .effect_plans import _records
from .host_helper import _mutation_lock
from .protected_bindings import BindingError, ProtectedRecorder
from .store import HostStore, StoreError, _decode, _framed_mac, _json


MAX_ACTIONS = 128
MAX_CONTEXT_BYTES = 4 * 1024 * 1024
_DOMAIN = b"MPKGEXECUTIONPLAN\x00\x01"
_ADAPTER = "inert_resource_v1"


class ExecutionPlanError(RuntimeError):
    def __init__(self, code="invalid_execution_plan"):
        self.code = code
        super().__init__(code)


def _require(condition, code="invalid_execution_plan"):
    if not condition:
        raise ExecutionPlanError(code)


def _digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def _uid(value):
    return type(value) is int and 0 <= value < 2**32 - 1


@dataclass(frozen=True)
class ExecutionPlan:
    _summary: bytes = field(repr=False)

    def as_dict(self):
        return json.loads(self._summary)


@dataclass(frozen=True)
class AcceptedPlanBinding:
    """Detached bridge data, always reloaded and compared before use."""
    plan_id: str
    acceptance_id: str
    host_id: str
    revision: int
    snapshot_id: str
    operator_uid: int
    descriptor_digest: str = field(repr=False)
    target_digest: str = field(repr=False)
    authority: str = "fixture_only"
    contract_version: int = 1


def _history(store, revision, roots):
    """Derive closure/order/checks from original authority and current intent."""
    _require(type(roots) is list and 1 <= len(roots) <= MAX_ACTIONS
             and all(_uuid(item) for item in roots) and roots == sorted(set(roots)))
    decision = store._db.execute("SELECT snapshot_id FROM decisions WHERE revision=?", (revision,)).fetchone()
    _require(decision is not None, "plan_authority_unavailable")
    declaration = store._load_snapshot(decision[0])
    records = _records(store, revision)
    active = {row["stable_id"]: row for row in records if row["active"]}
    by_key = {_json(row["physical_key"]): identity for identity, row in active.items()}
    current = {_json(store._physical(item)): item for item in declaration.model["resources"]}
    visiting, ordered, details = set(), [], {}

    def visit(identity):
        _require(identity not in visiting, "plan_dependency_cycle")
        if identity in details:
            return
        _require(identity in active and len(details) + len(visiting) < MAX_ACTIONS,
                 "plan_authority_unavailable")
        visiting.add(identity)
        record = active[identity]
        definition = current.get(_json(record["physical_key"]))
        _require(definition is not None and definition["kind"] == "package"
                 and definition["manage"] == ["present"], "plan_effect_unsupported")
        combined = store._adoption_record(declaration.model, definition, records)
        accepted = store._db.execute("SELECT snapshot_id FROM decisions WHERE revision=?", (record["revision"],)).fetchone()[0]
        original = store._load_snapshot(accepted)
        dependencies, checks = set(), []
        for source, resource, source_id in ((declaration, definition, decision[0]),
                                             (original, record["definition"], accepted)):
            source_resources = {item["id"]: item for item in source.model["resources"]}
            for logical in resource["requires"]:
                key = _json(store._physical(source_resources[logical]))
                _require(key in by_key, "plan_authority_unavailable")
                dependencies.add(by_key[key])
            checks.append({"snapshot_id": source_id,
                "definitions": [check for check in source.model["checks"] if check["id"] in resource["checks"]]})
        for dependency in sorted(dependencies):
            visit(dependency)
        visiting.remove(identity)
        details[identity] = {"stable_id": identity, "target": combined["definition"],
            "requirements": combined["requirements"], "dependencies": sorted(dependencies), "checks": checks}
        ordered.append(identity)

    for identity in roots:
        visit(identity)
    target = _target(store, revision, decision[0], ordered)
    return {"target": target, "roots": roots, "actions": [details[item] for item in ordered]}


class _InertAdapter:
    """Private fixture implementation of prepare/revalidate/execute/observe.

    Values simulate trusted observations and artifacts; they are never public
    request fields, executable commands, or production adapter registration.
    """
    def __init__(self):
        self.facts = {}
        self.executions = []

    def seed(self, stable_id, *, token="before", satisfied=False, artifact=b"inert artifact", checks=True):
        _require(_uuid(stable_id) and type(token) is str and len(token) <= 4096
                 and type(satisfied) is bool and type(artifact) is bytes and len(artifact) <= 65536
                 and type(checks) is bool)
        self.facts[stable_id] = {"token": token, "satisfied": satisfied, "artifact": artifact, "checks": checks}

    def prepare(self, action):
        facts = self.facts.get(action["stable_id"])
        _require(facts is not None, "plan_evidence_unavailable")
        return {"before": _digest({"token": facts["token"], "satisfied": facts["satisfied"]}),
            "mode": "verify" if facts["satisfied"] else "change",
            "artifacts": [{"id": _digest({"resource": action["stable_id"], "kind": "fixture"}),
                           "digest": hashlib.sha256(facts["artifact"]).hexdigest()}]}

    def revalidate(self, action, *, completed=False):
        current = self.prepare(action)
        expected = action["prepared"]
        if completed:
            expected = expected | {"before": action["after"], "mode": "verify"}
        return current == expected

    def execute(self, action):
        _require(action["prepared"]["mode"] == "change")
        self.executions.append(action["stable_id"])
        facts = self.facts[action["stable_id"]]
        facts.update(token=action["completion_token"], satisfied=True)
        return "succeeded"

    def observe(self, action):
        facts = self.facts[action["stable_id"]]
        return {"desired": "satisfied" if facts["satisfied"] else "failed",
                "checks": ["satisfied" if facts["checks"] else "failed"
                           for role in action["checks"] for _ in role["definitions"]]}


# Registration is installed code. No JSON or constructor accepts an arbitrary
# adapter, operation descriptor, dependency edge, command, path or callback.
_FIXTURE_REGISTRY = MappingProxyType({_ADAPTER: _InertAdapter})


def _descriptor(history, prepared):
    _require(type(prepared) is list and len(prepared) == len(history["actions"]))
    actions = []
    for action, evidence in zip(history["actions"], prepared):
        _require(type(evidence) is dict and set(evidence) == {"before", "mode", "artifacts"}
                 and evidence["mode"] in ("verify", "change") and _hash(evidence["before"])
                 and type(evidence["artifacts"]) is list and len(evidence["artifacts"]) == 1)
        artifact = evidence["artifacts"][0]
        _require(type(artifact) is dict and set(artifact) == {"id", "digest"}
                 and all(_hash(value) for value in artifact.values()))
        completion = _digest({"target": action["target"], "stable_id": action["stable_id"]})
        after = evidence["before"] if evidence["mode"] == "verify" else _digest({"token": completion, "satisfied": True})
        actions.append(action | {"adapter": _ADAPTER, "version": 1,
            "effect": "inert_" + evidence["mode"], "timeout_seconds": 1,
            "interruption": "stop_and_require_recovery", "disposition": "retain",
            "prepared": evidence, "completion_token": completion, "after": after})
    return actions


def _observation_satisfied(action, observed):
    count = sum(len(role["definitions"]) for role in action["checks"])
    return (type(observed) is dict and set(observed) == {"desired", "checks"}
        and observed["desired"] == "satisfied" and type(observed["checks"]) is list
        and observed["checks"] == ["satisfied"] * count)


def _hash(value):
    return type(value) is str and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _seal(store, kind, values):
    key = store._db.execute("SELECT private_key FROM host").fetchone()[0]
    encoded = [value.hex() if type(value) is bytes else value for value in values]
    return _framed_mac(key, _DOMAIN, {"host_id": store.host_id, "kind": kind}, _json(encoded))


def _row(store, identity):
    _require(_uuid(identity))
    row = store._db.execute("SELECT * FROM execution_plans WHERE id=?", (identity,)).fetchone()
    _require(row is not None, "execution_plan_missing")
    return row


def _verified(store, row):
    identity, revision, snapshot, created, raw, seal = row
    _require(_uuid(identity) and type(revision) is int and revision > 0
             and type(raw) is bytes and len(raw) <= MAX_CONTEXT_BYTES)
    _time(created)
    context = _decode(raw)
    _require(type(context) is dict and set(context) == {"version", "authority", "host_id", "history", "policy", "actions"}
             and context["version"] == 1 and context["authority"] == "fixture_only"
             and context["host_id"] == store.host_id)
    history = _history(store, revision, context["history"]["roots"])
    _require(context["history"] == history and history["target"]["snapshot_id"] == snapshot)
    expected = _descriptor(history, [action["prepared"] for action in context["actions"]])
    _require(context["actions"] == expected and _json(context) == raw)
    policy = context["policy"]
    _require(type(policy) is dict and set(policy) == {"host_id", "engine_aliases", "allowed_input_roots", "identity"}
             and policy["host_id"] == store.host_id and policy["engine_aliases"] == store.engine_aliases)
    _require(type(seal) is bytes and hmac.compare_digest(seal, _seal(store, "plan", list(row[:-1]))))
    return context


def _acceptance(store, identity):
    _require(_uuid(identity))
    row = store._db.execute("SELECT * FROM plan_acceptances WHERE id=?", (identity,)).fetchone()
    _require(row is not None, "plan_acceptance_missing")
    return row


def _verified_acceptance(store, row):
    identity, plan_id, operator, created, seal = row
    _require(_uuid(identity) and _uuid(plan_id) and _uid(operator))
    _time(created)
    plan = _row(store, plan_id)
    _require(created >= plan[3] and type(seal) is bytes
             and hmac.compare_digest(seal, _seal(store, "acceptance", list(row[:-1]) + [plan[-1].hex()])))


def _verify_plans(store):
    try:
        for row in store._db.execute("SELECT * FROM execution_plans ORDER BY id"):
            _verified(store, row)
        for row in store._db.execute("SELECT * FROM plan_acceptances ORDER BY id"):
            _verified_acceptance(store, row)
    except (ExecutionPlanError, BindingError, JournalError, ValueError, TypeError, KeyError, AttributeError,
            OverflowError, RecursionError):
        raise StoreError("store_corrupt") from None


def _projection(store, row, context):
    accepted = store._db.execute("SELECT id FROM plan_acceptances WHERE plan_id=?", (row[0],)).fetchone()
    return ExecutionPlan(_json({"plan_id": row[0], "host_id": store.host_id,
        "revision": row[1], "snapshot_id": row[2], "created_at": row[3],
        "authority": "fixture_only", "executable": False, "accepted": accepted is not None,
        "acceptance_id": None if accepted is None else accepted[0],
        "decision_state": "current" if store._revision() == row[1] else "superseded",
        "action_count": len(context["actions"]),
        "actions": [{"stable_resource_id": item["stable_id"], "adapter": item["adapter"],
                     "effect": item["effect"], "required_check_count": sum(len(role["definitions"]) for role in item["checks"]),
                     "artifact_count": len(item["prepared"]["artifacts"])} for item in context["actions"]]}))


def read_execution_plan(store, plan_id):
    _require(type(store) is HostStore)
    with store._read():
        _require(store._schema_version >= 5, "execution_plan_migration_required")
        row = _row(store, plan_id)
        return _projection(store, row, _verified(store, row))


class ExecutionPlanner:
    """Production adapter registration is deliberately empty in this slice."""
    def __init__(self, recorder):
        _require(type(recorder) is ProtectedRecorder)
        self.recorder, self.store = recorder, recorder._store

    def prepare(self, **arguments):
        raise ExecutionPlanError("execution_adapter_unavailable")


class _FixturePlanner(ExecutionPlanner):
    def __init__(self, recorder, adapter):
        super().__init__(recorder)
        _require(type(adapter) is _FIXTURE_REGISTRY[_ADAPTER], "execution_adapter_unavailable")
        self.adapter = adapter

    def _fresh(self, context, *, completed=()):
        """Every acceptance/action boundary checks old bindings, never updates them."""
        try:
            _require(self.recorder._policy_context() == context["policy"], "execution_plan_stale")
            with self.store._read():
                history = context["history"]
                revision = history["target"]["revision"]
                _require(self.store._revision() == revision and _history(self.store, revision, history["roots"]) == history,
                         "execution_plan_stale")
                captures = []
                for item in history["target"]["declared_inputs"]:
                    _require(item["state"] == "bound", "plan_input_unavailable")
                    capture = self.store._db.execute("SELECT raw,source_identity FROM protected_inputs WHERE id=?",
                                                     (item["capture_id"],)).fetchone()
                    _require(capture is not None, "plan_input_unavailable")
                    captures.append((item["entry"], capture))
            for entry, (raw, identity) in captures:
                fresh = self.recorder._capture(entry)
                _require(self.recorder._same_capture(fresh, raw, identity), "execution_plan_stale")
            _require(self.recorder._policy_context() == context["policy"], "execution_plan_stale")
            for action in context["actions"]:
                done = action["stable_id"] in completed
                _require(self.adapter.revalidate(action, completed=done), "execution_plan_stale")
                if done:
                    _require(_observation_satisfied(action, self.adapter.observe(action)), "execution_plan_stale")
        except BindingError:
            raise ExecutionPlanError("execution_plan_stale") from None

    def prepare(self, *, expected_revision, stable_resource_ids):
        _require(type(stable_resource_ids) in (tuple, list)
                 and all(_uuid(item) for item in stable_resource_ids))
        roots = sorted(stable_resource_ids)
        with self.store._read():
            _require(self.store._schema_version >= 5, "execution_plan_migration_required")
            _require(self.store._revision() == expected_revision, "execution_plan_stale")
            history = _history(self.store, expected_revision, roots)
            actions = _descriptor(history, [self.adapter.prepare(action) for action in history["actions"]])
            context = {"version": 1, "authority": "fixture_only", "host_id": self.store.host_id,
                       "history": history, "policy": self.recorder._policy_context(), "actions": actions}
        _require(len(_json(context)) <= MAX_CONTEXT_BYTES, "execution_plan_scope_limit")
        self._fresh(context)
        row = (str(uuid.uuid4()), expected_revision, history["target"]["snapshot_id"], _now(), _json(context))
        with self.store._write(expected_revision):
            _require(self.recorder._policy_context() == context["policy"], "execution_plan_stale")
            row += (_seal(self.store, "plan", list(row)),)
            self.store._db.execute("INSERT INTO execution_plans VALUES(?,?,?,?,?,?)", row)
            _verified(self.store, row)
            result = _projection(self.store, row, context)
        return result

    def accept(self, plan_id, *, operator_uid):
        _require(_uid(operator_uid))
        with self.store._read():
            row = _row(self.store, plan_id)
            context = _verified(self.store, row)
        self._fresh(context)
        with self.store._write(row[1]):
            _require(self.recorder._policy_context() == context["policy"], "execution_plan_stale")
            _require(self.store._db.execute("SELECT 1 FROM plan_acceptances WHERE plan_id=?", (plan_id,)).fetchone() is None,
                     "plan_already_accepted")
            accepted = (str(uuid.uuid4()), plan_id, operator_uid, _now())
            accepted += (_seal(self.store, "acceptance", list(accepted) + [row[-1].hex()]),)
            self.store._db.execute("INSERT INTO plan_acceptances VALUES(?,?,?,?,?)", accepted)
        return self.binding(accepted[0])

    def binding(self, acceptance_id):
        with self.store._read():
            acceptance = _acceptance(self.store, acceptance_id)
            _verified_acceptance(self.store, acceptance)
            row = _row(self.store, acceptance[1])
            context = _verified(self.store, row)
            return AcceptedPlanBinding(row[0], acceptance[0], self.store.host_id, row[1], row[2],
                acceptance[2], _digest(context), _digest(context["history"]["target"]))

    def validate(self, binding, *, completed=()):
        _require(type(binding) is AcceptedPlanBinding
                 and all(_uuid(value) for value in (binding.plan_id, binding.acceptance_id, binding.host_id))
                 and type(binding.revision) is int and 1 <= binding.revision < 2**63 - 1
                 and _uid(binding.operator_uid) and _hash(binding.snapshot_id)
                 and _hash(binding.descriptor_digest) and _hash(binding.target_digest)
                 and type(binding.contract_version) is int and binding.contract_version == 1
                 and binding.authority == "fixture_only"
                 and binding == self.binding(binding.acceptance_id), "plan_acceptance_mismatch")
        with self.store._read():
            context = _verified(self.store, _row(self.store, binding.plan_id))
        self._fresh(context, completed=completed)
        return context

    def create_attempt(self, binding, worker, *, predecessor=None):
        """Bridge for trusted inert assembly only; no production authority."""
        context = self.validate(binding)
        _require(type(worker) is WorkerIdentity and worker.operator_uid == binding.operator_uid,
                 "plan_operator_mismatch")
        if predecessor is not None:
            _require(_uuid(predecessor))
            with self.store._read():
                # Journal validation owns eligibility of the disposition; this
                # bridge additionally refuses a spare acceptance predating it.
                terminal = self.store._db.execute("""SELECT created_at FROM attempt_events
                    WHERE attempt_id=? AND kind IN ('attempt_finished','recovery_recorded')
                    ORDER BY sequence DESC LIMIT 1""", (predecessor,)).fetchone()
                _require(terminal is not None, "plan_retry_unavailable")
                _require(_row(self.store, binding.plan_id)[3] >= terminal[0]
                         and _acceptance(self.store, binding.acceptance_id)[3] >= terminal[0],
                         "plan_predates_recovery")
        plan = PlanReference(binding.plan_id, binding.host_id, binding.revision,
                             binding.snapshot_id, binding.target_digest)
        return _FixtureJournal(self.store).create(plan, worker,
            stable_resource_ids=context["history"]["target"]["selected"], predecessor=predecessor)

    def run_inert(self, binding, worker, *, mutation_lock):
        """Owned fixture harness: durable starts and no effects outside registry."""
        with _mutation_lock(mutation_lock, self.store.owner_uid):
            attempt = self.create_attempt(binding, worker).as_dict()
            identity = attempt["attempt_id"]
            writer = _FixtureJournal(self.store)
            def append(kind, outcome, action_id=None):
                current = read_attempt(self.store, identity).as_dict()
                return writer.append(identity, expected_sequence=current["sequence"],
                    action_id=action_id, kind=kind, outcome=outcome).as_dict()
            append("launch_reserved", "reserved")
            append("worker_started", "owned")
            completed = []
            try:
                context = self.validate(binding)
                for action, recorded in zip(context["actions"], attempt["actions"]):
                    self.validate(binding, completed=completed)
                    action_id = recorded["action_id"]
                    append("action_started", "started", action_id)
                    try:
                        command = "succeeded" if action["prepared"]["mode"] == "verify" else self.adapter.execute(action)
                        if command not in ("succeeded", "failed", "unknown"):
                            command = "unknown"
                    except Exception:
                        command = "unknown"
                    append("command_completed", command, action_id)
                    try:
                        observed = self.adapter.observe(action)
                        good = _observation_satisfied(action, observed)
                    except Exception:
                        good = False
                    current = append("observation_completed", "satisfied" if good else "unavailable", action_id)
                    if command != "succeeded" or not good:
                        break
                    completed.append(action["stable_id"])
                if current["state"] != "unknown":
                    append("attempt_finished", current["state"])
                append("worker_completed", "verified_complete" if current["state"] == "observed-complete" else "unresolved")
            except BaseException:
                try:
                    append("worker_completed", "unresolved")
                except BaseException:
                    pass
                raise
            return read_attempt(self.store, identity)
