"""Closed execution orchestration; installed adapter registration is empty.

The optional backend is trusted embedding for inert boundary integration,
never request data, a plugin loader, or an installed fixture switch.
"""
import os
import uuid

from .host_helper import BoundaryError, _mutation_lock
from .host_policy import load_host_policy
from .store import HostStore
from .protected_bindings import ProtectedRecorder
from .execution_plans import ExecutionPlanError, read_execution_plan
from .attempt_journal import (WorkerIdentity, _attempt_context, read_attempt,
                              require_no_pending_launch)
from .attempt_supervisor import LaunchSpec, LaunchResult, _append


def _require(value):
    if not value:
        raise BoundaryError("execution_request_rejected")


def _summary(store, plan_id):
    plan = read_execution_plan(store, plan_id).as_dict()
    # Project only the closed reviewed scope. Private descriptors stay inside
    # the planner. No fixture plan is advertised as production executable.
    return {key: plan[key] for key in ("plan_id", "revision", "accepted", "acceptance_id",
        "actions", "executable", "authority")} | {"interruption": "stop_and_require_recovery"}


def _retry_predecessor(store, binding, context):
    """Derive ancestry from complete authenticated history under the host lock.

    Scope includes derived prerequisites, not just the caller's roots. A
    single predecessor can represent only one lineage; unrelated overlapping
    failures remain blocked rather than silently choosing the newest one.
    """
    scope = set(context["history"]["target"]["selected"])
    with store._read():
        # _read authenticates all plans, acceptances, attempts and events before
        # any of these private timestamps or ancestry pointers are used.
        created = store._db.execute("SELECT created_at FROM execution_plans WHERE id=?",
                                    (binding.plan_id,)).fetchone()[0]
        accepted = store._db.execute("SELECT created_at FROM plan_acceptances WHERE id=?",
                                     (binding.acceptance_id,)).fetchone()[0]
        attempts = [_attempt_context(store, identity).as_dict()["summary"]
                    for (identity,) in store._db.execute("SELECT id FROM attempts ORDER BY ordinal")]
    ancestors, unresolved = {}, {}
    for attempt in attempts:
        identity, parent = attempt["attempt_id"], attempt["predecessor"]
        ancestors[identity] = (ancestors[parent] | {parent}) if parent is not None else set()
        overlap = scope & {action["stable_resource_id"] for action in attempt["actions"]}
        if not overlap:
            continue
        supervision = attempt["supervision"]
        complete = (supervision["recovery"] != "quiescent"
                    and attempt["finished"] and attempt["state"] == "observed-complete"
                    and (not supervision["reserved"] or supervision["released"]))
        # Even a later successful retry cannot revive a proposal prepared
        # before the earlier disposition. Check every overlapping recovery,
        # including ancestors that a successful descendant has resolved.
        terminals = [event["created_at"] for event in attempt["events"]
                     if (event["kind"] == "recovery_recorded" and event["outcome"] == "quiescent")
                     or (event["kind"] == "attempt_finished" and event["outcome"] in {"failed", "unverified"})]
        if terminals:
            _require(created >= max(terminals) and accepted >= max(terminals))
        if complete:
            # Success resolves only the overlapping resources actually checked
            # by a linked descendant; partial retries do not erase old scope.
            for ancestor in ancestors[identity] & unresolved.keys():
                unresolved[ancestor] -= overlap
        else:
            eligible = (supervision["recovery"] == "quiescent"
                        or (attempt["finished"] and attempt["state"] in {"failed", "unverified"}
                            and not supervision["reserved"]))
            _require(eligible and terminals)
            unresolved[identity] = overlap
    candidates = {identity for identity, remaining in unresolved.items() if remaining}
    if not candidates:
        return None
    tips = [identity for identity in candidates if candidates <= ancestors[identity] | {identity}]
    _require(len(tips) == 1)
    return tips[0]


def dispatch_execution(boundary, request):
    operator = boundary._operator_uid
    if type(operator) is not int or not 0 <= operator < 2**32 - 1:
        raise BoundaryError("operator_identity_unavailable")
    backend = boundary._execution
    if backend is None:
        # There is deliberately no public route to _FixturePlanner, inert
        # workers or fixture recovery collectors in the installed helper.
        raise BoundaryError("execution_adapter_unavailable")
    try:
        return _dispatch(boundary, request, backend, operator)
    except BoundaryError:
        raise
    except ExecutionPlanError as error:
        raise BoundaryError("execution_outcome_unknown" if error.code == "execution_outcome_unknown"
                            else "execution_request_rejected") from None
    except Exception:
        # Even cleanup can fail after a commit. Never infer rollback or expose
        # adapter errors; inspect exact plan/attempt history before retrying.
        raise BoundaryError("execution_outcome_unknown") from None


def _dispatch(boundary, request, backend, operator):
    if request.verb == "recover":
        result = backend.recover(request.attempt_id, request.expected_sequence, operator)
        return {"attempt_id": result["attempt_id"], "disposition": result["supervision"]["recovery"]}
    with _mutation_lock(boundary._mutation_lock, boundary._owner_uid):
        with load_host_policy(path=boundary._policy_path, owner_uid=boundary._owner_uid) as policy:
            with HostStore.open_existing(boundary._store_directory, policy.policy.host_id,
                                         owner_uid=boundary._owner_uid) as store:
                boundary._bound(store, policy.policy)
                planner = backend.planner(ProtectedRecorder(store, policy))
                if request.verb == "prepare":
                    require_no_pending_launch(store)
                    plan = planner.prepare(expected_revision=request.expected_revision,
                                           stable_resource_ids=request.resource_ids).as_dict()
                    return _summary(store, plan["plan_id"])
                plan = _summary(store, request.plan_id)
                if request.verb == "plan" and request.operation == "inspect":
                    return plan
                if request.verb == "plan":
                    require_no_pending_launch(store)
                    if plan["accepted"]:
                        binding = planner.binding(plan["acceptance_id"])
                        _require(binding.operator_uid == operator)
                        planner.validate(binding)
                    else:
                        planner.accept(request.plan_id, operator_uid=operator)
                    return _summary(store, request.plan_id)
                _require(request.verb == "apply" and plan["accepted"])
                binding = planner.binding(plan["acceptance_id"])
                _require(binding.operator_uid == operator and binding.plan_id == request.plan_id)
                # Unique plan identity is the durable idempotency key. Read it
                # before freshness checks so a lost response remains inspectable
                # even after the attempt changed facts or newer intent was recorded.
                existing = store._db.execute("SELECT id FROM attempts WHERE plan_id=?", (request.plan_id,)).fetchone()
                if existing is not None:
                    attempt = read_attempt(store, existing[0]).as_dict()
                    return {"attempt_id": attempt["attempt_id"], "launch": "existing", "executable": False}
                require_no_pending_launch(store)
                context = planner.validate(binding)
                predecessor = _retry_predecessor(store, binding, context)
                worker = WorkerIdentity(operator_uid=operator, worker_uid=os.geteuid(), boot_id=backend.boot_id, worker_id=str(uuid.uuid4()))
                attempt = planner.create_attempt(binding, worker, predecessor=predecessor).as_dict()
                identity = attempt["attempt_id"]
                # No gap for recording between attempt creation and reservation:
                # the host lock covers both durable transactions.
                _append(store, identity, "launch_reserved", "reserved")
                host_id = store.host_id
    # Reservation persists through disconnect and through the lock handoff.
    # An uncertain response never triggers a second launch.
    try:
        result = backend.launch(LaunchSpec(identity))
        if type(result) is not LaunchResult:
            result = LaunchResult("unknown")
    except Exception:
        result = LaunchResult("unknown")
    with HostStore.open_existing(boundary._store_directory, host_id, owner_uid=boundary._owner_uid) as store:
        _append(store, identity, "launch_result", result.outcome)
    return {"attempt_id": identity, "launch": result.outcome, "executable": False}
