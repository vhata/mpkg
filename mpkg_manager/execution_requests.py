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
from .attempt_journal import WorkerIdentity, read_attempt, require_no_pending_launch
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
                planner.validate(binding)
                worker = WorkerIdentity(operator_uid=operator, worker_uid=os.geteuid(), boot_id=backend.boot_id, worker_id=str(uuid.uuid4()))
                attempt = planner.create_attempt(binding, worker).as_dict()
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
