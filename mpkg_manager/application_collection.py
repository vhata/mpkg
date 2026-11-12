"""Explicit application collection from verified policy and durable host history."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json

from . import application_checks as observer
from .application_predicates import predicate_from_metadata
from . import runtime_checks as history
from .observations import utc_now


class ApplicationCollectionError(ValueError):
    def __init__(self, code="application_context_changed"):
        self.code = code
        super().__init__(code)


def application_check_manifest(store, loaded_policy, *, revision, snapshot_id, selected_components=None):
    """Return independent complete runtime scope, including application metadata."""
    return history.runtime_check_manifest(store, loaded_policy, revision=revision,
        snapshot_id=snapshot_id, selected_components=selected_components)


def _scopes(manifest):
    return tuple(raw for raw in manifest._scopes
                 if "application" in json.loads(raw)["context"]["check"])


class _HistoryGuard:
    """Own a live binding; callers cannot replace history with a True callback."""
    def __init__(self, store, policy, manifest):
        if type(manifest) is not history.RuntimeCheckManifest:
            raise ApplicationCollectionError("invalid_application_manifest")
        manifest.__post_init__()
        history._request(store, policy, manifest.revision, manifest._snapshot_id)
        self.store, self.policy, self.manifest = store, policy, manifest
        self.initial = self._context()
        self.verify()

    def _context(self):
        return history._live_context(self.store, self.policy, self.manifest.revision,
                                     self.manifest._snapshot_id)

    def verify(self):
        context = self._context()
        if (context != self.initial
                or history._manifest(context, self.manifest._selection) != self.manifest):
            raise ApplicationCollectionError()
        # Include a second live read after reconstructing accepted coverage.
        if self._context() != context:
            raise ApplicationCollectionError()

    def __call__(self, manifest, scope, predicate):
        self.verify()
        if (manifest != self.manifest or scope not in _scopes(manifest)
                or predicate_from_metadata(json.loads(scope)["context"]["check"]["application"]) != predicate):
            raise ApplicationCollectionError()
        return True


def observe_application(store, loaded_policy, *, manifest, scope, credential=None,
                        query_runner=None, namespace_holder=observer.hold_namespace,
                        application_runner=observer.run_application, route_runner=observer.published_route):
    """Observe one exact stored role; derive its predicate and live guard here.

    The credential resolver and native/worker seams are trusted embedding
    inputs. No predicate or guard override is accepted by this entrypoint.
    """
    guard = _HistoryGuard(store, loaded_policy, manifest)
    if scope not in _scopes(manifest):
        raise ApplicationCollectionError("invalid_application_scope")
    predicate = predicate_from_metadata(json.loads(scope)["context"]["check"]["application"])
    result = observer._observe_application(manifest, scope, predicate, context_guard=guard,
        credential=credential, query_runner=query_runner, namespace_holder=namespace_holder,
        application_runner=application_runner, route_runner=route_runner)
    guard.verify()
    return result


@dataclass(frozen=True)
class ApplicationCheckBatch:
    _manifest: history.RuntimeCheckManifest = field(repr=False)
    observed_at: str
    # Exact private role, observation or None, fixed unavailable reason or None.
    _rows: tuple = field(repr=False)

    def __post_init__(self):
        try:
            if type(self._manifest) is not history.RuntimeCheckManifest or type(self._rows) is not tuple:
                raise ValueError
            self._manifest.__post_init__()
            observer.runtime.validate_context(self._manifest.host_id, self.observed_at)
            if tuple(row[0] for row in self._rows) != _scopes(self._manifest):
                raise ValueError
            for scope, result, reason in self._rows:
                if result is None:
                    if reason not in ("collection_not_requested", "current_not_selected", "collection_limit"):
                        raise ValueError
                elif (type(result) is not observer.ApplicationObservation or reason is not None
                      or result._binding != observer._binding(self._manifest, scope,
                          predicate_from_metadata(json.loads(scope)["context"]["check"]["application"]))):
                    raise ValueError
                else:
                    result.__post_init__()
        except (ValueError, TypeError, KeyError, AttributeError, IndexError):
            raise ApplicationCollectionError("invalid_application_batch") from None

    def matches_manifest(self, expected, *, now=None, max_age_seconds=60):
        try:
            self.__post_init__()
            if type(expected) is not history.RuntimeCheckManifest:
                return False
            expected.__post_init__()
            when = datetime.now(timezone.utc) if now is None else now
            age = (when - datetime.fromisoformat(self.observed_at)).total_seconds()
            return (type(max_age_seconds) is int and 0 <= max_age_seconds <= 300
                    and 0 <= age <= max_age_seconds and expected == self._manifest)
        except (ValueError, TypeError, AttributeError):
            return False

    def as_dict(self):
        self.__post_init__()
        rows = []
        for raw, observation, reason in self._rows:
            scope = json.loads(raw)
            row = history._public_scope(scope)
            row.update(observation.as_dict() if observation is not None else {
                "functional_result": "unavailable", "route_result": "not_observed", "reason": reason})
            rows.append(row)
        return {"host_id": self._manifest.host_id, "revision": self._manifest.revision,
                "observed_at": self.observed_at, "coverage_complete": True,
                "source": "recorded_application_checks", "checks": rows, "executable": False}


def collect_application_checks(store, loaded_policy, *, revision, snapshot_id,
                               selected_components=None, check_applications=False,
                               credential_resolver=None, query_runner=None,
                               namespace_holder=observer.hold_namespace,
                               application_runner=observer.run_application,
                               route_runner=observer.published_route,
                               budget_seconds=60, max_checks=64):
    """Retained roles first; disabled and unscheduled roles remain explicit.

    credential_resolver receives the exact private scope. It may resolve a
    protected key for that accepted physical target, but cannot change its
    stored predicate. Neither keys nor credential references are recorded.
    """
    if (type(check_applications) is not bool or type(budget_seconds) is not int
            or not 1 <= budget_seconds <= 300 or type(max_checks) is not int or not 1 <= max_checks <= 256):
        raise ApplicationCollectionError("invalid_application_request")
    manifest = application_check_manifest(store, loaded_policy, revision=revision,
        snapshot_id=snapshot_id, selected_components=selected_components)
    guard = _HistoryGuard(store, loaded_policy, manifest)
    budget = history._Budget(budget_seconds, 1024, 64 * 1024 * 1024,
                            query_runner or observer.run_readonly, None)
    when, rows, attempted = utc_now(), [], 0
    for scope in _scopes(manifest):
        role = json.loads(scope)
        reason, result = None, None
        if not role["selected"]:
            reason = "current_not_selected"
        elif not check_applications:
            reason = "collection_not_requested"
        elif attempted >= max_checks or budget.remaining() < 2 * role["context"]["check"]["timeout_seconds"]:
            reason = "collection_limit"
        else:
            attempted += 1
            predicate = predicate_from_metadata(role["context"]["check"]["application"])
            result = observer._observe_application(manifest, scope, predicate, context_guard=guard,
                credential=(None if credential_resolver is None else lambda: credential_resolver(scope)),
                query_runner=budget.runner("endpoint"), namespace_holder=namespace_holder,
                application_runner=application_runner, route_runner=route_runner)
            if budget.remaining() <= 0:
                result, reason = None, "collection_limit"
        rows.append((scope, result, reason))
    guard.verify()
    return ApplicationCheckBatch(manifest, when, tuple(rows))
