"""Trusted collection of recorded runtime and declared-user check obligations."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
import time
import uuid

from . import consumer_access, runtime_endpoint
from .declarations import DeclarationError, canonical_json, physical_key, validate_model
from .host_policy import LoadedHostPolicy, PolicyError
from .observations import utc_now, validate_context
from .query_process import QueryResult
from .store import HostStore, StoreError


MAX_CHECKS = 4096
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_UNAVAILABLE = frozenset({
    "current_not_selected", "endpoint_collection_not_requested", "access_collection_not_requested",
    "physical_identity_unbound", "collection_budget_exhausted", "collection_check_limit",
    "collection_query_limit", "collection_query_byte_limit", "collection_query_timeout",
    "collection_query_failed", "collection_query_result_invalid", "collection_check_timeout",
    "check_observer_unavailable", "check_observation_invalid",
})
LIMITATIONS = (
    "time_bounded_observation_not_atomic_host_snapshot",
    "policy_history_and_proc_reads_have_no_enforced_latency_deadline",
    "query_output_budget_reserves_each_query_capture_allowance",
    "probe_and_access_workers_have_separate_fixed_output_and_read_bounds",
    "socket_ownership_not_responder_authentication_or_functional_health",
    "declared_local_credentials_not_running_application_credentials",
    "no_management_or_application_authority_inferred",
)


class RuntimeCheckError(ValueError):
    """Fixed diagnostics exclude private predicates, paths and underlying errors."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition):
    if not condition:
        raise ValueError


def _context(check, resource, host_id, aliases):
    kind = check["kind"]
    _require(kind in ("endpoint", "access"))
    minimal = {name: resource[name] for name in ("id", "kind", "identity")}
    minimal["checks"] = [check["id"]]
    components = []
    if kind == "access":
        consumer = check["consumer"]
        _require(consumer in resource["consumers"])
        minimal["consumers"] = [consumer]
        if not consumer.startswith("external:"):
            components = [{"id": consumer, "purpose": "Required access", "resources": [resource["id"]]}]
    elif resource["kind"] == "compose":
        minimal["desired"] = {"services": resource["desired"].get("services", [])}
    normalized = validate_model({"schema": 1, "components": components,
                                 "resources": [minimal], "checks": [check]})
    target_resource = normalized["resources"][0]
    minimal = {name: target_resource[name] for name in minimal}
    try:
        target = list(physical_key(target_resource, host_id, aliases))
    except DeclarationError:
        target = None
    return {"check": normalized["checks"][0], "resource": minimal, "target": target}


def _decode_scope(raw, host_id):
    _require(type(raw) is bytes and len(raw) <= MAX_MANIFEST_BYTES)
    scope = json.loads(raw)
    _require(type(scope) is dict and set(scope) == {
        "role", "stable_id", "adoption_revision", "snapshot_id", "management", "selected", "context"})
    _require(canonical_json(scope) == raw)
    _require(type(scope["snapshot_id"]) is str and _HASH.fullmatch(scope["snapshot_id"]))
    _require(type(scope["selected"]) is bool)
    if scope["role"] == "current":
        _require(scope["stable_id"] is None and scope["adoption_revision"] is None
                 and scope["management"] is None)
    else:
        _require(scope["role"] == "accepted" and scope["selected"] is True
                 and scope["management"] in ("accepted", "relinquished"))
        _require(type(scope["stable_id"]) is str and str(uuid.UUID(scope["stable_id"])) == scope["stable_id"])
        _require(type(scope["adoption_revision"]) is int and 0 < scope["adoption_revision"] < 2**63)
    context = scope["context"]
    _require(type(context) is dict and set(context) == {"check", "resource", "target"})
    target, resource = context["target"], context["resource"]
    aliases = {}
    if target is not None:
        _require(type(target) is list and len(target) >= 3 and target[0] == host_id)
        if resource["kind"] in ("compose", "volume"):
            aliases[resource["identity"]["engine"]] = target[2]
    _require(_context(context["check"], resource, host_id, aliases) == context)
    return scope


def _public_scope(scope):
    check, resource = scope["context"]["check"], scope["context"]["resource"]
    return {"role": scope["role"], "stable_id": scope["stable_id"],
            "adoption_revision": scope["adoption_revision"], "management": scope["management"],
            "selected": scope["selected"], "check_id": check["id"], "check_kind": check["kind"],
            "resource_id": resource["id"], "resource_kind": resource["kind"],
            "consumer_id": check.get("consumer"), "operation": check.get("operation")}


@dataclass(frozen=True)
class RuntimeCheckManifest:
    """Independent expected coverage; construction alone authenticates nothing."""
    host_id: str
    revision: int
    _snapshot_id: str = field(repr=False)
    _selection: tuple | None = field(repr=False)
    _scopes: tuple = field(repr=False)

    def __post_init__(self):
        try:
            validate_context(self.host_id, "2000-01-01T00:00:00Z")
            _require(type(self.revision) is int and 0 < self.revision < 2**63)
            _require(type(self._snapshot_id) is str and _HASH.fullmatch(self._snapshot_id))
            if self._selection is not None:
                _require(type(self._selection) is tuple and len(self._selection) <= MAX_CHECKS
                         and all(type(item) is str and _ID.fullmatch(item) for item in self._selection)
                         and tuple(sorted(set(self._selection))) == self._selection)
            _require(type(self._scopes) is tuple and len(self._scopes) <= MAX_CHECKS)
            _require(all(type(raw) is bytes for raw in self._scopes))
            _require(sum(map(len, self._scopes)) <= MAX_MANIFEST_BYTES)
            seen = set()
            for raw in self._scopes:
                scope = _decode_scope(raw, self.host_id)
                if scope["role"] == "current":
                    _require(scope["snapshot_id"] == self._snapshot_id)
                    _require(self._selection is not None or scope["selected"])
                else:
                    _require(scope["adoption_revision"] <= self.revision)
                    if scope["adoption_revision"] == self.revision:
                        _require(scope["snapshot_id"] == self._snapshot_id)
                key = (scope["role"], scope["stable_id"], scope["context"]["check"]["id"])
                _require(key not in seen)
                seen.add(key)
        except (ValueError, TypeError, KeyError, AttributeError, IndexError, UnicodeError, RecursionError):
            raise RuntimeCheckError("invalid_runtime_check_manifest") from None

    def matches_context(self, *, host_id, revision, snapshot_id):
        return (type(revision) is int and self.host_id == host_id and self.revision == revision
                and self._snapshot_id == snapshot_id)

    def as_dict(self):
        self.__post_init__()
        return {"host_id": self.host_id, "revision": self.revision,
                "source": "recorded_runtime_check_history", "coverage_complete": True,
                "selected_components": None if self._selection is None else list(self._selection),
                "checks": [_public_scope(json.loads(raw)) for raw in self._scopes]}


@dataclass(frozen=True)
class RuntimeCheckResult:
    """One original role, with separate typed runtime or access evidence."""
    host_id: str
    _scope: bytes = field(repr=False)
    observation: runtime_endpoint.AttributedEndpointObservation | consumer_access.ConsumerAccessObservation | None = field(repr=False)
    unavailable_reason: str | None = None

    def __post_init__(self):
        try:
            validate_context(self.host_id, "2000-01-01T00:00:00Z")
            scope = _decode_scope(self._scope, self.host_id)
            context = scope["context"]
            if self.observation is None:
                _require(type(self.unavailable_reason) is str and self.unavailable_reason in _UNAVAILABLE)
            else:
                _require(scope["selected"] and context["target"] is not None and self.unavailable_reason is None)
                observation = self.observation
                if context["check"]["kind"] == "endpoint":
                    _require(type(observation) is runtime_endpoint.AttributedEndpointObservation)
                    runtime_endpoint.AttributedEndpointObservation(observation._binding, observation.observed_at,
                        observation.attribution, observation.route_result, observation.reason)
                else:
                    _require(type(observation) is consumer_access.ConsumerAccessObservation)
                    consumer_access.ConsumerAccessObservation(observation._binding, observation.observed_at,
                        observation.access_result, observation.reason)
                aliases = {}
                if context["resource"]["kind"] in ("compose", "volume"):
                    aliases[context["resource"]["identity"]["engine"]] = context["target"][2]
                _require(observation.matches_context(context["check"], context["resource"],
                    host_id=self.host_id, engine_aliases=aliases))
        except (ValueError, TypeError, KeyError, AttributeError, IndexError, UnicodeError, RecursionError):
            raise RuntimeCheckError("invalid_runtime_check_result") from None

    def as_dict(self):
        self.__post_init__()
        scope = json.loads(self._scope)
        result = _public_scope(scope)
        result.update(functional_result="unverified")
        if self.observation is None:
            result.update(reason=self.unavailable_reason)
            if scope["context"]["check"]["kind"] == "endpoint":
                result.update(attribution="unavailable", route_result="not_observed")
            else:
                result.update(access_result="unavailable")
        else:
            observed = self.observation.as_dict()
            fields = ("attribution", "route_result") if scope["context"]["check"]["kind"] == "endpoint" else ("access_result",)
            result.update({name: observed[name] for name in (*fields, "reason")})
        return result


@dataclass(frozen=True)
class RuntimeCheckBatch:
    """Complete private role coverage; compare with independent trusted history."""
    _manifest: RuntimeCheckManifest = field(repr=False)
    observed_at: str
    checks: tuple
    probe_endpoints: bool
    check_access: bool
    endpoint_count: int
    access_count: int
    query_count: int
    query_output_bytes_reserved: int
    query_limits: tuple = ()

    def __post_init__(self):
        try:
            _require(type(self._manifest) is RuntimeCheckManifest)
            self._manifest.__post_init__()
            validate_context(self._manifest.host_id, self.observed_at)
            _require(type(self.probe_endpoints) is bool and type(self.check_access) is bool)
            _require(type(self.checks) is tuple and len(self.checks) == len(self._manifest._scopes))
            for count in (self.endpoint_count, self.access_count):
                _require(type(count) is int and 0 <= count <= 256)
            _require(self.endpoint_count + self.access_count <= min(256, len(self.checks)))
            _require(self.probe_endpoints or self.endpoint_count == 0)
            _require(self.check_access or self.access_count == 0)
            _require(type(self.query_count) is int and 0 <= self.query_count <= 4096)
            _require(type(self.query_output_bytes_reserved) is int
                     and 0 <= self.query_output_bytes_reserved <= 128 * 1024 * 1024)
            _require(type(self.query_limits) is tuple and all(type(code) is str and code in _UNAVAILABLE
                                                           for code in self.query_limits)
                     and tuple(sorted(set(self.query_limits))) == self.query_limits)
            for raw, row in zip(self._manifest._scopes, self.checks, strict=True):
                _require(type(row) is RuntimeCheckResult and row.host_id == self._manifest.host_id and row._scope == raw)
                row.__post_init__()
                if row.observation is not None:
                    _require(row.observation.observed_at == self.observed_at)
                    _require(self.probe_endpoints if json.loads(raw)["context"]["check"]["kind"] == "endpoint"
                             else self.check_access)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
            raise RuntimeCheckError("invalid_runtime_check_batch") from None

    def matches_manifest(self, manifest, *, now=None, max_age_seconds=60):
        """Pure exact coverage/freshness check; callers supply fresh trusted history."""
        try:
            self.__post_init__()
            _require(type(manifest) is RuntimeCheckManifest)
            manifest.__post_init__()
            _require(type(max_age_seconds) is int and 1 <= max_age_seconds <= 3600)
            now = datetime.now(timezone.utc) if now is None else now
            _require(type(now) is datetime and now.tzinfo is not None)
            age = (now - datetime.fromisoformat(self.observed_at)).total_seconds()
            return self._manifest == manifest and 0 <= age <= max_age_seconds
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            return False

    def as_dict(self):
        self.__post_init__()
        return {"host_id": self._manifest.host_id, "revision": self._manifest.revision,
                "observed_at": self.observed_at, "source": "recorded_runtime_and_consumer_checks",
                "checks": [row.as_dict() for row in self.checks], "coverage_complete": True,
                "probe_endpoints": self.probe_endpoints, "check_access": self.check_access,
                "endpoint_count": self.endpoint_count, "access_count": self.access_count,
                "query_count": self.query_count, "query_output_bytes_reserved": self.query_output_bytes_reserved,
                "query_limits": list(self.query_limits), "functional_result": "unverified",
                "executable": False, "limitations": list(LIMITATIONS)}


def _request(store, loaded_policy, revision, snapshot_id):
    if (type(store) is not HostStore or getattr(store, "readonly", None) is not True
            or type(loaded_policy) is not LoadedHostPolicy or type(revision) is not int
            or not 0 < revision < 2**63 or type(snapshot_id) is not str or not _HASH.fullmatch(snapshot_id)):
        raise RuntimeCheckError("invalid_runtime_check_request")


def _live_context(store, loaded_policy, revision, snapshot_id):
    try:
        policy = loaded_policy.policy
        current, aliases = store.current(), store.engine_aliases
        if policy.host_id != current["host_id"] or policy.engine_aliases != aliases:
            raise RuntimeCheckError("runtime_check_policy_store_mismatch")
        if current["revision"] != revision or current["snapshot_id"] != snapshot_id:
            raise RuntimeCheckError("runtime_check_context_changed")
        return policy, current, aliases, store.snapshot(snapshot_id)
    except PolicyError:
        raise RuntimeCheckError("runtime_check_policy_unavailable") from None
    except StoreError:
        raise RuntimeCheckError("runtime_check_store_unavailable") from None


def _manifest(context, selected_components):
    policy, current, aliases, declaration = context
    model = declaration.model
    resources = {item["id"]: item for item in model["resources"]}
    components = {item["id"]: item for item in model["components"]}
    if selected_components is None:
        selection, included = None, set(resources)
    else:
        if (type(selected_components) not in (list, tuple) or len(selected_components) > MAX_CHECKS
                or any(type(name) is not str for name in selected_components)
                or len(set(selected_components)) != len(selected_components)
                or not set(selected_components) <= set(components)):
            raise RuntimeCheckError("invalid_runtime_check_selection")
        selection = tuple(sorted(selected_components))
        included = {name for component in selection for name in components[component]["resources"]}
        pending = list(included)
        while pending:
            for name in resources[pending.pop()]["requires"]:
                if name not in included:
                    included.add(name)
                    pending.append(name)
    scopes, size = [], 0

    def append(check, resource, record=None):
        nonlocal size
        if check["kind"] not in ("endpoint", "access"):
            return
        context = _context(check, resource, policy.host_id, aliases)
        if record is not None and context["target"] != record["physical_key"]:
            raise RuntimeCheckError("runtime_check_store_unavailable")
        scope = {"role": "accepted" if record else "current", "context": context,
                 "snapshot_id": record["accepted_checks"]["snapshot_id"] if record else current["snapshot_id"],
                 "stable_id": record["stable_id"] if record else None,
                 "adoption_revision": record["accepted_checks"]["adoption_revision"] if record else None,
                 "management": record["management"] if record else None,
                 "selected": True if record else resource["id"] in included}
        raw = canonical_json(scope)
        size += len(raw)
        if len(scopes) >= MAX_CHECKS or size > MAX_MANIFEST_BYTES:
            raise RuntimeCheckError("runtime_check_coverage_limit")
        scopes.append(raw)

    for record in current["resources"]:
        for check in record["accepted_checks"]["definitions"]:
            append(check, record["definition"], record)
    checks = {check["id"]: check for check in model["checks"]}
    for resource in model["resources"]:
        for check_id in resource["checks"]:
            append(checks[check_id], resource)
    return RuntimeCheckManifest(policy.host_id, current["revision"], current["snapshot_id"],
                                selection, tuple(scopes))


def runtime_check_manifest(store, loaded_policy, *, revision, snapshot_id, selected_components=None):
    """Derive expected scope from actual read-only history without host checks."""
    _request(store, loaded_policy, revision, snapshot_id)
    try:
        context = _live_context(store, loaded_policy, revision, snapshot_id)
        manifest = _manifest(context, selected_components)
        if _live_context(store, loaded_policy, revision, snapshot_id) != context:
            raise RuntimeCheckError("runtime_check_context_changed")
        return manifest
    except RuntimeCheckError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise RuntimeCheckError("invalid_runtime_check_context") from None


class _Budget:
    def __init__(self, seconds, queries, query_bytes, runtime_runner, access_runner):
        self.deadline = time.monotonic() + seconds
        self.max_queries, self.max_bytes = queries, query_bytes
        self.runners = {"endpoint": runtime_runner, "access": access_runner}
        self.count, self.reserved = 0, 0
        self.issues = set()
        self.last_reason = None

    def remaining(self):
        return self.deadline - time.monotonic()

    def runner(self, kind):
        def query(argv, *, timeout, max_output=None):
            cap = runtime_endpoint.MAX_OUTPUT if kind == "endpoint" else consumer_access.MAX_QUERY_BYTES
            reason = None
            if self.remaining() <= 0:
                reason = "collection_budget_exhausted"
            elif self.count >= self.max_queries:
                reason = "collection_query_limit"
            elif self.reserved + cap > self.max_bytes:
                reason = "collection_query_byte_limit"
            if reason:
                self.last_reason = reason
                self.issues.add(reason)
                return QueryResult("timeout")
            seconds = min(timeout, self.remaining())
            if seconds <= 0:
                self.last_reason = "collection_budget_exhausted"
                self.issues.add(self.last_reason)
                return QueryResult("timeout")
            self.count += 1
            self.reserved += cap
            deadline = time.monotonic() + seconds
            try:
                runner = self.runners[kind]
                if kind == "endpoint":
                    result = (runtime_endpoint.run_readonly if runner is None else runner)(
                        argv, timeout=seconds, max_output=cap)
                else:
                    result = (consumer_access.run_readonly if runner is None else runner)(argv, timeout=seconds)
            except Exception:
                result, reason = QueryResult("io_error"), "collection_query_failed"
            if self.remaining() <= 0:
                reason = "collection_budget_exhausted"
            elif time.monotonic() >= deadline:
                reason = "collection_query_timeout"
            elif type(result) is not QueryResult or type(result.output) is not bytes or len(result.output) > cap:
                reason = "collection_query_result_invalid"
            if reason:
                self.last_reason = reason
                self.issues.add(reason)
                return QueryResult("timeout" if reason.endswith(("timeout", "exhausted")) else "io_error")
            return result
        return query


def collect_runtime_checks(store, loaded_policy, *, revision, snapshot_id, selected_components=None,
                           probe_endpoints=False, check_access=False, budget_seconds=60, max_checks=64,
                           max_queries=1024, max_query_bytes=64 * 1024 * 1024,
                           runtime_query_runner=None, proc_reader=None, probe_runner=None,
                           access_query_runner=None, access_worker_runner=None):
    """Explicitly collect original runtime/access obligations through trusted handles.

    Runner and proc seams are trusted embedding code, never request fields.
    Synchronous policy/history/proc reads and cleanup are not preemptible.
    """
    _request(store, loaded_policy, revision, snapshot_id)
    if (type(probe_endpoints) is not bool or type(check_access) is not bool
            or type(budget_seconds) is not int or not 1 <= budget_seconds <= 300
            or type(max_checks) is not int or not 1 <= max_checks <= 256
            or type(max_queries) is not int or not 1 <= max_queries <= 4096
            or type(max_query_bytes) is not int or not 1 <= max_query_bytes <= 128 * 1024 * 1024
            or any(runner is not None and not callable(runner) for runner in (
                runtime_query_runner, probe_runner, access_query_runner, access_worker_runner))
            or (proc_reader is not None and not callable(getattr(proc_reader, "capture", None)))):
        raise RuntimeCheckError("invalid_runtime_check_request")
    budget = _Budget(budget_seconds, max_queries, max_query_bytes, runtime_query_runner, access_query_runner)
    when = utc_now()
    initial = _live_context(store, loaded_policy, revision, snapshot_id)
    try:
        manifest = _manifest(initial, selected_components)
    except RuntimeCheckError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise RuntimeCheckError("invalid_runtime_check_context") from None
    aliases = initial[2]
    cache, rows, counts = {}, [], {"endpoint": 0, "access": 0}
    for raw in manifest._scopes:
        scope = json.loads(raw)
        context = scope["context"]
        kind = context["check"]["kind"]
        observation, reason = None, None
        if not scope["selected"]:
            reason = "current_not_selected"
        elif not (probe_endpoints if kind == "endpoint" else check_access):
            reason = "endpoint_collection_not_requested" if kind == "endpoint" else "access_collection_not_requested"
        elif context["target"] is None:
            reason = "physical_identity_unbound"
        key = canonical_json(context)
        if reason is None and key in cache:
            observation, reason = cache[key]
        elif reason is None:
            seconds = int(budget.remaining())
            if sum(counts.values()) >= max_checks:
                reason = "collection_check_limit"
            elif seconds < context["check"]["timeout_seconds"]:
                reason = "collection_budget_exhausted"
            else:
                counts[kind] += 1
                budget.last_reason = None
                started = time.monotonic()
                try:
                    if kind == "endpoint":
                        observation = runtime_endpoint.observe_attributed_endpoint(
                            context["check"], context["resource"], host_id=manifest.host_id,
                            engine_aliases=aliases, observed_at=when, budget_seconds=seconds,
                            query_runner=budget.runner(kind), proc_reader=proc_reader, probe_runner=probe_runner)
                    else:
                        observation = consumer_access.observe_consumer_access(
                            context["check"], context["resource"], host_id=manifest.host_id,
                            engine_aliases=aliases, observed_at=when,
                            query_runner=budget.runner(kind), worker_runner=access_worker_runner)
                    RuntimeCheckResult(manifest.host_id, raw, observation)
                    if observation.observed_at != when:
                        raise ValueError
                except (RuntimeCheckError, ValueError, TypeError, AttributeError):
                    observation, reason = None, "check_observation_invalid"
                except Exception:
                    observation, reason = None, "check_observer_unavailable"
                if budget.remaining() <= 0:
                    observation, reason = None, "collection_budget_exhausted"
                elif budget.last_reason and reason != "check_observation_invalid":
                    observation, reason = None, budget.last_reason
                elif time.monotonic() - started >= (seconds if kind == "endpoint" else context["check"]["timeout_seconds"]):
                    observation, reason = None, "collection_check_timeout"
            cache[key] = observation, reason
        rows.append(RuntimeCheckResult(manifest.host_id, raw, observation, reason))
    # Empty selections, disabled modes, failed observers and exhausted budgets
    # all cross live checks before any usable result is returned.
    if _live_context(store, loaded_policy, revision, snapshot_id) != initial:
        raise RuntimeCheckError("runtime_check_context_changed")
    return RuntimeCheckBatch(manifest, when, tuple(rows), probe_endpoints, check_access,
        counts["endpoint"], counts["access"], budget.count, budget.reserved, tuple(sorted(budget.issues)))
