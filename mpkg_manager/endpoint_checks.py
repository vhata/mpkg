"""Explicit trusted collection of recorded endpoint routes, never health authority."""
from dataclasses import dataclass, field
import json
import re
import time
import uuid

from .declarations import DeclarationError, canonical_json, physical_key, validate_model
from .observations import utc_now, validate_context
from .observe_endpoint import EndpointError, EndpointObservation, LIMITATIONS, observe_endpoint
from .store import HostStore, StoreError


MAX_CHECKS = 4096
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_UNAVAILABLE = frozenset({"collection_budget_exhausted", "collection_probe_limit", "collection_probe_timeout",
                          "physical_identity_unbound", "invalid_endpoint_context",
                          "endpoint_runner_failed", "invalid_endpoint_result"})


class EndpointCollectionError(ValueError):
    """Fixed diagnostics exclude snapshot, predicate and underlying error text."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition):
    if not condition:
        raise ValueError


def _context(check, resource, host_id, aliases):
    minimal = {key: resource[key] for key in ("id", "kind", "identity")}
    minimal["checks"] = [check["id"]]
    model = validate_model({"schema": 1, "components": [], "resources": [minimal], "checks": [check]})
    _require(model["checks"][0]["kind"] == "endpoint")
    try:
        target = list(physical_key(model["resources"][0], host_id, aliases))
    except DeclarationError:
        target = None
    return {"check": model["checks"][0], "resource": minimal, "target": target}


def _decode_scope(raw):
    _require(type(raw) is bytes and len(raw) <= MAX_MANIFEST_BYTES)
    scope = json.loads(raw)
    _require(type(scope) is dict and set(scope) == {
        "role", "stable_id", "adoption_revision", "snapshot_id", "management", "context"})
    _require(canonical_json(scope) == raw)
    _require(type(scope["snapshot_id"]) is str and _HASH.fullmatch(scope["snapshot_id"]))
    if scope["role"] == "current":
        _require(scope["stable_id"] is None and scope["adoption_revision"] is None
                 and scope["management"] is None)
    else:
        _require(scope["role"] == "accepted" and scope["management"] in ("accepted", "relinquished"))
        _require(type(scope["stable_id"]) is str and str(uuid.UUID(scope["stable_id"])) == scope["stable_id"])
        _require(type(scope["adoption_revision"]) is int and 0 < scope["adoption_revision"] < 2**63)
    context = scope["context"]
    _require(type(context) is dict and set(context) == {"check", "resource", "target"})
    target = context["target"]
    aliases = {}
    host = "00000000-0000-4000-8000-000000000000"
    if target is not None:
        _require(type(target) is list and len(target) == 4 and all(type(value) is str for value in target))
        host = target[0]
        validate_context(host, "2000-01-01T00:00:00Z")
        if context["resource"]["kind"] == "compose":
            aliases[context["resource"]["identity"]["engine"]] = target[2]
    _require(_context(context["check"], context["resource"], host, aliases) == context)
    return scope


@dataclass(frozen=True)
class EndpointCheckResult:
    """One recorded role and its immutable private predicate/target binding."""
    _scope: bytes = field(repr=False)
    observation: EndpointObservation | None = field(repr=False)
    unavailable_reason: str | None = None

    def __post_init__(self):
        try:
            scope = _decode_scope(self._scope)
            context, observation = scope["context"], self.observation
            if observation is None:
                _require(type(self.unavailable_reason) is str and self.unavailable_reason in _UNAVAILABLE)
            else:
                _require(type(observation) is EndpointObservation and self.unavailable_reason is None)
                EndpointObservation(observation._binding, observation.observed_at,
                                    observation.route_result, observation.reason)
                _require(json.loads(observation._binding) == {
                    "check": context["check"], "target": context["target"]})
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
            raise EndpointCollectionError("invalid_endpoint_check_result") from None

    def matches_context(self, check, resource, *, host_id, role, snapshot_id,
                        engine_aliases=None, stable_id=None, adoption_revision=None):
        """Compare original role, adoption and complete physical predicate context."""
        try:
            scope = _decode_scope(self._scope)
            context = _context(check, resource, host_id, {} if engine_aliases is None else engine_aliases)
            return (context["target"] is not None
                    and {key: scope[key] for key in ("role", "snapshot_id", "stable_id", "adoption_revision")}
                    == {"role": role, "snapshot_id": snapshot_id, "stable_id": stable_id,
                        "adoption_revision": adoption_revision}
                    and {key: context[key] for key in ("check", "target")}
                    == {key: scope["context"][key] for key in ("check", "target")})
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
            return False

    @property
    def functional_result(self):
        return "unverified"

    @property
    def limitations(self):
        return LIMITATIONS

    def as_dict(self):
        scope = json.loads(self._scope)
        context = scope["context"]
        return {"role": scope["role"], "stable_id": scope["stable_id"],
                "adoption_revision": scope["adoption_revision"], "management": scope["management"],
                "check_id": context["check"]["id"], "resource_id": context["check"]["resource"],
                "resource_kind": context["resource"]["kind"],
                "route_result": self.observation.route_result if self.observation else "unavailable",
                "reason": self.observation.reason if self.observation else self.unavailable_reason,
                "functional_result": self.functional_result, "limitations": list(self.limitations)}


@dataclass(frozen=True)
class EndpointCheckBatch:
    """Complete role coverage from one recorded revision; no JSON import API."""
    host_id: str
    revision: int
    _snapshot_id: str = field(repr=False)
    observed_at: str
    checks: tuple
    probe_count: int

    def __post_init__(self):
        try:
            validate_context(self.host_id, self.observed_at)
            _require(type(self.revision) is int and 0 < self.revision < 2**63)
            _require(type(self._snapshot_id) is str and _HASH.fullmatch(self._snapshot_id))
            _require(type(self.checks) is tuple and len(self.checks) <= MAX_CHECKS)
            _require(type(self.probe_count) is int and 0 <= self.probe_count <= 256)
            _require(sum(len(row._scope) for row in self.checks) <= MAX_MANIFEST_BYTES)
            seen = set()
            for row in self.checks:
                _require(type(row) is EndpointCheckResult)
                EndpointCheckResult(row._scope, row.observation, row.unavailable_reason)
                scope = json.loads(row._scope)
                target = scope["context"]["target"]
                _require(target is None or target[0] == self.host_id)
                if scope["role"] == "current":
                    _require(scope["snapshot_id"] == self._snapshot_id)
                else:
                    _require(scope["adoption_revision"] <= self.revision)
                    if scope["adoption_revision"] == self.revision:
                        _require(scope["snapshot_id"] == self._snapshot_id)
                key = (scope["role"], scope["stable_id"], scope["context"]["check"]["id"])
                _require(key not in seen)
                seen.add(key)
                _require(row.observation is None or row.observation.observed_at == self.observed_at)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
            raise EndpointCollectionError("invalid_endpoint_check_batch") from None

    def matches_context(self, *, host_id, revision, snapshot_id):
        """The caller supplies fresh trusted store context; this performs no I/O."""
        return (type(revision) is int and self.host_id == host_id and self.revision == revision
                and self._snapshot_id == snapshot_id)

    @property
    def functional_result(self):
        return "unverified"

    @property
    def limitations(self):
        return (*LIMITATIONS, "time_bounded_observation_not_atomic_host_snapshot")

    def as_dict(self):
        return {"host_id": self.host_id, "revision": self.revision, "observed_at": self.observed_at,
                "checks": [row.as_dict() for row in self.checks], "probe_count": self.probe_count,
                "coverage_complete": True, "functional_result": self.functional_result, "executable": False,
                "limitations": list(self.limitations)}


def _current(store, revision, snapshot_id):
    try:
        current = store.current()
    except StoreError:
        raise EndpointCollectionError("endpoint_store_unavailable") from None
    if current["revision"] != revision or current["snapshot_id"] != snapshot_id:
        raise EndpointCollectionError("endpoint_revision_changed")
    return current


def _scopes(current, model, aliases):
    scopes, total = [], 0

    def append(check, resource, *, role, snapshot_id, record=None):
        nonlocal total
        if check["kind"] != "endpoint":
            return
        context = _context(check, resource, current["host_id"], aliases)
        if record is not None and context["target"] != record["physical_key"]:
            raise EndpointCollectionError("endpoint_store_unavailable")
        scope = {"role": role, "snapshot_id": snapshot_id, "context": context,
                 "stable_id": record["stable_id"] if record else None,
                 "adoption_revision": record["accepted_checks"]["adoption_revision"] if record else None,
                 "management": record["management"] if record else None}
        raw = canonical_json(scope)
        total += len(raw)
        if len(scopes) >= MAX_CHECKS or total > MAX_MANIFEST_BYTES:
            raise EndpointCollectionError("endpoint_coverage_limit")
        _decode_scope(raw)
        scopes.append(raw)

    # Retained obligations get first access to the bounded probe budget. Their
    # rows remain explicit even after removal, relinquishment or logical rename.
    for record in current["resources"]:
        for check in record["accepted_checks"]["definitions"]:
            append(check, record["definition"], role="accepted",
                   snapshot_id=record["accepted_checks"]["snapshot_id"], record=record)
    checks = {check["id"]: check for check in model["checks"]}
    for resource in model["resources"]:
        for name in resource["checks"]:
            append(checks[name], resource, role="current", snapshot_id=current["snapshot_id"])
    return scopes


def collect_endpoint_checks(store, *, revision, snapshot_id, budget_seconds=60,
                            max_probes=64, runner=None):
    """Explicitly probe required current/retained routes from an actual store.

    The budget bounds network scheduling, not trusted local history I/O or
    kernel cleanup. Only full original per-check timeouts are scheduled.
    Injected runners are trusted and must honor their own deadline/cancellation.
    """
    if (type(store) is not HostStore or type(revision) is not int or not 0 < revision < 2**63
            or type(snapshot_id) is not str or not _HASH.fullmatch(snapshot_id)
            or type(budget_seconds) is not int or not 1 <= budget_seconds <= 300
            or type(max_probes) is not int or not 1 <= max_probes <= 256
            or (runner is not None and not callable(runner))):
        raise EndpointCollectionError("invalid_endpoint_collection_request")
    deadline = time.monotonic() + budget_seconds
    when = utc_now()
    current = _current(store, revision, snapshot_id)
    try:
        aliases = store.engine_aliases
        model = store.snapshot(snapshot_id).model
        scopes = _scopes(current, model, aliases)
    except StoreError:
        raise EndpointCollectionError("endpoint_store_unavailable") from None
    except EndpointCollectionError:
        raise
    except (DeclarationError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise EndpointCollectionError("invalid_endpoint_collection_context") from None
    cache, rows, count = {}, [], 0
    for raw in scopes:
        scope = json.loads(raw)
        context = scope["context"]
        key = canonical_json({name: context[name] for name in ("check", "target")})
        if key not in cache:
            observation, reason = None, None
            started = time.monotonic()
            if context["target"] is None:
                reason = "physical_identity_unbound"
            elif count >= max_probes:
                reason = "collection_probe_limit"
            elif deadline - started < context["check"]["timeout_seconds"]:
                reason = "collection_budget_exhausted"
            else:
                count += 1
                try:
                    observation = observe_endpoint(context["check"], context["resource"],
                                                   host_id=current["host_id"], engine_aliases=aliases,
                                                   observed_at=when, runner=runner)
                except EndpointError as error:
                    reason = error.code if error.code in _UNAVAILABLE else "invalid_endpoint_result"
                finished = time.monotonic()
                if finished >= deadline:
                    observation, reason = None, "collection_budget_exhausted"
                elif finished - started >= context["check"]["timeout_seconds"]:
                    observation, reason = None, "collection_probe_timeout"
            cache[key] = observation, reason
        rows.append(EndpointCheckResult(raw, *cache[key]))
    _current(store, revision, snapshot_id)
    return EndpointCheckBatch(current["host_id"], revision, snapshot_id, when, tuple(rows), count)
