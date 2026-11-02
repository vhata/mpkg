"""Closed loopback route observations, never attributed application health."""
from dataclasses import dataclass, field
import json

from .declarations import DeclarationError, canonical_json, physical_key, validate_model
from .observations import utc_now, validate_context
from ._endpoint_process import PROBE_CODES, ProbeResult, run_probe
from ._endpoint_worker import _ProbeFailure, validate_request


LIMITATIONS = ("listener_attribution_unavailable", "application_identity_unverified")
_MAX_BINDING = 16 * 1024


class EndpointError(ValueError):
    """A fixed diagnostic with no URL, target values or response text."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _binding(check, resource, host_id, aliases):
    try:
        if type(check) is not dict or type(resource) is not dict:
            raise ValueError
        if type(aliases) is not dict or any(type(k) is not str or type(v) is not str
                                           or not v or len(v) > 255 or "\0" in v
                                           for k, v in aliases.items()):
            raise ValueError
        minimal = {key: resource[key] for key in ("id", "kind", "identity")}
        minimal["checks"] = [check["id"]]
        model = validate_model({"schema": 1, "components": [], "resources": [minimal], "checks": [check]})
        normalized = model["checks"][0]
        if normalized["kind"] != "endpoint":
            raise ValueError
        validate_request({"url": normalized["url"], "timeout_seconds": normalized["timeout_seconds"]})
        target = list(physical_key(model["resources"][0], host_id, aliases))
        encoded = canonical_json({"check": normalized, "target": target})
        if len(encoded) > _MAX_BINDING:
            raise ValueError
        return encoded
    except (DeclarationError, _ProbeFailure, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise EndpointError("invalid_endpoint_context") from None


def _validate_binding(raw):
    try:
        if type(raw) is not bytes or len(raw) > _MAX_BINDING:
            raise ValueError
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {"check", "target"} or canonical_json(value) != raw:
            raise ValueError
        check, target = value["check"], value["target"]
        if type(target) is not list or len(target) != 4 or any(type(item) is not str for item in target):
            raise ValueError
        host, kind, first, second = target
        if kind == "service":
            identity, aliases = {"manager": first, "unit": second}, {}
        elif kind == "compose":
            identity, aliases = {"engine": "accepted", "project": second}, {"accepted": first}
        else:
            raise ValueError
        resource = {"id": check["resource"], "kind": kind, "identity": identity}
        if _binding(check, resource, host, aliases) != raw:
            raise ValueError
        return value
    except (EndpointError, DeclarationError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise EndpointError("invalid_endpoint_observation") from None


@dataclass(frozen=True)
class EndpointObservation:
    """Immutable trusted evidence; public projection is not import authority."""
    _binding: bytes = field(repr=False)
    observed_at: str
    route_result: str
    reason: str

    def __post_init__(self):
        context = _validate_binding(self._binding)
        try:
            validate_context(context["target"][0], self.observed_at)
        except ValueError:
            raise EndpointError("invalid_endpoint_observation") from None
        allowed = {"match": {"status_matches"}, "mismatch": {"status_differs"},
                   "unavailable": PROBE_CODES - {"ok"}}
        if (type(self.route_result) is not str or self.route_result not in allowed
                or type(self.reason) is not str or self.reason not in allowed[self.route_result]):
            raise EndpointError("invalid_endpoint_observation")

    def matches_context(self, check, resource, *, host_id, engine_aliases=None):
        """Match the full predicate and accepted physical target, never just IDs."""
        try:
            return self._binding == _binding(check, resource, host_id,
                                             {} if engine_aliases is None else engine_aliases)
        except (EndpointError, AttributeError):
            return False

    @property
    def functional_result(self):
        return "unverified"

    @property
    def limitations(self):
        return LIMITATIONS

    def as_dict(self):
        context = json.loads(self._binding)
        return {"host_id": context["target"][0], "observed_at": self.observed_at,
                "check_id": context["check"]["id"], "resource_id": context["check"]["resource"],
                "resource_kind": context["target"][1], "route_result": self.route_result,
                "reason": self.reason, "functional_result": self.functional_result,
                "evidence_source": "loopback_http_status", "limitations": list(self.limitations)}


def observe_endpoint(check, resource, *, host_id, engine_aliases=None,
                     observed_at=None, runner=None):
    """Observe one route at collection-start time without verifying its owner.

    The embedding owns trusted host/alias context and any injected runner.
    The default runner executes only the built-in bounded endpoint worker.
    """
    when = utc_now() if observed_at is None else observed_at
    try:
        validate_context(host_id, when)
    except ValueError:
        raise EndpointError("invalid_endpoint_context") from None
    encoded = _binding(check, resource, host_id, {} if engine_aliases is None else engine_aliases)
    normalized = json.loads(encoded)["check"]
    try:
        result = (run_probe if runner is None else runner)(normalized["url"], normalized["timeout_seconds"])
    except Exception:
        raise EndpointError("endpoint_runner_failed") from None
    if type(result) is not ProbeResult:
        raise EndpointError("invalid_endpoint_result")
    # Revalidate exact-type results; frozen dataclasses are not a trust boundary.
    try:
        result = ProbeResult(result.code, result.status)
    except (ValueError, AttributeError):
        raise EndpointError("invalid_endpoint_result") from None
    if result.code != "ok":
        outcome, reason = "unavailable", result.code
    elif result.status == normalized["expected_status"]:
        outcome, reason = "match", "status_matches"
    else:
        outcome, reason = "mismatch", "status_differs"
    return EndpointObservation(encoded, when, outcome, reason)
