"""Positive native dependency satisfaction, never provider or absence authority."""
import re

from .declarations import DeclarationError, validate_model
from .observations import Observation, ObservationBatch, utc_now, validate_context
from .query_process import QueryResult, run_bounded


MAX_RESOURCES = 256
MAX_OUTPUT = 128 * 1024
QUERY = ("/usr/bin/pacman", "-T", "--")
ENVIRONMENT = {"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C"}
SOURCE = "pacman_dependency_satisfaction"
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}\Z")
LIMITATIONS = ("time_bounded_observation_not_atomic_host_snapshot",
              "unmet_request_not_verified_absence",
              "provider_identity_version_reason_and_provenance_not_observed",
              "no_management_authority_inferred")


def run_readonly(argv):
    """Only an unversioned, bounded dependency-test query may be executed."""
    if (type(argv) is not tuple or not len(QUERY) < len(argv) <= len(QUERY) + MAX_RESOURCES
            or argv[:len(QUERY)] != QUERY
            or any(type(name) is not str or not _NAME.fullmatch(name) for name in argv[len(QUERY):])
            or len(set(argv[len(QUERY):])) != len(argv) - len(QUERY)):
        return QueryResult("invalid_query")
    return run_bounded(argv, environment=ENVIRONMENT, timeout=10, max_output=MAX_OUTPUT,
                       accepted_returncodes=(0, 127), require_empty_stderr=True)


def _sample(names, runner):
    try:
        result = runner(QUERY + names)
    except Exception:
        return None, "package_query_unavailable"
    if type(result) is not QueryResult:
        return None, "invalid_package_query_result"
    if result.code != "ok":
        return None, result.code
    if len(result.output) > MAX_OUTPUT:
        return None, "output_limit"
    # Match pacman's exact line protocol rather than accepting whitespace,
    # truncated final lines, duplicate rows or unrelated diagnostic content.
    if result.returncode == 0:
        return (frozenset(), None) if result.output == b"" else (None, "malformed_package_satisfaction")
    if result.returncode != 127 or not result.output.endswith(b"\n"):
        return None, "malformed_package_satisfaction"
    try:
        unmet = result.output[:-1].decode("ascii").split("\n")
    except UnicodeError:
        return None, "malformed_package_satisfaction"
    if len(set(unmet)) != len(unmet) or not set(unmet) <= set(names):
        return None, "malformed_package_satisfaction"
    return frozenset(unmet), None


def observe_package_requests(resources, *, host_id, observed_at=None, runner=None):
    """Observe positive unversioned satisfaction for validated package resources.

    Unmet requests remain unknown because native dependency testing cannot
    distinguish every incomplete database read from genuine absence. The
    trusted injected runner must enforce the same protocol and timing policy.
    """
    when = utc_now() if observed_at is None else observed_at
    validate_context(host_id, when)
    try:
        if type(resources) not in (list, tuple) or len(resources) > MAX_RESOURCES:
            raise ValueError
        if runner is not None and not callable(runner):
            raise ValueError
        checked, seen = [], set()
        for resource in resources:
            if type(resource) is not dict or resource.get("kind") != "package":
                raise ValueError
            minimal = {key: resource[key] for key in ("id", "kind", "identity")}
            validated = validate_model({"schema": 1, "components": [], "resources": [minimal]})["resources"][0]
            if validated["id"] in seen:
                raise ValueError
            seen.add(validated["id"])
            checked.append(validated)
    except (ValueError, TypeError, KeyError, AttributeError, DeclarationError, RecursionError):
        raise ValueError("invalid_package_observation_request") from None
    names = tuple(sorted({resource["identity"]["name"] for resource in checked}))
    unmet, error = frozenset(), None
    if names:
        runner = run_readonly if runner is None else runner
        first, error = _sample(names, runner)
        if error is None:
            unmet, error = _sample(names, runner)
            if error is None and first != unmet:
                error = "package_satisfaction_changed"
    facts = []
    for resource in checked:
        reason = error
        if reason is None and resource["identity"]["name"] in unmet:
            reason = "package_request_unsatisfied_or_database_unavailable"
        facts.append(Observation(host_id, resource["id"], "package", resource["identity"],
                                 "present", "unknown" if reason else "known",
                                 None if reason else True, when, SOURCE, (reason,) if reason else ()))
    return ObservationBatch(host_id, when, tuple(facts), tuple(resource["id"] for resource in checked),
                            LIMITATIONS)
