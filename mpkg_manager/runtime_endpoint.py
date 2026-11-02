"""Attribute bounded loopback status probes to a stable selected runtime."""
from dataclasses import dataclass, field
import json
import posixpath
import re
import time

from ._endpoint_process import PROBE_CODES, ProbeResult, run_probe
from ._endpoint_worker import validate_request
from ._runtime_proc import MAX_PROCESSES, ProcReader, ProcUnavailable
from .declarations import canonical_json, validate_model
from .observe_compose import DOCKER, ENVIRONMENT as DOCKER_ENVIRONMENT, ENGINE_QUERY
from .observe_endpoint import _binding as endpoint_binding, _validate_binding
from .observe_native import ENVIRONMENT, LONG_RUNNING_TYPES
from .observations import utc_now, validate_context
from .query_process import QueryResult, run_bounded


SERVICE_FIELDS = ("LoadState", "ActiveState", "SubState", "Type", "MainPID",
                  "InvocationID", "ControlGroup", "TriggeredBy")
SERVICE_QUERY = ("/usr/bin/systemctl", "show", "--no-pager",
                 *("--property=" + key for key in SERVICE_FIELDS), "--")
LIST_QUERY = DOCKER + ("container", "ls", "--all", "--quiet", "--no-trunc", "--filter")
_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,254}\Z")
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}\Z")
_OBJECT = re.compile(r"[0-9a-f]{64}\Z")
_FORMAT = '{"id":{{json .Id}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},' \
    '"status":{{json .State.Status}},"started_at":{{json .State.StartedAt}},' \
    '"network_mode":{{json .HostConfig.NetworkMode}},' \
    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},' \
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},' \
    '"oneoff":{{json (index .Config.Labels "com.docker.compose.oneoff")}}}'
INSPECT_QUERY = DOCKER + ("container", "inspect", "--format", _FORMAT, "--")
TOP_QUERY = DOCKER + ("container", "top")
MAX_OUTPUT = 64 * 1024
MAX_TOTAL_OUTPUT = 1024 * 1024
MAX_QUERIES = 32
LIMITATIONS = (
    "time_bounded_observation_not_atomic_runtime_snapshot",
    "kernel_proc_reads_have_size_bounds_not_preemptible_deadlines",
    "ipv4_loopback_in_collector_network_namespace_only",
    "native_main_process_or_single_host_network_compose_service_only",
    "shared_socket_descriptor_holders_not_exhaustively_enumerated",
    "runtime_ownership_not_application_authentication_or_functional_health",
    "no_management_or_application_authority_inferred",
)
_RUNTIME_CODES = {
    "runtime_unavailable", "runtime_query_unavailable", "runtime_query_malformed",
    "runtime_query_timeout", "runtime_inspection_limit", "runtime_budget_exhausted",
    "runtime_process_unavailable", "runtime_process_malformed", "runtime_changed",
    "runtime_listener_table_unavailable", "runtime_listener_table_malformed",
    "runtime_ipv6_listener_unsupported", "runtime_listener_unavailable",
    "runtime_listener_unattributed", "runtime_namespace_unsupported",
    "runtime_scope_unsupported", "runtime_socket_activation_unsupported",
    "runtime_service_unavailable", "runtime_engine_mismatch",
    "runtime_container_ambiguous", "runtime_container_unavailable",
    "runtime_network_unsupported", "runtime_probe_failed",
}


class RuntimeEndpointError(ValueError):
    def __init__(self, code="invalid_runtime_endpoint_context"):
        self.code = code
        super().__init__(code)


class _Unavailable(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _binding(check, resource, host_id, aliases):
    try:
        endpoint = json.loads(endpoint_binding(check, resource, host_id, aliases))
        selected = []
        if endpoint["target"][1] == "compose":
            normalized = validate_model({"schema": 1, "components": [], "resources": [{
                "id": resource["id"], "kind": resource["kind"], "identity": resource["identity"],
                "desired": {"services": resource.get("desired", {}).get("services", [])}}]})
            selected = normalized["resources"][0]["desired"]["services"]
        return canonical_json({"endpoint": endpoint, "services": selected})
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise RuntimeEndpointError() from None


def _decode_binding(raw):
    try:
        if type(raw) is not bytes or len(raw) > 32768:
            raise ValueError
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {"endpoint", "services"} or canonical_json(value) != raw:
            raise ValueError
        context = _validate_binding(canonical_json(value["endpoint"]))
        services = value["services"]
        if (type(services) is not list or len(services) > 64
                or any(type(name) is not str or not _NAME.fullmatch(name) for name in services)
                or len(set(services)) != len(services)
                or (context["target"][1] != "compose" and services)):
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise RuntimeEndpointError("invalid_runtime_endpoint_evidence") from None


@dataclass(frozen=True)
class AttributedEndpointObservation:
    """Trusted-library evidence; public JSON is never a runtime attestation."""
    _binding: bytes = field(repr=False)
    observed_at: str
    attribution: str
    route_result: str
    reason: str

    def __post_init__(self):
        try:
            context = _decode_binding(self._binding)
            validate_context(context["endpoint"]["target"][0], self.observed_at)
            if self.attribution == "verified":
                valid = {"match": {"status_matches"}, "mismatch": {"status_differs"},
                         "unavailable": PROBE_CODES - {"ok"} | {"runtime_probe_failed"}}
            elif self.attribution == "unavailable":
                valid = {"not_observed": _RUNTIME_CODES, "unavailable": _RUNTIME_CODES}
            else:
                raise ValueError
            if self.route_result not in valid or self.reason not in valid[self.route_result]:
                raise ValueError
        except (ValueError, TypeError, KeyError):
            raise RuntimeEndpointError("invalid_runtime_endpoint_evidence") from None

    def matches_context(self, check, resource, *, host_id, engine_aliases=None):
        try:
            return self._binding == _binding(check, resource, host_id,
                                             {} if engine_aliases is None else engine_aliases)
        except RuntimeEndpointError:
            return False

    def as_dict(self):
        context = _decode_binding(self._binding)["endpoint"]
        return {"host_id": context["target"][0], "observed_at": self.observed_at,
                "check_id": context["check"]["id"], "resource_id": context["check"]["resource"],
                "resource_kind": context["target"][1], "attribution": self.attribution,
                "route_result": self.route_result, "reason": self.reason,
                "functional_result": "unverified", "evidence_source": "runtime_attributed_loopback_status",
                "limitations": list(LIMITATIONS)}


def _allowed_query(argv):
    if argv == ENGINE_QUERY:
        return True
    if (len(argv) == len(SERVICE_QUERY) + 1 and argv[:-1] == SERVICE_QUERY
            and _NAME.fullmatch(argv[-1]) and argv[-1].endswith(".service")):
        return True
    if len(argv) == len(LIST_QUERY) + 3 and argv[:len(LIST_QUERY)] == LIST_QUERY:
        project, flag, service = argv[-3:]
        return (flag == "--filter" and project.startswith("label=com.docker.compose.project=")
                and service.startswith("label=com.docker.compose.service=")
                and bool(_PROJECT.fullmatch(project.removeprefix("label=com.docker.compose.project=")))
                and bool(_NAME.fullmatch(service.removeprefix("label=com.docker.compose.service="))))
    if len(argv) == len(INSPECT_QUERY) + 1 and argv[:-1] == INSPECT_QUERY:
        return bool(_OBJECT.fullmatch(argv[-1]))
    return (len(argv) == len(TOP_QUERY) + 3 and argv[:len(TOP_QUERY)] == TOP_QUERY
            and bool(_OBJECT.fullmatch(argv[-3])) and argv[-2:] == ("-eo", "pid"))


def run_readonly(argv, *, timeout, max_output=MAX_OUTPUT):
    """Only selected manager/runtime fields, never caller-selected commands."""
    if type(argv) is not tuple or any(type(item) is not str for item in argv) or not _allowed_query(argv):
        return QueryResult("invalid_query")
    return run_bounded(argv, environment=DOCKER_ENVIRONMENT if argv[:len(DOCKER)] == DOCKER else ENVIRONMENT,
                       timeout=timeout, max_output=max_output)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))


class _Collector:
    def __init__(self, seconds, runner, proc):
        self.deadline = time.monotonic() + seconds
        self.runner, self.proc = runner, proc
        self.count, self.bytes = 0, 0

    def guard(self):
        if time.monotonic() >= self.deadline:
            raise _Unavailable("runtime_budget_exhausted")

    def query(self, argv):
        self.guard()
        self.count += 1
        if self.count > MAX_QUERIES:
            raise _Unavailable("runtime_inspection_limit")
        timeout = min(5, self.deadline - time.monotonic())
        deadline = time.monotonic() + timeout
        result = self.runner(argv, timeout=timeout, max_output=MAX_OUTPUT)
        self.guard()
        if time.monotonic() >= deadline:
            raise _Unavailable("runtime_query_timeout")
        if type(result) is not QueryResult or result.code != "ok" or type(result.output) is not bytes:
            raise _Unavailable("runtime_query_unavailable")
        self.bytes += len(result.output)
        if len(result.output) > MAX_OUTPUT or self.bytes > MAX_TOTAL_OUTPUT:
            raise _Unavailable("runtime_inspection_limit")
        return result.output

    def runtime(self, context):
        endpoint, services = context["endpoint"], context["services"]
        host, kind, accepted, name = endpoint["target"]
        if kind == "service":
            fields = {}
            for line in self.query(SERVICE_QUERY + (name,)).decode("utf-8").splitlines():
                key, separator, value = line.partition("=")
                if not separator or key not in SERVICE_FIELDS or key in fields:
                    raise ValueError
                fields[key] = value
            if set(fields) != set(SERVICE_FIELDS):
                raise ValueError
            if fields["TriggeredBy"]:
                raise _Unavailable("runtime_socket_activation_unsupported")
            if (fields["LoadState"] != "loaded" or fields["ActiveState"] != "active"
                    or fields["SubState"] != "running" or fields["Type"] not in LONG_RUNNING_TYPES):
                raise _Unavailable("runtime_service_unavailable")
            if (not re.fullmatch(r"[1-9][0-9]{0,9}", fields["MainPID"])
                    or not int(fields["MainPID"]) < 2**31
                    or not re.fullmatch(r"[0-9a-f]{32}", fields["InvocationID"])
                    or fields["InvocationID"] == "0" * 32):
                raise ValueError
            group = fields["ControlGroup"]
            if (not group.startswith("/") or group.startswith("//") or group == "/"
                    or len(group) > 4096 or posixpath.normpath(group) != group
                    or any(ord(char) < 32 or ord(char) == 127 for char in group)):
                raise ValueError
            return canonical_json(fields), (int(fields["MainPID"]),), group
        if len(services) != 1:
            raise _Unavailable("runtime_scope_unsupported")
        if _json(self.query(ENGINE_QUERY)) != accepted:
            raise _Unavailable("runtime_engine_mismatch")
        ids = self.query(LIST_QUERY + ("label=com.docker.compose.project=" + name, "--filter",
                                      "label=com.docker.compose.service=" + services[0])).decode("ascii").splitlines()
        if len(ids) != 1:
            raise _Unavailable("runtime_container_ambiguous")
        if not _OBJECT.fullmatch(ids[0]):
            raise ValueError
        data = _json(self.query(INSPECT_QUERY + (ids[0],)))
        if (type(data) is not dict or set(data) != {"id", "pid", "running", "status", "started_at",
                "network_mode", "project", "service", "oneoff"}
                or data["id"] != ids[0] or data["project"] != name or data["service"] != services[0]
                or data["oneoff"] not in ("False", "false")
                or type(data["pid"]) is not int or not 0 < data["pid"] < 2**31
                or type(data["running"]) is not bool
                or type(data["started_at"]) is not str
                or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
                                    data["started_at"])):
            raise ValueError
        if data["running"] is not True or data["status"] != "running":
            raise _Unavailable("runtime_container_unavailable")
        if data["network_mode"] != "host":
            raise _Unavailable("runtime_network_unsupported")
        lines = self.query(TOP_QUERY + (ids[0], "-eo", "pid")).decode("ascii").splitlines()
        if not lines or lines[0].strip() != "PID" or not 1 <= len(lines) - 1 <= MAX_PROCESSES:
            raise ValueError
        pids = []
        for line in lines[1:]:
            if not re.fullmatch(r"\s*[1-9][0-9]{0,9}\s*", line) or not 0 < int(line) < 2**31:
                raise ValueError
            pids.append(int(line))
        if len(set(pids)) != len(pids) or data["pid"] not in pids:
            raise ValueError
        return canonical_json(data), tuple(sorted(pids)), None

    def capture(self, context, port):
        runtime = self.runtime(context)
        snapshot = self.proc.capture(runtime[1], port, self.guard)
        if runtime[2] is not None:
            # V1 binds native MainPID to the manager's unified cgroup as well.
            cgroup = snapshot[0][0][0][-1].decode("ascii").splitlines()
            expected = "0::" + runtime[2]
            if not any(line == expected or line.startswith(expected + "/") for line in cgroup):
                raise _Unavailable("runtime_process_unavailable")
        if self.runtime(context) != runtime:
            raise _Unavailable("runtime_changed")
        self.guard()
        return runtime, snapshot


def observe_attributed_endpoint(check, resource, *, host_id, engine_aliases=None,
                                observed_at=None, budget_seconds=60, query_runner=None,
                                proc_reader=None, probe_runner=None):
    """Inspect one exact endpoint; all seams are trusted library/test inputs.

    No PID, process name, executable, environment or command is a request
    parameter. The installed embedding must supply accepted host/engine
    identity and execute in the host network/user namespaces.
    """
    when = utc_now() if observed_at is None else observed_at
    try:
        validate_context(host_id, when)
        if (type(budget_seconds) is not int or not 1 <= budget_seconds <= 300
                or any(runner is not None and not callable(runner) for runner in (query_runner, probe_runner))
                or (proc_reader is not None and not callable(getattr(proc_reader, "capture", None)))):
            raise ValueError
        raw = _binding(check, resource, host_id, {} if engine_aliases is None else engine_aliases)
        context = _decode_binding(raw)
        normalized = context["endpoint"]["check"]
        _, host, port, _, timeout = validate_request({"url": normalized["url"],
                                                     "timeout_seconds": normalized["timeout_seconds"]})
    except (ValueError, TypeError, KeyError, AttributeError):
        raise RuntimeEndpointError() from None

    def result(attribution, route, reason):
        return AttributedEndpointObservation(raw, when, attribution, route, reason)

    if host == "::1" or (context["endpoint"]["target"][1] == "compose" and len(context["services"]) != 1):
        return result("unavailable", "not_observed", "runtime_scope_unsupported")
    collector = _Collector(budget_seconds, run_readonly if query_runner is None else query_runner,
                           ProcReader() if proc_reader is None else proc_reader)
    probed = False
    try:
        before = collector.capture(context, port)
        if collector.deadline - time.monotonic() < timeout:
            raise _Unavailable("runtime_budget_exhausted")
        started = time.monotonic()
        probed = True
        try:
            probe = (run_probe if probe_runner is None else probe_runner)(normalized["url"], timeout)
            if type(probe) is not ProbeResult:
                raise ValueError
            probe = ProbeResult(probe.code, probe.status)
        except Exception:
            probe = None
        collector.guard()
        if time.monotonic() - started >= timeout:
            probe = ProbeResult("timeout")
        if collector.capture(context, port) != before:
            raise _Unavailable("runtime_changed")
        if probe is None:
            return result("verified", "unavailable", "runtime_probe_failed")
        if probe.code != "ok":
            return result("verified", "unavailable", probe.code)
        matches = probe.status == normalized["expected_status"]
        return result("verified", "match" if matches else "mismatch",
                      "status_matches" if matches else "status_differs")
    except (ProcUnavailable, _Unavailable) as error:
        code = error.code if error.code in _RUNTIME_CODES else "runtime_unavailable"
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, IndexError, OverflowError):
        code = "runtime_query_malformed"
    except Exception:
        code = "runtime_unavailable"
    return result("unavailable", "unavailable" if probed else "not_observed", code)
