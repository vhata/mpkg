"""Version-bound application predicates for trusted current/retained roles.

This library has no installed request or declaration extension. Its caller
must independently bind predicates to accepted history; JSON is not authority.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

from . import runtime_endpoint as runtime
from ._endpoint_process import run_probe
from ._runtime_proc import MAX_PROCESSES
from .declarations import canonical_json
from .runtime_checks import RuntimeCheckManifest, _decode_scope

VERSIONS = {"sonarr": ("4.0.20.3014", "sha256:076be80fcab2bd0acdea4c8c5f604318f2feb61aeeaacd71cfcb1983a8fb50bf"),
            "radarr": ("6.4.4.10685", "sha256:a9b08c177649ae4e2c03f4ab375140ac8e633f87a781eeaa7a0e7f1e85b112a8")}
FORMAT = runtime._FORMAT[:-1] + ',"image":{{json .Image}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}}}'
INSPECT = runtime.DOCKER + ("container", "inspect", "--format", FORMAT, "--")


def _require(condition):
    if not condition:
        raise ValueError


@dataclass(frozen=True)
class ApplicationPredicate:
    application: str
    version: str
    port: int
    base: str = ""
    root_id: int = 0
    root_path: str = ""
    sentinel: str = ""

    def __post_init__(self):
        try:
            _require(self.application in VERSIONS and self.version == VERSIONS[self.application][0])
            _require(type(self.port) is int and 1 <= self.port <= 65535)
            _require(type(self.base) is str and re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*", self.base))
            if self.application == "sonarr":
                _require((self.root_id, self.root_path, self.sentinel) == (0, "", ""))
            else:
                _require(type(self.root_id) is int and 0 < self.root_id < 2**31)
                _require(re.fullmatch(r"/(?:[A-Za-z0-9 _.-]+/)*[A-Za-z0-9 _.-]+", self.root_path))
                _require(all(part not in (".", "..") for part in self.root_path.split("/")))
                _require(re.fullmatch(r"[A-Za-z0-9 _().-]{1,255}", self.sentinel))
                _require(self.sentinel not in (".", ".."))
            _require(len(canonical_json(asdict(self))) < 8192)
        except (ValueError, TypeError, KeyError):
            raise ValueError("invalid_application_predicate") from None


@dataclass(frozen=True)
class ApplicationObservation:
    _binding: bytes = field(repr=False)
    functional_result: str
    route_result: str
    reason: str
    observed_at: str

    def __post_init__(self):
        if (self.functional_result not in ("passed", "failed", "unavailable")
                or self.route_result not in ("match", "mismatch", "unavailable", "not_observed")
                or self.reason not in ("application_unavailable", "context_changed", "predicate_mismatch", "predicate_observed")):
            raise ValueError("invalid_application_observation")
        runtime.validate_context(json.loads(self._binding)["host"], self.observed_at)

    def as_dict(self):
        return {"functional_result": self.functional_result, "route_result": self.route_result,
                "reason": self.reason, "observed_at": self.observed_at, "executable": False,
                "limitations": ["bounded_observation_not_atomic_snapshot",
                                "selected_predicate_only_not_general_application_health"]}

    def matches(self, manifest, scope, predicate, *, now=None, max_age_seconds=60):
        when = datetime.now(timezone.utc) if now is None else now
        age = (when - datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))).total_seconds()
        return (type(max_age_seconds) is int and 0 <= max_age_seconds <= 300
                and 0 <= age <= max_age_seconds
                and self._binding == _binding(manifest, scope, predicate))


def _binding(manifest, scope, predicate):
    if type(manifest) is not RuntimeCheckManifest or type(predicate) is not ApplicationPredicate:
        raise ValueError("invalid_application_context")
    manifest.__post_init__()
    predicate.__post_init__()
    if scope not in manifest._scopes:
        raise ValueError("invalid_application_context")
    return canonical_json({"host": manifest.host_id, "revision": manifest.revision,
                           "snapshot": manifest._snapshot_id, "selection": None if manifest._selection is None else list(manifest._selection),
                           "scope": json.loads(scope), "predicate": asdict(predicate)})


def run_readonly(argv, *, timeout, max_output):
    if argv[:-1] == INSPECT and runtime._OBJECT.fullmatch(argv[-1]):
        return runtime.run_bounded(argv, environment=runtime.DOCKER_ENVIRONMENT,
                                   timeout=timeout, max_output=max_output)
    return runtime.run_readonly(argv, timeout=timeout, max_output=max_output)


class _Runtime(runtime._Collector):
    def capture_application(self, context, predicate):
        target = context["target"]
        services = context["resource"]["desired"]["services"]
        if len(services) != 1 or runtime._json(self.query(runtime.ENGINE_QUERY)) != target[2]:
            raise ValueError
        ids = self.query(runtime.LIST_QUERY + ("label=com.docker.compose.project=" + target[3],
                        "--filter", "label=com.docker.compose.service=" + services[0])).decode().splitlines()
        if len(ids) != 1 or not runtime._OBJECT.fullmatch(ids[0]):
            raise ValueError
        data = runtime._json(self.query(INSPECT + (ids[0],)))
        if (data["id"] != ids[0] or data["project"] != target[3] or data["service"] != services[0]
                or data["oneoff"] not in ("False", "false") or data["running"] is not True
                or data["status"] != "running" or data["image"] != VERSIONS[predicate.application][1]
                or type(data["pid"]) is not int or not 0 < data["pid"] < 2**31
                or not re.fullmatch(r"[0-9T:.Z-]{20,40}", data["started_at"])):
            raise ValueError
        mode = data["network_mode"]
        if mode != "host":
            if (mode in ("none", "default") or mode.startswith("container:")
                    or not isinstance(data["networks"], dict) or not data["networks"]):
                raise ValueError
            for network in data["networks"].values():
                if not runtime._OBJECT.fullmatch(network["NetworkID"]) or not runtime._OBJECT.fullmatch(network["EndpointID"]):
                    raise ValueError
        lines = self.query(runtime.TOP_QUERY + (ids[0], "-eo", "pid")).decode().splitlines()
        if not lines or lines[0].strip() != "PID" or not 1 <= len(lines)-1 <= MAX_PROCESSES:
            raise ValueError
        pids = tuple(sorted(int(row) for row in lines[1:]))
        if len(set(pids)) != len(pids) or data["pid"] not in pids or any(not 0 < pid < 2**31 for pid in pids):
            raise ValueError
        return data, pids


@contextmanager
def hold_namespace(pid):
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        yield fd, (info.st_dev, info.st_ino)
    finally:
        os.close(fd)


def run_application(data, key, namespace):
    fd, identity = namespace
    request = dict(data, key=key, namespace_fd=fd, namespace=identity)
    raw = json.dumps(request, separators=(",", ":")).encode("ascii")
    if len(raw) > 16384:
        return "unavailable"
    process = subprocess.Popen((sys.executable, "-I", str(Path(__file__).with_name("_application_worker.py"))),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env={"PATH": "/usr/bin", "LC_ALL": "C"}, pass_fds=(fd,), start_new_session=True)
    try:
        output, _ = process.communicate(raw, timeout=data["timeout"])
        value = json.loads(output) if len(output) < 256 and process.returncode == 0 else {}
        result = value.get("functional_result")
        return result if result in ("passed", "failed", "unavailable") else "unavailable"
    except Exception:
        return "unavailable"
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout):
            stream.close()


def published_route(application, url, timeout):
    if application == "sonarr":
        probe = run_probe(url, timeout)
        return "match" if probe.code == "ok" and probe.status == 200 else "unavailable"
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    with socket.create_connection(("127.0.0.1", parsed.port or 80), timeout=timeout):
        return "match"


def observe_application(manifest, scope, predicate, *, context_guard, credential=None,
                        query_runner=None, namespace_holder=hold_namespace,
                        application_runner=run_application, route_runner=published_route):
    """Observe an independently accepted original role and versioned predicate.

    context_guard must rederive history AND this predicate's accepted binding.
    All callbacks are trusted embedding seams, never public request options.
    """
    raw = _binding(manifest, scope, predicate)
    when = runtime.utc_now()
    role = _decode_scope(scope, manifest.host_id)
    context = role["context"]
    def result(functional="unavailable", route="not_observed", reason="application_unavailable"):
        return ApplicationObservation(raw, functional, route, reason, when)
    if not role["selected"] or context["target"] is None or context["resource"]["kind"] != "compose" or context["check"]["kind"] != "endpoint":
        return result()
    check = context["check"]
    from urllib.parse import urlsplit
    url = urlsplit(check["url"])
    timeout = check["timeout_seconds"]
    if (url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost")
            or not 1 <= timeout <= 10 or check["expected_status"] != 200
            or url.path != predicate.base + ("/ping" if predicate.application == "sonarr" else
                    f"/api/v3/rootfolder/{predicate.root_id}")
            or url.query):
        return result(reason="predicate_mismatch")
    collector = _Runtime(60, query_runner or run_readonly, None)
    try:
        if context_guard(manifest, scope, predicate) is not True:
            return result(reason="context_changed")
        before = collector.capture_application(context, predicate)
        data, pids = before
        route_port = url.port or 80
        if data["network_mode"] == "host":
            if route_port != predicate.port:
                raise ValueError
        elif data["ports"].get(f"{predicate.port}/tcp") != [{"HostIp": "127.0.0.1", "HostPort": str(route_port)}]:
            raise ValueError
        with namespace_holder(data["pid"]) as namespace:
            if collector.capture_application(context, predicate) != before:
                raise ValueError
            # Key resolution stays private; only the namespace worker sends it.
            key = "" if predicate.application == "sonarr" else credential()
            if predicate.application == "radarr" and (type(key) is not str or not re.fullmatch(r"[A-Za-z0-9]{1,256}", key)):
                raise ValueError
            if context_guard(manifest, scope, predicate) is not True:
                return result(reason="context_changed")
            started = time.monotonic()
            functional = application_runner(dict(asdict(predicate), timeout=timeout, pids=pids), key, namespace)
            if time.monotonic() - started >= timeout or functional not in ("passed", "failed", "unavailable"):
                functional = "unavailable"
            if collector.capture_application(context, predicate) != before:
                raise ValueError
            started = time.monotonic()
            try:
                route = route_runner(predicate.application, check["url"], timeout)
            except Exception:
                route = "unavailable"
            if time.monotonic() - started >= timeout or route not in ("match", "mismatch", "unavailable"):
                route = "unavailable"
            if collector.capture_application(context, predicate) != before:
                raise ValueError
            collector.guard()
            if context_guard(manifest, scope, predicate) is not True:
                return result(reason="context_changed")
            return result(functional, route, "predicate_observed")
    except Exception:
        return result()
