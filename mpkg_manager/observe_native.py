"""Read only direct installed-package and systemd service facts.

Fixed queries do not refresh sources, resolve providers, adopt resources or
change the host. Missing or unsupported evidence stays unknown.
"""
from dataclasses import dataclass, field
import math
import os
import re
import selectors
import signal
import subprocess
import time

from .observations import Observation, ObservationBatch, utc_now, validate_context


PACKAGE_VERSIONS = ("/usr/bin/pacman", "-Q")
PACKAGE_EXPLICIT = ("/usr/bin/pacman", "-Qqe")
SERVICE_FIELDS = ("LoadState", "ActiveState", "SubState", "UnitFileState", "Type",
                  "MainPID", "InvocationID", "ActiveEnterTimestampMonotonic")
SERVICE_QUERY = ("/usr/bin/systemctl", "show", "--no-pager",
                 *("--property=" + name for name in SERVICE_FIELDS), "--")
ENVIRONMENT = {"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C",
               "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"}
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+~\-]{0,254}\Z")
PACKAGE_PROPERTIES = ("present", "version", "install_reason", "source", "provider")
SERVICE_PROPERTIES = ("present", "running", "enabled", "load_state", "active_state",
                      "sub_state", "unit_file_state", "service_type", "main_pid")
LONG_RUNNING_TYPES = {"simple", "exec", "forking", "dbus", "notify", "notify-reload", "idle"}
RESULT_CODES = {"ok", "invalid_query", "tool_unavailable", "permission_denied",
                "start_failed", "command_failed", "timeout", "output_limit", "io_error"}


@dataclass(frozen=True)
class QueryResult:
    code: str
    output: bytes = field(default=b"", repr=False)
    returncode: int | None = None

    def __post_init__(self):
        if (self.code not in RESULT_CODES or type(self.output) is not bytes
                or (self.returncode is not None and type(self.returncode) is not int)):
            raise ValueError("invalid_query_result")
        if self.code != "ok" and self.output:
            raise ValueError("failed_query_has_output")


def _allowed_query(argv):
    if argv in (PACKAGE_VERSIONS, PACKAGE_EXPLICIT):
        return True
    return (len(argv) == len(SERVICE_QUERY) + 1 and argv[:-1] == SERVICE_QUERY
            and bool(NAME.fullmatch(argv[-1])) and argv[-1].endswith(".service"))


def _terminate_query(process):
    # The group can outlive its leader, so do not condition this on poll().
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        # A kernel-blocked child must not make cleanup unbounded.
        pass


def run_readonly(argv, *, timeout=10, max_output=1024 * 1024):
    """Run a closed query with one deadline and a combined stdout/stderr cap.

    Only stdout from a successful query is returned privately for parsing.
    Exceptions and stderr are never included in the public error code.
    """
    if (type(argv) is not tuple or any(type(arg) is not str for arg in argv)
            or not _allowed_query(argv)):
        return QueryResult("invalid_query")
    if (type(timeout) not in (float, int) or not math.isfinite(timeout)
            or not 0 < timeout <= 30 or type(max_output) is not int
            or not 0 < max_output <= 8 * 1024 * 1024):
        raise ValueError("invalid_query_bounds")
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=dict(ENVIRONMENT), close_fds=True,
                                   start_new_session=True)
    except FileNotFoundError:
        return QueryResult("tool_unavailable")
    except PermissionError:
        return QueryResult("permission_denied")
    except OSError:
        return QueryResult("start_failed")
    deadline = time.monotonic() + timeout
    chunks = []
    total = 0
    failure = None
    try:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, True)
                selector.register(process.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure = "timeout"
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > max_output:
                            failure = "output_limit"
                            break
                        if key.data:
                            chunks.append(chunk)
                    if failure:
                        break
                if not failure:
                    try:
                        process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        failure = "timeout"
        except OSError:
            failure = "io_error"
        if failure:
            _terminate_query(process)
    except BaseException:
        # Cancellation must stop descendants even if the leader was reaped.
        # Preserve the original exception if cleanup itself is interrupted.
        try:
            _terminate_query(process)
        except BaseException:
            pass
        raise
    finally:
        process.stdout.close()
        process.stderr.close()
    if failure:
        return QueryResult(failure, returncode=process.returncode)
    if process.returncode != 0:
        return QueryResult("command_failed", returncode=process.returncode)
    return QueryResult("ok", b"".join(chunks), process.returncode)


def _query(runner, argv):
    result = runner(argv)
    if not isinstance(result, QueryResult):
        raise ValueError("invalid_query_result")
    return result


def _package_snapshot(runner):
    snapshots = []
    for _ in range(2):
        versions = _query(runner, PACKAGE_VERSIONS)
        reasons = _query(runner, PACKAGE_EXPLICIT)
        for result in (versions, reasons):
            if result.code != "ok":
                return None, result.code
        try:
            installed = {}
            for line in versions.output.decode("utf-8").splitlines():
                fields = line.split(" ")
                if (len(fields) != 2 or not NAME.fullmatch(fields[0])
                        or not VERSION.fullmatch(fields[1]) or fields[0] in installed):
                    return None, "malformed_package_inventory"
                installed[fields[0]] = fields[1]
            explicit = reasons.output.decode("utf-8").splitlines()
        except UnicodeError:
            return None, "malformed_package_inventory"
        if (len(set(explicit)) != len(explicit) or any(not NAME.fullmatch(n) for n in explicit)
                or not set(explicit) <= installed.keys()):
            return None, "malformed_package_inventory"
        snapshots.append((installed, frozenset(explicit)))
    if snapshots[0] != snapshots[1]:
        return None, "package_inventory_changed"
    return snapshots[0], None


def _service_snapshot(unit, runner):
    snapshots = []
    for _ in range(2):
        result = _query(runner, SERVICE_QUERY + (unit,))
        if result.code != "ok":
            return None, result.code
        try:
            fields = {}
            for line in result.output.decode("utf-8").splitlines():
                name, separator, value = line.partition("=")
                if not separator or name not in SERVICE_FIELDS or name in fields:
                    return None, "malformed_service_properties"
                fields[name] = value
        except UnicodeError:
            return None, "malformed_service_properties"
        if set(fields) != set(SERVICE_FIELDS):
            return None, "service_properties_unavailable"
        choices = {"LoadState": {"loaded", "not-found", "masked", "error", "bad-setting", "stub", "merged"},
                   "ActiveState": {"active", "inactive", "failed", "activating", "deactivating", "reloading", "refreshing", "maintenance"},
                   "SubState": {"running", "dead", "exited", "failed", "start-pre", "start", "start-post", "stop", "stop-sigterm", "stop-sigkill", "stop-post", "final-sigterm", "final-sigkill", "auto-restart", "auto-restart-queued", "reload", "reload-signal", "reload-notify", "cleaning", "condition"},
                   "UnitFileState": {"", "enabled", "enabled-runtime", "disabled", "static", "indirect", "alias", "masked", "masked-runtime", "linked", "linked-runtime", "generated", "transient", "bad"},
                   "Type": LONG_RUNNING_TYPES | {"", "oneshot"}}
        if (any(fields[key] not in allowed for key, allowed in choices.items())
                or not re.fullmatch(r"[0-9]{1,10}", fields["MainPID"])
                or not re.fullmatch(r"[0-9]{1,20}", fields["ActiveEnterTimestampMonotonic"])
                or not re.fullmatch(r"(?:[0-9a-f]{32})?", fields["InvocationID"])):
            return None, "unsupported_service_properties"
        fields["MainPID"] = int(fields["MainPID"])
        snapshots.append(fields)
    if snapshots[0] != snapshots[1]:
        return None, "service_state_changed"
    return snapshots[0], None


def observe_resources(resources, *, host_id, runner=None, observed_at=None):
    """Observe validated package/service declarations without changing intent.

    Other resource kinds receive explicit unknown facts. This library has no
    privilege launcher and cannot turn a reference into mutation authority.
    """
    when = observed_at or utc_now()
    validate_context(host_id, when)
    runner = runner or run_readonly
    resources = list(resources)
    seen = set()
    for resource in resources:
        if (type(resource) is not dict or type(resource.get("id")) is not str
                or resource["id"] in seen or type(resource.get("identity")) is not dict
                or type(resource.get("kind")) is not str):
            raise ValueError("invalid_observation_resource")
        seen.add(resource["id"])
        if resource["kind"] == "package":
            if (set(resource["identity"]) != {"name"}
                    or type(resource["identity"]["name"]) is not str
                    or not NAME.fullmatch(resource["identity"]["name"])):
                raise ValueError("invalid_observation_resource")
        if resource["kind"] == "service":
            identity = resource["identity"]
            if (set(identity) != {"manager", "unit"} or identity["manager"] != "system"
                    or type(identity["unit"]) is not str or not NAME.fullmatch(identity["unit"])):
                raise ValueError("invalid_observation_resource")
    facts = []

    def add(resource, prop, state, value=None, *, reason=None, source):
        facts.append(Observation(host_id, resource["id"], resource["kind"], resource["identity"],
                                 prop, state, value, when, source, (reason,) if reason else ()))

    packages = [r for r in resources if r["kind"] == "package"]
    snapshot, error = _package_snapshot(runner) if packages else (None, None)
    for resource in packages:
        source = "pacman_installed_inventory"
        if error:
            for prop in PACKAGE_PROPERTIES:
                add(resource, prop, "unknown", reason=error, source=source)
            continue
        versions, explicit = snapshot
        name = resource["identity"]["name"]
        present = name in versions
        add(resource, "present", "known", present, source=source)
        add(resource, "version", "known" if present else "absent", versions.get(name), source=source)
        reason = ("explicit" if name in explicit else "dependency") if present else None
        add(resource, "install_reason", "known" if present else "absent", reason, source=source)
        add(resource, "source", "unknown", reason="package_provenance_not_observed", source=source)
        add(resource, "provider", "unknown", reason="package_request_resolution_not_observed", source=source)
    for resource in resources:
        if resource["kind"] == "package":
            continue
        source = "systemd_unit_properties"
        if resource["kind"] != "service":
            for prop in sorted({"present", *resource.get("desired", {})}):
                add(resource, prop, "unknown", reason="resource_kind_not_observed", source="unsupported_adapter")
            continue
        if not resource["identity"]["unit"].endswith(".service"):
            for prop in SERVICE_PROPERTIES:
                add(resource, prop, "unknown", reason="service_unit_type_unsupported",
                    source="unsupported_adapter")
            continue
        properties, error = _service_snapshot(resource["identity"]["unit"], runner)
        if error:
            for prop in SERVICE_PROPERTIES:
                add(resource, prop, "unknown", reason=error, source=source)
            continue
        present = properties["LoadState"] != "not-found"
        add(resource, "present", "known", present, source=source)
        for prop, key in (("load_state", "LoadState"), ("active_state", "ActiveState"),
                          ("sub_state", "SubState"), ("unit_file_state", "UnitFileState"),
                          ("service_type", "Type"), ("main_pid", "MainPID")):
            add(resource, prop, "known", properties[key], source=source)
        running = None
        if (properties["LoadState"] == "loaded" and properties["Type"] in LONG_RUNNING_TYPES
                and properties["ActiveState"] == "active" and properties["SubState"] == "running"
                and properties["MainPID"] > 0):
            running = True
        elif (properties["ActiveState"] in {"inactive", "failed"}
              and properties["SubState"] in {"dead", "failed"} and properties["MainPID"] == 0):
            running = False
        add(resource, "running", "known" if running is not None else "unknown", running,
            reason=None if running is not None else "service_running_semantics_unsupported", source=source)
        enabled = {"enabled": True, "disabled": False}.get(properties["UnitFileState"])
        add(resource, "enabled", "known" if enabled is not None else "unknown", enabled,
            reason=None if enabled is not None else "service_enablement_semantics_unsupported", source=source)
    return ObservationBatch(host_id, when, tuple(facts), tuple(r["id"] for r in resources),
                            ("time_bounded_observation_not_atomic_host_snapshot",
                             "direct_installed_names_not_package_request_satisfaction",
                             "service_state_not_functional_health",
                             "no_authority_or_provider_provenance_inferred"))
