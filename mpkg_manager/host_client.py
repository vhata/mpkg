"""Unprivileged, fixed transport to the installed host helper.

There are no caller-selected programs, paths, environments or root imports.
Tests replace the private sender; that seam is never a command-line option.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
import re
import selectors
import signal
import subprocess
import time
import uuid

from .host_protocol import MAX_RESPONSE_BYTES, PROTOCOL_VERSION, parse_request
from .status_wire import validate_status
from .attempt_reporting import validate_attempt_page, validate_attempt_detail


_ENVIRONMENT = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
_AUTHORIZE = ("/usr/bin/sudo", "-v", "-u", "root")
_HELPER = ("/usr/bin/sudo", "-n", "-u", "root", "--", "/usr/lib/mpkg/host-helper.py")
_AUTH_SECONDS = 120
_REQUEST_SECONDS = 60
_ERROR_CODES = frozenset({
    "invalid_request", "request_size_limit", "protocol_unsupported", "operation_unsupported",
    "invalid_declaration", "protected_preparation_required", "request_timeout",
    "transport_unavailable", "response_size_limit", "host_owner_required", "policy_unavailable",
    "host_binding_conflict", "mutation_busy", "mutation_lock_unavailable", "store_missing",
    "store_exists", "store_busy", "store_recovery_required", "store_corrupt", "store_unavailable",
    "store_creation_failed", "store_permissions", "store_identity_changed", "revision_conflict",
    "commit_outcome_unknown", "store_write_failed", "store_read_failed", "record_rejected",
    "record_outcome_unknown", "internal_error", "installed_helper_unavailable", "invalid_status_selection",
    "status_no_recorded_snapshot", "status_unavailable", "status_context_changed", "status_scope_limit",
    "input_capture_rejected", "store_migration_required", "attempt_recovery_required",
    "invalid_attempt_page", "attempt_history_requires_migration", "attempt_history_size_limit",
    "attempt_cursor_missing", "attempt_event_cursor_missing", "attempt_missing",
})
_UNCERTAIN_CODES = {"commit_outcome_unknown", "record_outcome_unknown", "response_size_limit",
                    "internal_error", "installed_helper_unavailable"}
_TRANSPORT_CODES = {"request_timeout", "transport_unavailable", "installed_helper_unavailable"}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PROPERTIES = {
    "package": {"present", "source", "version"},
    "compose": {"running", "profiles", "services", "images"},
    "volume": {"present"}, "network": {"present"},
    "service": {"running", "enabled"},
    "user": {"present", "home", "shell", "primary_group", "groups"},
    "group": {"present", "members"},
    "file": {"present", "owner", "group", "mode", "content", "content_input"},
    "directory": {"present", "owner", "group", "mode"},
    "symlink": {"present", "owner", "group", "mode", "target"},
    "sonarr_xml": {"port"},
}


class HostClientError(RuntimeError):
    """Fixed public failure with an explicit outcome class and exit status."""

    def __init__(self, code, category, exit_status):
        self.code, self.category, self.exit_status = code, category, exit_status
        super().__init__(code)


class _TransportFailure(Exception):
    def __init__(self, code, *, dispatched):
        self.code, self.dispatched = code, dispatched


@dataclass(frozen=True)
class _Reply:
    raw: bytes = field(repr=False)
    returncode: int


def _authorize():
    # sudo uses its controlling terminal, never declaration stdin or askpass.
    try:
        result = subprocess.run(_AUTHORIZE, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=dict(_ENVIRONMENT), cwd="/", close_fds=True,
                                timeout=_AUTH_SECONDS, check=False)
    except OSError:
        raise _TransportFailure("authorization_unavailable", dispatched=False) from None
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        raise HostClientError("authentication_failed", "authentication", 4) from None
    if result.returncode != 0:
        raise HostClientError("authentication_failed", "authentication", 4)


def _stop(process):
    # This can stop our unprivileged transport, but cannot guarantee that an
    # already privileged helper has stopped or that a decision was not stored.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _exchange(raw):
    try:
        process = subprocess.Popen(_HELPER, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=dict(_ENVIRONMENT), cwd="/",
                                   close_fds=True, process_group=0)
    except OSError:
        raise _TransportFailure("helper_unavailable", dispatched=False) from None
    # From successful spawn onward, even a partial write is conservatively
    # uncertain for mutations. No transport error is evidence of rollback.
    # A separate group permits bounded cleanup while retaining the session's
    # controlling terminal and sudo's terminal-scoped authentication timestamp.
    try:
        deadline = time.monotonic() + _REQUEST_SECONDS
        chunks, received, offset = [], 0, 0
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.PollSelector() as selector:
            selector.register(process.stdin, selectors.EVENT_WRITE, "input")
            selector.register(process.stdout, selectors.EVENT_READ, "output")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _TransportFailure("helper_timeout", dispatched=True)
                for key, _ in selector.select(min(remaining, 0.1)):
                    if time.monotonic() >= deadline:
                        raise _TransportFailure("helper_timeout", dispatched=True)
                    try:
                        if key.data == "input":
                            offset += os.write(key.fd, raw[offset:offset + 65536])
                            if offset == len(raw):
                                selector.unregister(process.stdin)
                                process.stdin.close()
                        else:
                            chunk = os.read(key.fd, min(65536, MAX_RESPONSE_BYTES + 1 - received))
                            if not chunk:
                                selector.unregister(process.stdout)
                                continue
                            received += len(chunk)
                            if received > MAX_RESPONSE_BYTES:
                                raise _TransportFailure("response_size_limit", dispatched=True)
                            chunks.append(chunk)
                    except BlockingIOError:
                        continue
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise _TransportFailure("helper_timeout", dispatched=True) from None
            if time.monotonic() >= deadline:
                raise _TransportFailure("helper_timeout", dispatched=True)
        return _Reply(b"".join(chunks), process.returncode)
    except (OSError, KeyboardInterrupt):
        _stop(process)
        raise _TransportFailure("helper_interrupted", dispatched=True) from None
    except BaseException:
        _stop(process)
        raise
    finally:
        process.stdin.close()
        process.stdout.close()


def _send(raw):
    _authorize()
    return _exchange(raw)


def _require(condition):
    if not condition:
        raise ValueError


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _reject_number(value):
    raise ValueError


def _keys(value, keys):
    _require(type(value) is dict and set(value) == set(keys))


def _integer(value, *, minimum=0):
    _require(type(value) is int and minimum <= value <= 2**63 - 1)


def _identifier(value):
    _require(type(value) is str and _IDENTIFIER.fullmatch(value))


def _uuid(value):
    _require(type(value) is str and str(uuid.UUID(value)) == value)


def _hash(value):
    _require(type(value) is str and _HASH.fullmatch(value))


def _enum(value, choices):
    _require(type(value) is str and value in choices)


def _decision(value, *, history=False):
    keys = {"revision", "kind", "snapshot_id"}
    _keys(value, keys | {"parent_revision", "created_at"} if history else keys)
    _integer(value["revision"], minimum=1)
    _enum(value["kind"], {"intent", "adopt", "relinquish"})
    _hash(value["snapshot_id"])
    if history:
        parent = value["parent_revision"]
        if value["revision"] == 1:
            _require(parent is None)
        else:
            _integer(parent, minimum=1)
            _require(parent == value["revision"] - 1)
        created = value["created_at"]
        _require(type(created) is str and len(created) == 32)
        timestamp = datetime.fromisoformat(created)
        _require(timestamp.tzinfo == timezone.utc
                 and timestamp.isoformat(timespec="microseconds") == created)


def _current(value):
    _keys(value, {"host_id", "revision", "snapshot_id", "snapshot", "resources"})
    _uuid(value["host_id"])
    _integer(value["revision"])
    if value["revision"] == 0:
        _require(value["snapshot_id"] is None and value["snapshot"] is None)
    else:
        _hash(value["snapshot_id"])
        snapshot = value["snapshot"]
        _keys(snapshot, {"id", "source_sha256", "canonical_sha256", "schema_version", "normalization_version"})
        _require(snapshot["id"] == value["snapshot_id"])
        for key in ("source_sha256", "canonical_sha256"):
            _hash(snapshot[key])
        for key in ("schema_version", "normalization_version"):
            _integer(snapshot[key], minimum=1)
            _require(snapshot[key] == 1)
    _require(type(value["resources"]) is list)
    seen = set()
    for item in value["resources"]:
        _keys(item, {"stable_id", "logical_id", "kind", "management", "declaration_state",
                     "pending_disposition", "managed_properties", "observation"})
        _uuid(item["stable_id"])
        _require(item["stable_id"] not in seen)
        seen.add(item["stable_id"])
        _identifier(item["logical_id"])
        _enum(item["kind"], _PROPERTIES)
        _enum(item["management"], {"accepted", "relinquished"})
        _enum(item["declaration_state"], {"present", "absent", "unknown"})
        _require(type(item["pending_disposition"]) is bool)
        _require(item["pending_disposition"] == (item["management"] == "accepted"
                                                  and item["declaration_state"] == "absent"))
        properties = item["managed_properties"]
        _require(type(properties) is list)
        for name in properties:
            _enum(name, _PROPERTIES[item["kind"]])
        _require(len(properties) == len(set(properties)))
        _require(item["observation"] == {"state": "unknown", "reason": "not_observed"})
    _require(value["revision"] != 0 or not value["resources"])


def _result(value, request):
    if request.verb == "prepare":
        _keys(value, {"host_id", "revision", "preparation_id", "protected_count"})
        _uuid(value["host_id"])
        _uuid(value["preparation_id"])
        _integer(value["revision"])
        _require(value["revision"] == request.expected_revision
                 and type(value["protected_count"]) is int and 1 <= value["protected_count"] <= 64)
    elif request.verb == "observe":
        validate_status(value, request)
    elif request.operation == "initialize":
        _keys(value, {"host_id", "revision", "initialized"})
        _uuid(value["host_id"])
        _integer(value["revision"])
        _require(value["revision"] == 0 and value["initialized"] is True)
    elif request.operation == "current":
        _current(value)
    elif request.operation == "attempts":
        validate_attempt_page(value, request)
    elif request.operation == "attempt":
        validate_attempt_detail(value, request)
    elif request.operation == "history":
        _keys(value, {"host_id", "decisions"})
        _uuid(value["host_id"])
        _require(type(value["decisions"]) is list)
        for revision, decision in enumerate(value["decisions"], 1):
            _decision(decision, history=True)
            _require(decision["revision"] == revision)
    else:
        _decision(value)
        _require(value["revision"] == request.expected_revision + 1
                 and value["kind"] == request.operation)


def _response(reply, request):
    _require(type(reply) is _Reply and type(reply.raw) is bytes
             and 0 < len(reply.raw) <= MAX_RESPONSE_BYTES and type(reply.returncode) is int)
    value = json.loads(reply.raw.decode("utf-8"), object_pairs_hook=_object,
                       parse_float=_reject_number, parse_constant=_reject_number)
    _require(type(value) is dict and type(value.get("ok")) is bool)
    _keys(value, {"version", "ok", "result"} if value["ok"] else {"version", "ok", "error"})
    _require(type(value["version"]) is int and value["version"] == PROTOCOL_VERSION)
    if value["ok"]:
        _require(reply.returncode == 0)
        _result(value["result"], request)
        return value["result"]
    _keys(value["error"], {"code"})
    code = value["error"]["code"]
    _enum(code, _ERROR_CODES)
    _require(reply.returncode == (1 if code in _TRANSPORT_CODES else 2))
    if request.verb == "record" and code in _UNCERTAIN_CODES:
        raise HostClientError(code, "uncertain", 7)
    if code in _TRANSPORT_CODES or code in _UNCERTAIN_CODES:
        raise HostClientError(code, "transport", 5)
    raise HostClientError(code, "rejected", 6)


def request_host(raw, *, _sender=None):
    """Validate locally, send exactly once, and accept only closed responses."""
    request = parse_request(raw)
    try:
        reply = (_send if _sender is None else _sender)(raw)
        try:
            return _response(reply, request)
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, KeyError):
            uncertain = request.verb == "record"
            raise HostClientError("invalid_helper_response", "uncertain" if uncertain else "transport",
                                  7 if uncertain else 5) from None
    except _TransportFailure as error:
        uncertain = error.dispatched and request.verb == "record"
        raise HostClientError(error.code, "uncertain" if uncertain else "transport",
                              7 if uncertain else 5) from None
    except KeyboardInterrupt:
        # Covers cancellation between transport completion and response
        # validation as well as the boundary between authorization and spawn.
        uncertain = request.verb == "record"
        raise HostClientError("helper_interrupted", "uncertain" if uncertain else "transport",
                              7 if uncertain else 5) from None
