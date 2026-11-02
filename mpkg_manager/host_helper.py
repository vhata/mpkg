"""Installed recording/export dispatch with trusted paths and fixed outcomes.

Only the fixed launcher is a privileged entrypoint. Python construction with
alternate fixture paths or an owner is trusted embedding, never wire input.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import selectors
import stat
import time

from .declarations import load_declaration
from .host_policy import POLICY_PATH, PolicyError, _DirectoryChain, load_host_policy
from .host_protocol import (MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION,
                            HostRequest, RequestError, parse_request)
from .store import HostStore, StoreError


STORE_DIRECTORY = Path("/var/lib/mpkg")
MUTATION_LOCK = Path("/run/mpkg/apply.lock")
TRANSPORT_SECONDS = 5.0
_ERROR_CODES = frozenset({
    "invalid_request", "request_size_limit", "protocol_unsupported", "operation_unsupported",
    "invalid_declaration", "protected_recording_unsupported", "request_timeout",
    "transport_unavailable", "response_size_limit", "host_owner_required", "policy_unavailable",
    "host_binding_conflict", "mutation_busy", "mutation_lock_unavailable", "store_missing",
    "store_exists", "store_busy", "store_recovery_required", "store_corrupt", "store_unavailable",
    "store_creation_failed", "store_permissions", "store_identity_changed", "revision_conflict",
    "commit_outcome_unknown", "store_write_failed", "store_read_failed", "record_rejected",
    "record_outcome_unknown", "internal_error",
})
_STORE_ERRORS = _ERROR_CODES & frozenset({
    "store_missing", "store_exists", "store_busy", "store_recovery_required", "store_corrupt",
    "store_unavailable", "store_creation_failed", "store_permissions", "store_identity_changed",
    "revision_conflict", "commit_outcome_unknown", "store_write_failed", "store_read_failed",
})


class BoundaryError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _error(code):
    return {"version": PROTOCOL_VERSION, "ok": False,
            "error": {"code": code if code in _ERROR_CODES else "internal_error"}}


def encode_response(value):
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode("utf-8") + b"\n"
        if len(raw) > MAX_RESPONSE_BYTES:
            raise BoundaryError("response_size_limit")
        return raw
    except BoundaryError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise BoundaryError("internal_error") from None


def _lock_info(info, owner_uid):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise BoundaryError("mutation_lock_unavailable")


@contextmanager
def _mutation_lock(path, owner_uid):
    """Use an administratively provisioned lock; never create or replace it."""
    chain, fd = None, None
    try:
        try:
            chain = _DirectoryChain(path.parent, owner_uid=owner_uid)
            info = os.fstat(chain.fd)
            if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o700:
                raise BoundaryError("mutation_lock_unavailable")
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=chain.fd)
            opened = os.fstat(fd)
            _lock_info(opened, owner_uid)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BoundaryError("mutation_busy") from None
            chain.verify()
            linked = os.stat(path.name, dir_fd=chain.fd, follow_symlinks=False)
            _lock_info(linked, owner_uid)
            if (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino):
                raise BoundaryError("mutation_lock_unavailable")
        except (OSError, PolicyError):
            raise BoundaryError("mutation_lock_unavailable") from None
        yield
    finally:
        if fd is not None:
            os.close(fd)
        if chain is not None:
            chain.close()


def _current_projection(current):
    # Store.current() is trusted internal data. Do not expose its definitions,
    # physical identities, desired values, accepted predicates or references.
    resources = [{"stable_id": item["stable_id"], "logical_id": item["logical_id"],
                  "kind": item["definition"]["kind"], "management": item["management"],
                  "declaration_state": item["declaration_state"],
                  "pending_disposition": item["pending_disposition"],
                  "managed_properties": list(item["definition"]["manage"]),
                  "observation": {"state": "unknown", "reason": "not_observed"}}
                 for item in current["resources"]]
    return {key: current[key] for key in ("host_id", "revision", "snapshot_id", "snapshot")} | {"resources": resources}


class HostBoundary:
    """Trusted construction only. The installed entrypoint supplies no overrides."""

    def __init__(self, *, policy_path=POLICY_PATH, store_directory=STORE_DIRECTORY,
                 mutation_lock=MUTATION_LOCK, owner_uid=0):
        self._policy_path = policy_path
        self._store_directory = store_directory
        self._mutation_lock = Path(mutation_lock)
        self._owner_uid = owner_uid

    def dispatch(self, request):
        if type(request) is not HostRequest:
            raise BoundaryError("invalid_request")
        if type(self._owner_uid) is not int or self._owner_uid != os.geteuid():
            raise BoundaryError("host_owner_required")
        with load_host_policy(path=self._policy_path, owner_uid=self._owner_uid) as policy:
            accepted_policy = policy.policy
            if request.verb == "export":
                with HostStore.open_readonly(self._store_directory, accepted_policy.host_id,
                                             owner_uid=self._owner_uid) as store:
                    self._bound(store, accepted_policy)
                    if request.operation == "current":
                        result = _current_projection(store.current())
                    elif request.operation == "history":
                        result = {"host_id": accepted_policy.host_id, "decisions": store.history()}
                    else:
                        raise BoundaryError("operation_unsupported")
                    policy.policy
                    return result
            if request.verb != "record":
                raise BoundaryError("operation_unsupported")
            with _mutation_lock(self._mutation_lock, self._owner_uid):
                policy.policy
                if request.operation == "initialize":
                    try:
                        with HostStore.create(self._store_directory, accepted_policy.host_id,
                                              engine_aliases=accepted_policy.engine_aliases,
                                              owner_uid=self._owner_uid) as store:
                            result = {"host_id": store.host_id, "revision": 0, "initialized": True}
                    except StoreError as error:
                        # Creation may have committed or left partial files before
                        # an error is reported. Its lower-level codes do not
                        # establish rollback. An existing destination is refused.
                        if error.code == "store_exists":
                            raise
                        raise BoundaryError("record_outcome_unknown") from None
                else:
                    with HostStore.open_existing(self._store_directory, accepted_policy.host_id,
                                                 owner_uid=self._owner_uid) as store:
                        self._bound(store, accepted_policy)
                        if request.operation == "intent":
                            result = store.record_intent(load_declaration(request.source), request.expected_revision)
                        elif request.operation == "adopt":
                            result = store.adopt(load_declaration(request.source), request.expected_revision,
                                                 request.resource_ids)
                        elif request.operation == "relinquish":
                            result = store.relinquish(request.resource_ids, request.expected_revision)
                        else:
                            raise BoundaryError("operation_unsupported")
                try:
                    policy.policy
                except PolicyError:
                    raise BoundaryError("record_outcome_unknown") from None
                return result

    @staticmethod
    def _bound(store, policy):
        if store.engine_aliases != policy.engine_aliases:
            raise BoundaryError("host_binding_conflict")


def handle_request(raw, *, boundary=None):
    """Return one bounded response; never return raw exceptions or requests."""
    request = None
    try:
        request = parse_request(raw)
        result = (HostBoundary() if boundary is None else boundary).dispatch(request)
        return encode_response({"version": PROTOCOL_VERSION, "ok": True, "result": result})
    except RequestError as error:
        response = _error(error.code)
    except PolicyError:
        response = _error("policy_unavailable")
    except StoreError as error:
        response = _error(error.code if error.code in _STORE_ERRORS else "record_rejected")
    except BoundaryError as error:
        response = _error(error.code)
    except Exception:
        response = _error("record_outcome_unknown" if request is not None and request.verb == "record" else "internal_error")
    return encode_response(response)


def read_request(fd, *, timeout=TRANSPORT_SECONDS):
    """Read one JSON request through EOF, bounded by bytes and elapsed time."""
    deadline = time.monotonic() + timeout
    chunks, size = [], 0
    previous = os.get_blocking(fd)
    try:
        os.set_blocking(fd, False)
        # PollSelector supports regular-file redirection as well as pipes.
        with selectors.PollSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise BoundaryError("request_timeout")
                try:
                    chunk = os.read(fd, min(65536, MAX_REQUEST_BYTES + 1 - size))
                except BlockingIOError:
                    continue
                if time.monotonic() >= deadline:
                    raise BoundaryError("request_timeout")
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_REQUEST_BYTES:
                    raise BoundaryError("request_size_limit")
    finally:
        os.set_blocking(fd, previous)


def write_response(fd, raw, *, timeout=TRANSPORT_SECONDS):
    """Bound response delivery to an unresponsive pipe consumer."""
    deadline = time.monotonic() + timeout
    previous = os.get_blocking(fd)
    try:
        os.set_blocking(fd, False)
        with selectors.PollSelector() as selector:
            selector.register(fd, selectors.EVENT_WRITE)
            offset = 0
            while offset < len(raw):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return False
                try:
                    count = os.write(fd, raw[offset:offset + 65536])
                except BlockingIOError:
                    continue
                if count <= 0 or time.monotonic() >= deadline:
                    return False
                offset += count
            return True
    except OSError:
        return False
    finally:
        try:
            os.set_blocking(fd, previous)
        except OSError:
            pass


def main():
    """Fixed installed invocation; no command-line options or environment input."""
    import sys
    transport_failed = False
    if len(sys.argv) != 1:
        raw = encode_response(_error("invalid_request"))
    else:
        try:
            raw = handle_request(read_request(0))
        except BoundaryError as error:
            raw = encode_response(_error(error.code))
            # The byte limit is a rejected request; timeout or input failure
            # means the transport could not deliver a complete request.
            transport_failed = error.code != "request_size_limit"
        except Exception:
            raw = encode_response(_error("transport_unavailable"))
            transport_failed = True
    if not write_response(1, raw) or transport_failed:
        return 1
    return 0 if json.loads(raw)["ok"] else 2
