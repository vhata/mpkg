"""Internal subprocess mechanics; adapters own closed argv/environment policies.

Declarations and public callers never select commands through this module.
"""
from dataclasses import dataclass, field
import math
import os
import selectors
import signal
import subprocess
import time


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


def run_bounded(argv, *, environment, timeout=10, max_output=1024 * 1024):
    """Run an adapter-approved query with bounded private capture and cleanup.

    Only stdout from a successful query is returned privately for parsing.
    Exceptions and stderr are never included in the public error code.
    """
    if (type(timeout) not in (float, int) or not math.isfinite(timeout)
            or not 0 < timeout <= 30 or type(max_output) is not int
            or not 0 < max_output <= 8 * 1024 * 1024):
        raise ValueError("invalid_query_bounds")
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=dict(environment), close_fds=True,
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
        if not failure and process.returncode != 0:
            failure = "command_failed"
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
    return QueryResult("ok", b"".join(chunks), process.returncode)
