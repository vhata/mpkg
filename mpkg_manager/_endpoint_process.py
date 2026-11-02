"""Private supervision for the fixed endpoint worker, never caller commands."""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

from ._endpoint_worker import MAX_REQUEST, _CODES, _ProbeFailure, validate_request


MAX_OUTPUT = 4096
_ENVIRONMENT = {"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C"}
_WORKER = Path(__file__).with_name("_endpoint_worker.py")
PROBE_CODES = frozenset(_CODES | {"worker_unavailable", "worker_failed",
                               "worker_output_invalid", "worker_output_limit", "io_error"})


@dataclass(frozen=True)
class ProbeResult:
    code: str
    status: int | None = None

    def __post_init__(self):
        if (type(self.code) is not str or self.code not in PROBE_CODES
                or (self.code == "ok" and (type(self.status) is not int or not 200 <= self.status <= 599))
                or (self.code != "ok" and self.status is not None)):
            raise ValueError("invalid_endpoint_result")


def _stop(process):
    # A failed leader can leave descendants after closing its captured pipes.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _decode(raw):
    try:
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {"code", "status"}:
            raise ValueError
        return ProbeResult(**value)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return ProbeResult("worker_output_invalid")


def run_probe(url, timeout_seconds):
    """Send a bounded private request; retain only a fixed status/code result."""
    request = {"url": url, "timeout_seconds": timeout_seconds}
    try:
        validate_request(request)
    except _ProbeFailure:
        return ProbeResult("invalid_request")
    raw = json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_REQUEST:
        return ProbeResult("invalid_request")
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen((sys.executable, "-I", str(_WORKER)),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=dict(_ENVIRONMENT),
                                   close_fds=True, start_new_session=True)
    except OSError:
        return ProbeResult("worker_unavailable")
    chunks, total, written = [], 0, 0
    failure = None
    try:
        try:
            with selectors.DefaultSelector() as selector:
                for stream, event, role in ((process.stdin, selectors.EVENT_WRITE, "request"),
                                            (process.stdout, selectors.EVENT_READ, "output"),
                                            (process.stderr, selectors.EVENT_READ, "error")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event, role)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure = "timeout"
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        try:
                            if key.data == "request":
                                written += os.write(key.fd, raw[written:])
                                if written == len(raw):
                                    selector.unregister(key.fileobj)
                                    process.stdin.close()
                                continue
                            chunk = os.read(key.fd, min(4096, MAX_OUTPUT - total + 1))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > MAX_OUTPUT:
                            failure = "worker_output_limit"
                            break
                        if key.data == "output":
                            chunks.append(chunk)
                    if failure:
                        break
                if not failure:
                    try:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            failure = "timeout"
                        else:
                            process.wait(timeout=remaining)
                            if time.monotonic() >= deadline:
                                failure = "timeout"
                    except subprocess.TimeoutExpired:
                        failure = "timeout"
        except OSError:
            failure = "io_error"
        if failure:
            result = ProbeResult(failure)
        elif process.returncode != 0:
            result = ProbeResult("worker_failed")
        else:
            result = _decode(b"".join(chunks))
        if result.code != "ok":
            _stop(process)
        return result
    except BaseException:
        try:
            _stop(process)
        except BaseException:
            pass
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
