"""Bounded private supervision for the fixed declared-user access worker."""
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

from ._access_worker import MAX_REQUEST, _CODES, AccessFailure, validate_request


MAX_OUTPUT = 4096
ENVIRONMENT = {"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C"}
_WORKER = Path(__file__).with_name('_access_worker.py')
RESULT_CODES = frozenset(_CODES | {'timeout', 'worker_unavailable', 'worker_failed',
                                  'worker_output_invalid', 'worker_output_limit', 'io_error'})


@dataclass(frozen=True)
class AccessResult:
    code: str

    def __post_init__(self):
        if type(self.code) is not str or self.code not in RESULT_CODES:
            raise ValueError('invalid_access_result')


def _stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _decode(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
        if type(value) is not dict or set(value) != {'code'}:
            raise ValueError
        return AccessResult(value['code'])
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return AccessResult('worker_output_invalid')


def run_access(request, *, timeout):
    """Numeric credentials and path travel only over bounded private stdin."""
    try:
        validate_request(request)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError
        raw = json.dumps(request, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        if len(raw) > MAX_REQUEST:
            raise ValueError
    except (AccessFailure, ValueError, TypeError):
        return AccessResult('invalid_request')
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen((sys.executable, '-I', str(_WORKER)), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(ENVIRONMENT), close_fds=True,
            start_new_session=True, cwd='/')
    except OSError:
        return AccessResult('worker_unavailable')
    chunks, total, written, failure = [], 0, 0, None
    try:
        try:
            with selectors.DefaultSelector() as selector:
                for stream, event, role in ((process.stdin, selectors.EVENT_WRITE, 'request'),
                                          (process.stdout, selectors.EVENT_READ, 'output'),
                                          (process.stderr, selectors.EVENT_READ, 'error')):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event, role)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure = 'timeout'
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        try:
                            if key.data == 'request':
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
                            failure = 'worker_output_limit'
                            break
                        if key.data == 'output':
                            chunks.append(chunk)
                        else:
                            failure = 'worker_failed'
                            break
                    if failure:
                        break
                if not failure:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure = 'timeout'
                    else:
                        try:
                            process.wait(timeout=remaining)
                        except subprocess.TimeoutExpired:
                            failure = 'timeout'
                        if time.monotonic() >= deadline:
                            failure = 'timeout'
        except OSError:
            failure = 'io_error'
        result = (AccessResult(failure) if failure else AccessResult('worker_failed')
                  if process.returncode != 0 else _decode(b''.join(chunks)))
        return result
    except BaseException:
        try:
            _stop(process)
        except BaseException:
            pass
        raise
    finally:
        # A completed leader must not leave a descendant holding credentials.
        _stop(process)
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
