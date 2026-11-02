"""Private isolated worker for a fixed loopback HTTP status probe.

Run directly by observe_endpoint's supervisor, never as a privilege helper.
Only standard-library imports are used under Python isolated mode.
"""
import json
import re
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit


MAX_REQUEST = 8192
MAX_URL = 4096
MAX_HEADERS = 16 * 1024
MAX_LINE = 4096
MAX_FIELDS = 64
MAX_INFORMATIONAL = 4
_CODES = {"ok", "invalid_request", "endpoint_unavailable", "timeout",
          "tls_verification_failed", "tls_failed", "response_invalid",
          "response_limit", "request_failed"}
_STATUS = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\t\x20-\x7e]*\r\n\Z")
_HEADER = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class _ProbeFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def validate_request(value):
    """Revalidate the private wire request before any socket operation."""
    try:
        if (type(value) is not dict or set(value) != {"url", "timeout_seconds"}
                or type(value["url"]) is not str or type(value["timeout_seconds"]) is not int
                or not 1 <= value["timeout_seconds"] <= 60):
            raise ValueError
        raw = value["url"].encode("ascii")
        if (not raw or len(raw) > MAX_URL or any(byte <= 32 or byte >= 127 for byte in raw)
                or b"?" in raw or b"#" in raw):
            raise ValueError
        parsed = urlsplit(value["url"])
        if (parsed.scheme not in ("http", "https")
                or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.port is None
                or not 1 <= parsed.port <= 65535):
            raise ValueError
        path = parsed.path or "/"
        if not path.startswith("/"):
            raise ValueError
        return parsed.scheme, parsed.hostname, parsed.port, path, value["timeout_seconds"]
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
        raise _ProbeFailure("invalid_request") from None


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _ProbeFailure("timeout")
    return remaining


def _status(sock, deadline):
    total = fields = informational = 0

    def line():
        nonlocal total
        result = bytearray()
        while True:
            sock.settimeout(_remaining(deadline))
            char = sock.recv(1)
            if not char:
                raise _ProbeFailure("response_invalid")
            total += len(char)
            result.extend(char)
            if total > MAX_HEADERS or len(result) > MAX_LINE:
                raise _ProbeFailure("response_limit")
            if char == b"\n":
                if not result.endswith(b"\r\n"):
                    raise _ProbeFailure("response_invalid")
                return bytes(result)

    while True:
        match = _STATUS.fullmatch(line())
        if match is None:
            raise _ProbeFailure("response_invalid")
        status = int(match.group(1))
        while True:
            header = line()
            if header == b"\r\n":
                break
            fields += 1
            if fields > MAX_FIELDS:
                raise _ProbeFailure("response_limit")
            name, separator, value = header[:-2].partition(b":")
            if (not separator or not _HEADER.fullmatch(name)
                    or any(byte < 32 and byte != 9 or byte == 127 for byte in value)):
                raise _ProbeFailure("response_invalid")
        if status >= 200:
            return status
        informational += 1
        if status == 101 or informational > MAX_INFORMATIONAL:
            raise _ProbeFailure("response_invalid")


def probe(value):
    """Return fixed code/status only; discard request and response diagnostics."""
    sock = None
    try:
        scheme, host, port, path, timeout = validate_request(value)
        deadline = time.monotonic() + timeout
        ipv6 = host == "::1"
        address = ("::1", port, 0, 0) if ipv6 else ("127.0.0.1", port)
        sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_remaining(deadline))
        sock.connect(address)
        if scheme == "https":
            context = ssl.create_default_context()
            sock.settimeout(_remaining(deadline))
            sock = context.wrap_socket(sock, server_hostname=host)
        authority = f"[{host}]:{port}" if ipv6 else f"{host}:{port}"
        request = f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode("ascii")
        sock.settimeout(_remaining(deadline))
        sock.sendall(request)
        return {"code": "ok", "status": _status(sock, deadline)}
    except _ProbeFailure as error:
        return {"code": error.code, "status": None}
    except (TimeoutError, socket.timeout):
        return {"code": "timeout", "status": None}
    except ssl.SSLCertVerificationError:
        return {"code": "tls_verification_failed", "status": None}
    except ssl.SSLError:
        return {"code": "tls_failed", "status": None}
    except OSError:
        return {"code": "endpoint_unavailable", "status": None}
    except (ValueError, TypeError, UnicodeError, OverflowError):
        return {"code": "request_failed", "status": None}
    finally:
        if sock is not None:
            sock.close()


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise ValueError
        request = json.loads(raw)
        result = probe(request)
    except (ValueError, TypeError, UnicodeError, RecursionError, OSError):
        result = {"code": "invalid_request", "status": None}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
