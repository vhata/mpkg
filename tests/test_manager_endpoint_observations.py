"""Closed endpoint probes use owned loopback listeners and private fixtures."""
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from mpkg_manager import _endpoint_process as transport
from mpkg_manager import _endpoint_worker as worker
from mpkg_manager.observe_endpoint import EndpointError, observe_endpoint
from mpkg_manager._endpoint_process import ProbeResult


HOST = "12345678-1234-4234-8234-123456789abc"
OTHER_HOST = "22345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T10:00:00Z"
PRIVATE = "endpoint-private-sentinel"
SERVICE = {"id": "service", "kind": "service", "identity": {"manager": "system", "unit": "example.service"}}


def check(url="http://127.0.0.1:12345/private", **changes):
    return {"id": "health", "kind": "endpoint", "resource": "service",
            "url": url, "timeout_seconds": 1, "expected_status": 200} | changes


class Listener:
    def __init__(self, response, *, context=None):
        self.response = response
        self.context = context
        self.request = b""
        self.error = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.socket.settimeout(3)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        try:
            with ExitStack() as stack:
                client = stack.enter_context(self.socket.accept()[0])
                client.settimeout(3)
                if self.context is not None:
                    client = stack.enter_context(self.context.wrap_socket(client, server_side=True))
                while b"\r\n\r\n" not in self.request and len(self.request) < 8192:
                    data = client.recv(1024)
                    if not data:
                        break
                    self.request += data
                if callable(self.response):
                    self.response(client)
                else:
                    client.sendall(self.response)
        except OSError as error:
            self.error = type(error).__name__

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.socket.close()
        self.thread.join(4)
        if self.thread.is_alive():
            raise AssertionError("Fixture listener did not finish")


class EndpointObservationTests(unittest.TestCase):
    def observe(self, definition=None, *, result=None, resource=SERVICE, **kwargs):
        return observe_endpoint(check() if definition is None else definition, resource,
                                host_id=HOST, observed_at=WHEN,
                                runner=lambda url, timeout: result or ProbeResult("ok", 200), **kwargs)

    def test_status_match_is_not_listener_or_application_verification(self):
        evidence = self.observe()
        public = evidence.as_dict()
        self.assertEqual(public["route_result"], "match")
        self.assertEqual(public["functional_result"], "unverified")
        self.assertEqual(public["limitations"], ["listener_attribution_unavailable", "application_identity_unverified"])
        self.assertEqual(public["evidence_source"], "loopback_http_status")
        self.assertEqual(self.observe(result=ProbeResult("ok", 500)).route_result, "mismatch")
        self.assertEqual(self.observe(result=ProbeResult("timeout")).route_result, "unavailable")

    def test_private_predicate_binding_is_complete_and_projection_is_immutable(self):
        definition = check(url=f"http://localhost:12345/{PRIVATE}")
        evidence = self.observe(definition)
        self.assertTrue(evidence.matches_context(definition, SERVICE, host_id=HOST))
        for altered in (definition | {"expected_status": 201}, definition | {"url": "http://localhost:12345/changed"},
                        definition | {"timeout_seconds": 2}, definition | {"id": "different"}):
            self.assertFalse(evidence.matches_context(altered, SERVICE, host_id=HOST))
        self.assertFalse(evidence.matches_context(definition, SERVICE, host_id=OTHER_HOST))
        other = SERVICE | {"identity": {"manager": "system", "unit": "other.service"}}
        self.assertFalse(evidence.matches_context(definition, other, host_id=HOST))
        self.assertNotIn(PRIVATE, repr(evidence) + json.dumps(evidence.as_dict()))
        self.assertNotIn("url", evidence.as_dict())
        projection = evidence.as_dict()
        projection["limitations"].clear()
        self.assertTrue(evidence.as_dict()["limitations"])
        with self.assertRaises(FrozenInstanceError):
            evidence.route_result = "match"
        with self.assertRaises(EndpointError):
            replace(evidence, route_result="passed")

    def test_compose_target_requires_exact_accepted_engine_identity(self):
        resource = {"id": "service", "kind": "compose", "identity": {"engine": "local", "project": "app"}}
        with self.assertRaises(EndpointError):
            self.observe(resource=resource)
        evidence = self.observe(resource=resource, engine_aliases={"local": "accepted-engine"})
        self.assertTrue(evidence.matches_context(check(), resource, host_id=HOST,
                                                engine_aliases={"local": "accepted-engine"}))
        self.assertFalse(evidence.matches_context(check(), resource, host_id=HOST,
                                                 engine_aliases={"local": "foreign-engine"}))

    def test_real_worker_uses_owned_listener_without_exporting_headers_or_body(self):
        response = (f"HTTP/1.1 200 OK\r\nX-Private: {PRIVATE}\r\nContent-Length: {len(PRIVATE)}\r\n\r\n{PRIVATE}").encode()
        with Listener(response) as server:
            evidence = observe_endpoint(check(url=f"http://127.0.0.1:{server.port}/{PRIVATE}"), SERVICE,
                                        host_id=HOST, observed_at=WHEN)
        self.assertEqual(evidence.route_result, "match")
        self.assertEqual(evidence.functional_result, "unverified")
        self.assertNotIn(PRIVATE, repr(evidence) + json.dumps(evidence.as_dict()))
        self.assertEqual(server.request, (f"GET /{PRIVATE} HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\nConnection: close\r\n\r\n").encode())

    def test_redirect_response_is_compared_without_following_location(self):
        with Listener(b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1:9/private\r\n\r\n") as server:
            evidence = observe_endpoint(check(url=f"http://localhost:{server.port}/"), SERVICE,
                                        host_id=HOST, observed_at=WHEN)
        self.assertEqual(evidence.route_result, "mismatch")
        self.assertEqual(evidence.reason, "status_differs")


class ReplySocket:
    def __init__(self, raw):
        self.raw = raw
        self.reads = []
        self.timeouts = []
        self.connected = None
        self.sent = None
        self.closed = False

    def recv(self, count):
        self.reads.append(count)
        result, self.raw = self.raw[:count], self.raw[count:]
        return result

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        self.connected = address

    def sendall(self, raw):
        self.sent = raw

    def close(self):
        self.closed = True


class EndpointProtocolTests(unittest.TestCase):
    def status(self, raw):
        return worker._status(ReplySocket(raw), time.monotonic() + 5)

    def test_parser_stops_at_headers_and_skips_informational_responses(self):
        reply = ReplySocket(b"HTTP/1.1 100 Continue\r\nX-One: yes\r\n\r\n"
                            b"HTTP/1.0 204 No Content\r\nX-Two: yes\r\n\r\n" + PRIVATE.encode())
        self.assertEqual(worker._status(reply, time.monotonic() + 5), 204)
        self.assertEqual(reply.raw, PRIVATE.encode())
        self.assertEqual(set(reply.reads), {1})
        self.assertTrue(all(value > 0 for value in reply.timeouts))

    def test_malformed_protocol_never_yields_a_terminal_status(self):
        cases = [b"HTTP/2 200 OK\r\n\r\n", b"HTTP/1.1 099 Invalid\r\n\r\n",
                 b"HTTP/1.1 600 Invalid\r\n\r\n", b"HTTP/1.1 200 OK\n\n",
                 b"HTTP/1.1 200 OK\r\n", b"HTTP/1.1 200 OK\r\n no: folded\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\nX: bad\x01\r\n\r\n",
                 b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                 b"HTTP/1.1 100 Continue\r\n\r\n" * 5]
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(worker._ProbeFailure) as error:
                    self.status(raw)
                self.assertEqual(error.exception.code, "response_invalid")

    def test_header_line_count_and_total_bytes_are_bounded(self):
        status = b"HTTP/1.1 200 OK\r\n"
        cases = [status + b"X: " + b"a" * worker.MAX_LINE + b"\r\n\r\n",
                 status + b"X: x\r\n" * (worker.MAX_FIELDS + 1) + b"\r\n",
                 status + (b"X: " + b"a" * 3000 + b"\r\n") * 6 + b"\r\n"]
        for raw in cases:
            with self.subTest(size=len(raw)):
                with self.assertRaises(worker._ProbeFailure) as error:
                    self.status(raw)
                self.assertEqual(error.exception.code, "response_limit")
        self.assertEqual(self.status(status + b"X: x\r\n" * worker.MAX_FIELDS + b"\r\n"), 200)

    def test_numeric_loopback_selection_never_uses_a_resolver(self):
        for host, family, address in [("localhost", socket.AF_INET, ("127.0.0.1", 4321)),
                                      ("127.0.0.1", socket.AF_INET, ("127.0.0.1", 4321)),
                                      ("[::1]", socket.AF_INET6, ("::1", 4321, 0, 0))]:
            reply = ReplySocket(b"HTTP/1.1 200 OK\r\n\r\n")
            with self.subTest(host=host), patch.object(worker.socket, "socket", return_value=reply) as make_socket, \
                    patch.object(worker.socket, "getaddrinfo", side_effect=AssertionError("DNS lookup")):
                result = worker.probe({"url": f"http://{host}:4321/health", "timeout_seconds": 1})
            self.assertEqual(result, {"code": "ok", "status": 200})
            make_socket.assert_called_once_with(family, socket.SOCK_STREAM)
            self.assertEqual(reply.connected, address)
            self.assertTrue(reply.closed)

    def test_unsupported_requests_are_rejected_before_socket_creation(self):
        urls = ["http://192.0.2.1:80/", "http://localhost/", "http://localhost:0/",
                "http://localhost:65536/", "ftp://localhost:80/", "http://user@localhost:80/",
                "http://localhost:80/?private", "http://localhost:80/#private",
                "http://localhost:80/\x01", "http://localhost:80/\x7f", "http://localhost:80/é",
                "http://localhost:80/" + "x" * worker.MAX_URL]
        with patch.object(worker.socket, "socket", side_effect=AssertionError("Invalid request used socket")):
            for url in urls:
                with self.subTest(url=url):
                    self.assertEqual(worker.probe({"url": url, "timeout_seconds": 1})["code"], "invalid_request")
            for timeout in (0, 61, True, 1.0, "1"):
                self.assertEqual(worker.probe({"url": "http://localhost:80/", "timeout_seconds": timeout})["code"], "invalid_request")

    def test_worker_deadline_is_rechecked_between_response_bytes(self):
        reply = ReplySocket(b"HTTP/1.1 200 OK\r\n\r\n")
        with patch.object(worker.time, "monotonic", side_effect=[0.0, 0.2, 0.4, 1.1]), \
                self.assertRaises(worker._ProbeFailure) as error:
            worker._status(reply, 1.0)
        self.assertEqual(error.exception.code, "timeout")
        self.assertEqual(reply.timeouts, [1.0, 0.8, 0.6])


    def test_worker_rejects_a_final_status_processed_after_its_deadline(self):
        clock = [0.0]

        class LateSocket(ReplySocket):
            def recv(self, count):
                result = super().recv(count)
                if not self.raw:
                    clock[0] = 2.0
                return result

        with patch.object(worker.time, "monotonic", side_effect=lambda: clock[0]), \
                self.assertRaises(worker._ProbeFailure) as error:
            worker._status(LateSocket(b"HTTP/1.1 200 OK\r\n\r\n"), 1.0)
        self.assertEqual(error.exception.code, "timeout")


class EndpointTlsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Path(__file__).parent / "fixtures" / "endpoint"
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.load_cert_chain(self.fixture / "localhost-cert.pem", self.fixture / "localhost-key.pem")

    def test_isolated_worker_rejects_untrusted_certificate_even_with_parent_ca_override(self):
        with Listener(b"HTTP/1.1 200 OK\r\n\r\n", context=self.server_context) as server, \
                patch.dict(os.environ, {"SSL_CERT_FILE": str(self.fixture / "localhost-cert.pem"),
                                        "HTTP_PROXY": "http://192.0.2.1:1", "HTTPS_PROXY": "http://192.0.2.1:1"}):
            result = transport.run_probe(f"https://localhost:{server.port}/", 1)
        self.assertEqual(result.code, "tls_verification_failed")
        self.assertIsNone(result.status)

    def test_private_worker_verified_tls_success_and_hostname_mismatch(self):
        trusted = ssl.create_default_context(cafile=str(self.fixture / "localhost-cert.pem"))
        self.assertTrue(trusted.check_hostname)
        self.assertEqual(trusted.verify_mode, ssl.CERT_REQUIRED)
        for host, expected in (("localhost", "ok"), ("127.0.0.1", "tls_verification_failed")):
            with self.subTest(host=host), Listener(b"HTTP/1.1 200 OK\r\n\r\n", context=self.server_context) as server, \
                    patch.object(worker.ssl, "create_default_context", return_value=trusted):
                result = worker.probe({"url": f"https://{host}:{server.port}/", "timeout_seconds": 1})
            self.assertEqual(result["code"], expected)


class EndpointSupervisorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.index = 0

    def script(self, source):
        self.index += 1
        path = self.directory / f"worker-{self.index}.py"
        path.write_text(source)
        return path

    def run_child(self, source):
        with patch.object(transport, "_WORKER", self.script(source)):
            return transport.run_probe(f"http://localhost:12345/{PRIVATE}", 1)

    def assert_stopped(self, pid):
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0]
            except FileNotFoundError:
                return
            if state in ("Z", "X"):
                return
            time.sleep(0.01)
        self.fail("Owned fixture descendant still runs")

    def cleanup_pid(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_request_is_stdin_only_and_worker_environment_is_closed(self):
        record = self.directory / "private-request.json"
        source = ("import json,os,sys\nfrom pathlib import Path\n"
                  f"Path({str(record)!r}).write_text(json.dumps({{'argv':sys.argv,'env':dict(os.environ),'request':json.loads(sys.stdin.buffer.read())}}))\n"
                  "print('{\"code\":\"ok\",\"status\":200}')\n")
        with patch.dict(os.environ, {"PYTHONPATH": PRIVATE, "SSL_CERT_FILE": PRIVATE, "HTTP_PROXY": PRIVATE}):
            result = self.run_child(source)
        self.assertEqual(result, ProbeResult("ok", 200))
        value = json.loads(record.read_text())
        self.assertNotIn(PRIVATE, json.dumps(value["argv"]) + json.dumps(value["env"]))
        self.assertEqual(value["request"], {"url": f"http://localhost:12345/{PRIVATE}", "timeout_seconds": 1})

    def test_combined_stdout_stderr_limit_discards_all_private_output(self):
        for fd in (1, 2):
            with self.subTest(fd=fd):
                result = self.run_child(f"import os,sys,time\nsys.stdin.buffer.read()\nos.write({fd},b'x'*{transport.MAX_OUTPUT + 1})\ntime.sleep(10)\n")
            self.assertEqual(result.code, "worker_output_limit")
            self.assertIsNone(result.status)
            self.assertNotIn("x" * 16, repr(result))

    def test_nonzero_malformed_and_semantically_failed_leaders_stop_closed_pipe_descendants(self):
        for code, output, expected in [(7, "", "worker_failed"),
                                       (0, PRIVATE, "worker_output_invalid"),
                                       (0, '{"code":"endpoint_unavailable","status":null}', "endpoint_unavailable")]:
            pidfile = self.directory / f"child-{code}-{expected}.pid"
            source = ("import os,sys,time\nfrom pathlib import Path\nsys.stdin.buffer.read()\n"
                      "pid=os.fork()\nif pid==0:\n"
                      "    for fd in (0,1,2): os.close(fd)\n"
                      f"    Path({str(pidfile)!r}).write_text(str(os.getpid()))\n"
                      "    time.sleep(10)\n    os._exit(0)\n"
                      f"while not Path({str(pidfile)!r}).exists(): time.sleep(0.001)\n"
                      f"sys.stdout.write({output!r})\nsys.stdout.flush()\nsys.exit({code})\n")
            with self.subTest(expected=expected):
                result = self.run_child(source)
                self.assertEqual(result.code, expected)
                pid = int(pidfile.read_text())
                self.addCleanup(self.cleanup_pid, pid)
                self.assert_stopped(pid)

    def test_timeout_covers_worker_and_inherited_output_streams(self):
        pidfile = self.directory / "timeout-child.pid"
        source = ("import os,sys,time\nfrom pathlib import Path\nsys.stdin.buffer.read()\n"
                  "pid=os.fork()\nif pid==0:\n"
                  f"    Path({str(pidfile)!r}).write_text(str(os.getpid()))\n"
                  "    time.sleep(10)\n    os._exit(0)\n"
                  "os._exit(0)\n")
        start = time.monotonic()
        result = self.run_child(source)
        elapsed = time.monotonic() - start
        self.assertEqual(result.code, "timeout")
        self.assertLess(elapsed, 3)
        pid = int(pidfile.read_text())
        self.addCleanup(self.cleanup_pid, pid)
        self.assert_stopped(pid)

    def test_cancellation_preserves_interrupt_and_closes_all_owned_resources(self):
        pidfile = self.directory / "cancel-child.pid"
        source = ("import os,sys,time\nfrom pathlib import Path\n"
                  "pid=os.fork()\nif pid==0:\n"
                  f"    Path({str(pidfile)!r}).write_text(str(os.getpid()))\n"
                  "    time.sleep(10)\n    os._exit(0)\n"
                  "sys.stdin.buffer.read()\ntime.sleep(10)\n")
        original_selector = transport.selectors.DefaultSelector
        original_popen = subprocess.Popen
        started = []
        cancellation = KeyboardInterrupt()

        class InterruptedSelector:
            def __init__(self):
                self.delegate = original_selector()

            def __enter__(self):
                self.delegate.__enter__()
                return self

            def __exit__(self, *args):
                return self.delegate.__exit__(*args)

            def __getattr__(self, name):
                return getattr(self.delegate, name)

            def select(self, timeout):
                events = self.delegate.select(timeout)
                if pidfile.exists():
                    raise cancellation
                return events

        def spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            started.append(process)
            return process

        with patch.object(transport.selectors, "DefaultSelector", InterruptedSelector), \
                patch.object(transport.subprocess, "Popen", side_effect=spawn), \
                self.assertRaises(KeyboardInterrupt) as error:
            self.run_child(source)
        self.assertIs(error.exception, cancellation)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].returncode)
        self.assertTrue(all(stream.closed for stream in (started[0].stdin, started[0].stdout, started[0].stderr)))
        pid = int(pidfile.read_text())
        self.addCleanup(self.cleanup_pid, pid)
        self.assert_stopped(pid)

    def test_slow_response_cannot_restart_the_parent_deadline(self):
        def slow(client):
            for byte in b"HTTP/1.1 200 OK\r\n\r\n":
                client.sendall(bytes([byte]))
                time.sleep(0.2)

        with Listener(slow) as server:
            start = time.monotonic()
            result = transport.run_probe(f"http://localhost:{server.port}/", 1)
            elapsed = time.monotonic() - start
        self.assertEqual(result.code, "timeout")
        self.assertLess(elapsed, 3)

    def test_invalid_worker_protocol_and_start_failures_are_fixed_codes(self):
        for raw in (PRIVATE, '[]', '{"code":"ok","status":true}', '{"code":"ok","status":199}',
                    '{"code":"timeout","status":200}', '{"code":"ok","status":200,"extra":1}'):
            with self.subTest(raw=raw):
                result = self.run_child(f"import sys\nsys.stdin.buffer.read()\nprint({raw!r})\n")
            self.assertEqual(result, ProbeResult("worker_output_invalid"))
        with patch.object(transport.subprocess, "Popen", side_effect=OSError(PRIVATE)):
            self.assertEqual(transport.run_probe("http://localhost:12345/", 1), ProbeResult("worker_unavailable"))
        with patch.object(transport.subprocess, "Popen", side_effect=AssertionError("Invalid request launched")):
            self.assertEqual(transport.run_probe("http://192.0.2.1:80/", 1), ProbeResult("invalid_request"))


    def test_worker_completion_after_deadline_cannot_return_a_success_status(self):
        original_clock = time.monotonic
        original_popen = subprocess.Popen
        completed = [False]

        def clock():
            return original_clock() + (2 if completed[0] else 0)

        def spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            original_wait = process.wait

            def wait(*wait_args, **wait_kwargs):
                result = original_wait(*wait_args, **wait_kwargs)
                completed[0] = True
                return result

            process.wait = wait
            return process

        with patch.object(transport.time, "monotonic", side_effect=clock), \
                patch.object(transport.subprocess, "Popen", side_effect=spawn):
            result = self.run_child("import sys\nsys.stdin.buffer.read()\nprint('{\"code\":\"ok\",\"status\":200}')\n")
        self.assertEqual(result.code, "timeout")


class EndpointBoundaryTests(unittest.TestCase):
    def test_malformed_requests_never_invoke_runner_or_export_values(self):
        def forbidden(*args):
            self.fail("Malformed context reached runner")

        definitions = [check(resource="missing"), check(kind="package"), check(timeout_seconds=True),
                       check(url=f"http://192.0.2.1:80/{PRIVATE}"), check(url="http://localhost:80/\x01")]
        for definition in definitions:
            with self.subTest(definition=definition):
                with self.assertRaises(EndpointError) as error:
                    observe_endpoint(definition, SERVICE, host_id=HOST, runner=forbidden)
                self.assertEqual(str(error.exception), "invalid_endpoint_context")
                self.assertNotIn(PRIVATE, str(error.exception))
        for host, when in (("invalid", WHEN), (HOST, "not-a-time"), (HOST, "2026-11-02T00:00:00+01:00")):
            with self.subTest(host=host, when=when), self.assertRaises(EndpointError):
                observe_endpoint(check(), SERVICE, host_id=host, observed_at=when, runner=forbidden)

    def test_runner_exceptions_and_forged_results_do_not_leak_diagnostics(self):
        def failed(*args):
            raise OSError(PRIVATE)

        with self.assertRaises(EndpointError) as error:
            observe_endpoint(check(), SERVICE, host_id=HOST, runner=failed)
        self.assertEqual(str(error.exception), "endpoint_runner_failed")
        forged = object.__new__(ProbeResult)
        for result in (None, {"code": "ok", "status": 200}, forged):
            with self.subTest(result_type=type(result)):
                with self.assertRaises(EndpointError) as error:
                    observe_endpoint(check(), SERVICE, host_id=HOST, runner=lambda *args: result)
                self.assertEqual(str(error.exception), "invalid_endpoint_result")

    def test_cancellation_from_trusted_runner_is_not_converted_to_success(self):
        cancellation = KeyboardInterrupt()

        def interrupted(*args):
            raise cancellation

        with self.assertRaises(KeyboardInterrupt) as error:
            observe_endpoint(check(), SERVICE, host_id=HOST, runner=interrupted)
        self.assertIs(error.exception, cancellation)


if __name__ == "__main__":
    unittest.main()
