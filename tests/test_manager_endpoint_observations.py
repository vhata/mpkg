"""Closed endpoint probes use owned loopback listeners and private fixtures."""
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import signal
import socket
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
    def __init__(self, response):
        self.response = response
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
            with self.socket.accept()[0] as client:
                client.settimeout(3)
                while b"\r\n\r\n" not in self.request and len(self.request) < 8192:
                    data = client.recv(1024)
                    if not data:
                        break
                    self.request += data
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


if __name__ == "__main__":
    unittest.main()
