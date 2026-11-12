from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from datetime import datetime, timedelta
import os
import threading
import time
import unittest

from mpkg_manager import application_checks as app
from mpkg_manager._application_worker import predicate_result
from mpkg_manager.declarations import canonical_json
from mpkg_manager.query_process import QueryResult
from mpkg_manager.runtime_checks import RuntimeCheckManifest

HOST = "62b87faa-bd2c-415a-9211-adfb233a8b58"
CID = "a" * 64


def fixture(application="sonarr", port=18989, role="current"):
    predicate = app.ApplicationPredicate(application, app.VERSIONS[application][0], port,
                  root_id=1 if application == "radarr" else 0,
                  root_path="/media/root" if application == "radarr" else "",
                  sentinel="Mpkg Sentinel (2000)" if application == "radarr" else "")
    path = "/ping" if application == "sonarr" else "/api/v3/rootfolder/1"
    scope = canonical_json({"role": role, "stable_id": None if role == "current" else HOST,
        "adoption_revision": None if role == "current" else 1, "snapshot_id": "b" * 64,
        "management": None if role == "current" else "relinquished", "selected": True,
        "context": {"check": {"id": "check", "kind": "endpoint", "resource": "web",
             "timeout_seconds": 2, "expected_status": 200, "url": f"http://127.0.0.1:{port}{path}"},
          "resource": {"id": "web", "kind": "compose", "identity": {"engine": "local", "project": "example"},
                       "checks": ["check"], "desired": {"services": ["web"]}},
          "target": [HOST, "compose", "engine-1", "example"]}})
    manifest = RuntimeCheckManifest(HOST, 1, "b" * 64, None, (scope,))
    return manifest, scope, predicate


class Replies:
    def __init__(self, application="sonarr", port=18989):
        self.data = {"id": CID, "pid": os.getpid(), "project": "example", "service": "web",
           "oneoff": "False", "running": True, "status": "running", "started_at": "2026-11-11T00:00:00Z",
           "image": app.VERSIONS[application][1], "network_mode": "host", "ports": {}, "networks": {}}
        self.calls = 0
    def __call__(self, argv, **kwargs):
        self.calls += 1
        if argv == app.runtime.ENGINE_QUERY:
            value = json.dumps("engine-1").encode()
        elif argv[:-1] == app.INSPECT:
            value = json.dumps(self.data).encode()
        elif argv[:len(app.runtime.LIST_QUERY)] == app.runtime.LIST_QUERY:
            value = (CID + "\n").encode()
        elif argv[:len(app.runtime.TOP_QUERY)] == app.runtime.TOP_QUERY:
            value = f"PID\n{os.getpid()}\n".encode()
        else:
            raise AssertionError(argv)
        return QueryResult("ok", value)


class ApplicationTests(unittest.TestCase):
    def observe(self, application="sonarr", role="current", **kwargs):
        return app.observe_application(*fixture(application, role=role), context_guard=lambda *a: True,
             query_runner=kwargs.pop("query_runner", Replies(application)), credential=lambda: "SECRET",
             application_runner=kwargs.pop("application_runner", lambda *a: "passed"),
             route_runner=kwargs.pop("route_runner", lambda *a: "match"), **kwargs)

    def test_current_and_retained_bindings_are_separate(self):
        for role in ("current", "accepted"):
            result = self.observe(role=role)
            self.assertEqual(result.functional_result, "passed")
            self.assertTrue(result.matches(*fixture(role=role)))
            self.assertFalse(result.matches(*fixture(role="accepted" if role == "current" else "current")))
            changed = app.ApplicationPredicate("sonarr", "4.0.20.3014", 18990)
            self.assertFalse(result.matches(*fixture(role=role)[:2], changed))

    def test_future_and_stale_evidence_cannot_match(self):
        result = self.observe()
        when = datetime.fromisoformat(result.observed_at.replace("Z", "+00:00"))
        self.assertFalse(result.matches(*fixture(), now=when + timedelta(seconds=61)))
        self.assertFalse(result.matches(*fixture(), now=when - timedelta(seconds=1)))
        self.assertTrue(result.matches(*fixture(), now=when + timedelta(seconds=60)))

    def test_context_refused_before_queries(self):
        replies = Replies()
        result = app.observe_application(*fixture(), context_guard=lambda *a: False, query_runner=replies)
        self.assertEqual(result.reason, "context_changed")
        self.assertEqual(replies.calls, 0)

    def test_context_changed_after_request_discards_result(self):
        guards = iter((True, True, False))
        result = app.observe_application(*fixture(), context_guard=lambda *a: next(guards),
             query_runner=Replies(), application_runner=lambda *a: "passed", route_runner=lambda *a: "match")
        self.assertEqual(result.reason, "context_changed")

    def test_replacement_and_wrong_version_refused(self):
        for field, value in (("id", "c" * 64), ("image", "sha256:" + "c" * 64),
                             ("project", "wrong"), ("running", False)):
            replies = Replies()
            replies.data[field] = value
            result = self.observe(query_runner=replies)
            self.assertEqual(result.functional_result, "unavailable")
        replies = Replies()
        def replace(*args):
            replies.data["started_at"] = "2026-11-12T00:00:00Z"
            return "passed"
        self.assertEqual(self.observe(query_runner=replies, application_runner=replace).functional_result, "unavailable")

    def test_bridge_mapping_is_bound_and_route_has_no_key(self):
        replies = Replies("radarr")
        replies.data.update(network_mode="example_default", ports={"18989/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "18989"}]}, networks={"example_default": {
                "NetworkID": "d" * 64, "EndpointID": "e" * 64}})
        seen = []
        def worker(data, key, namespace):
            self.assertEqual(key, "SECRET")
            self.assertGreater(namespace[0], 0)
            return "passed"
        result = self.observe("radarr", query_runner=replies, application_runner=worker,
                              route_runner=lambda *args: seen.append(args) or "match")
        self.assertEqual(result.functional_result, "passed")
        self.assertNotIn("SECRET", repr(seen) + repr(result) + json.dumps(result.as_dict()))
        replies.data["ports"]["18989/tcp"][0]["HostPort"] = "99"
        self.assertEqual(self.observe("radarr", query_runner=replies).functional_result, "unavailable")

    def test_route_and_functional_results_are_independent(self):
        self.assertEqual(self.observe(application_runner=lambda *a: "failed").route_result, "match")
        result = self.observe(route_runner=lambda *a: "unavailable")
        self.assertEqual(result.functional_result, "passed")
        self.assertEqual(result.route_result, "unavailable")

    def test_errors_do_not_leak_credentials(self):
        def broken(*args):
            raise RuntimeError("SECRET /private/path")
        result = self.observe("radarr", application_runner=broken)
        self.assertNotIn("SECRET", repr(result) + json.dumps(result.as_dict()))
        self.assertEqual(result.functional_result, "unavailable")

    def test_radarr_predicate_requires_exact_sentinel(self):
        good = {"id": 1, "path": "/media/root", "accessible": True, "unmappedFolders": [
            {"name": "Mpkg Sentinel (2000)", "path": "/media/root/Mpkg Sentinel (2000)"}]}
        def evaluate(value):
            return predicate_result("radarr", json.dumps(value), 1, "/media/root", "Mpkg Sentinel (2000)")
        self.assertTrue(evaluate(good))
        for key, value in (("id", True), ("path", "/wrong"), ("accessible", False), ("unmappedFolders", [])):
            bad = dict(good, **{key: value})
            self.assertFalse(evaluate(bad))
        with self.assertRaises(ValueError):
            predicate_result("sonarr", '{"status":"NO","status":"OK"}', 0, "", "")


class WorkerTests(unittest.TestCase):
    def setUp(self):
        owner = self
        self.requests = []
        self.body = b'{"status":"OK"}'
        self.status = 200
        self.delay = 0
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append((self.path, self.headers.get("X-Api-Key")))
                time.sleep(owner.delay)
                self.send_response(owner.status)
                self.send_header("Location", "http://127.0.0.1:1/leak")
                self.end_headers()
                try:
                    self.wfile.write(owner.body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
    def run_worker(self, *, pids=None, mismatch=False, application="sonarr", timeout=2):
        predicate = fixture(application, self.port)[2]
        with app.hold_namespace(os.getpid()) as ns:
            if mismatch:
                ns = (ns[0], (0, 0))
            return app.run_application(dict(app.asdict(predicate), timeout=timeout,
                pids=[os.getpid()] if pids is None else pids), "SECRET" if application == "radarr" else "", ns)
    def test_owned_listener_and_full_observer(self):
        self.assertEqual(self.run_worker(), "passed")
        result = app.observe_application(*fixture(port=self.port), context_guard=lambda *a: True,
                                        query_runner=Replies(port=self.port))
        self.assertEqual(result.functional_result, "passed")
        self.assertEqual(result.route_result, "match")
        self.assertTrue(all(key is None for _, key in self.requests))
    def test_namespace_mismatch_and_wrong_listener_block_credentials(self):
        self.assertEqual(self.run_worker(mismatch=True, application="radarr"), "unavailable")
        self.assertEqual(self.run_worker(pids=[], application="radarr"), "unavailable")
        self.assertEqual(self.requests, [])
    def test_radarr_authenticated_get_only(self):
        self.body = json.dumps({"id": 1, "path": "/media/root", "accessible": True,
            "unmappedFolders": [{"name": "Mpkg Sentinel (2000)", "path": "/media/root/Mpkg Sentinel (2000)"}]}).encode()
        self.assertEqual(self.run_worker(application="radarr"), "passed")
        self.assertEqual(self.requests, [("/api/v3/rootfolder/1?timeout=true", "SECRET")])
    def test_redirect_malformed_and_oversized_response(self):
        self.status = 302
        self.assertEqual(self.run_worker(application="radarr"), "failed")
        self.assertEqual(len(self.requests), 1)
        self.status = 200
        for body in (b'not json', b'x' * 65537):
            self.body = body
            self.assertEqual(self.run_worker(), "unavailable")
    def test_timeout_no_retry(self):
        self.delay = 0.3
        self.assertEqual(self.run_worker(timeout=0.1), "unavailable")
        self.assertEqual(len(self.requests), 1)


if __name__ == "__main__":
    unittest.main()
