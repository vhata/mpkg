"""Combined evidence from owned fixtures; no production host operations."""
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from mpkg_manager import endpoint_checks
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.observations import ObservationBatch
from mpkg_manager.observe_files import observe_files
from mpkg_manager.observe_native import SERVICE_QUERY, observe_resources
from mpkg_manager.observe_packages import QUERY as PACKAGE_TEST_QUERY, observe_package_requests
from mpkg_manager.planning import build_report
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.query_process import QueryResult
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T10:00:00Z"
NOW = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
PRIVATE = "pipeline-private-sentinel"


class FixtureIdentities:
    def user(self, uid):
        return "fixture-user" if uid == os.geteuid() else None

    def group(self, gid):
        return "fixture-group" if gid == os.getegid() else None


class ObservationPipelineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "private-inputs"
        self.inputs.mkdir(mode=0o700)
        self.config = self.inputs / "private-config.env"
        self.config.write_text(PRIVATE + "=original\n")
        self.config.chmod(0o600)
        policy_dir = self.root / "policy"
        policy_dir.mkdir(mode=0o700)
        policy_path = policy_dir / "host-policy.toml"
        policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                              f'allowed_input_roots={json.dumps([str(self.inputs)])}\n')
        policy_path.chmod(0o600)
        self.policy = load_host_policy(path=policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.store_path = self.root / "records"
        self.store = HostStore.create(self.store_path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)
        self.package_result = QueryResult("ok", b"", 0)
        self.package_calls = []
        self.requests = []
        requests = self.requests
        self.response_status = [200]
        response_status = self.response_status

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(response_status[0])
                self.send_header("X-Private", PRIVATE)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        prepared = self.recorder.prepare(expected_revision=0, input_id="config-inputs",
                                         base_directory=str(self.inputs), path=self.config.name)
        self.reference = prepared.reference
        self.declaration = self.make_declaration()
        self.recorder.adopt(self.declaration, 0, ["daemon", "config", "package"], prepared_inputs=[prepared])

    def stop_server(self):
        self.server.shutdown()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())

    def make_declaration(self, *, expected_status=200, logical="daemon", suffix=""):
        return load_declaration(f'''schema=1
[[components]]
id="app"
purpose="combined evidence fixture"
resources=["{logical}","config","package"]
[[resources]]
id="package"
kind="package"
identity={{name="virtual-fixture"}}
manage=["present"]
desired={{present=true}}
[[resources]]
id="{logical}"
kind="service"
identity={{manager="system",unit="example.service"}}
manage=["running"]
desired={{running=true}}
input={{bundle="config-inputs"}}
checks=["route"]
[[resources]]
id="config"
kind="file"
identity={{path={json.dumps(str(self.config))}}}
manage=["present","mode"]
desired={{present=true,mode=0o600}}
[[inputs]]
id="config-inputs"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="{self.config.name}",classification="protected",reference="{self.reference}"}}]
[[checks]]
id="route"
kind="endpoint"
resource="{logical}"
url="http://127.0.0.1:{self.server.server_port}/{PRIVATE}"
expected_status={expected_status}
timeout_seconds=2
{suffix}'''.encode())

    def native_query(self, argv):
        self.assertEqual(argv, SERVICE_QUERY + ("example.service",))
        values = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                  "UnitFileState": "enabled", "Type": "simple", "MainPID": "123",
                  "InvocationID": "1234567890abcdef1234567890abcdef",
                  "ActiveEnterTimestampMonotonic": "100000"}
        return QueryResult("ok", "".join(f"{key}={value}\n" for key, value in values.items()).encode())

    def package_query(self, argv):
        self.assertEqual(argv, PACKAGE_TEST_QUERY + ("virtual-fixture",))
        self.package_calls.append(argv)
        return self.package_result

    def files(self):
        return {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode,
                            path.stat().st_uid, path.stat().st_gid)
                for path in self.store_path.iterdir()}

    def collect(self, declaration=None):
        declaration = self.declaration if declaration is None else declaration
        current = self.store.current()
        target = {"revision": current["revision"], "snapshot_id": current["snapshot_id"]}
        resources = declaration.model["resources"]
        with patch("subprocess.Popen", side_effect=AssertionError("Unexpected native process")):
            native = observe_resources([r for r in resources if r["kind"] == "service"],
                host_id=HOST, observed_at=WHEN, runner=self.native_query)
            metadata = observe_files([r for r in resources if r["kind"] == "file"],
                host_id=HOST, observed_at=WHEN, identities=FixtureIdentities())
            packages = observe_package_requests([r for r in resources if r["kind"] == "package"],
                host_id=HOST, observed_at=WHEN, runner=self.package_query)
            inputs = self.recorder.observe_inputs(**target, observed_at=WHEN)
        # Disjoint source ownership is explicit test assembly, not a production
        # observation coordinator or automatic collector invoked by recording.
        facts = ObservationBatch(HOST, WHEN, native.facts + metadata.facts + packages.facts,
            native.coverage + metadata.coverage + packages.coverage,
            tuple(dict.fromkeys(native.limitations + metadata.limitations + packages.limitations)))
        with patch.object(endpoint_checks, "utc_now", return_value=WHEN):
            endpoints = endpoint_checks.collect_endpoint_checks(self.store, **target)
        return current, facts, inputs, endpoints

    def report(self, collected, *, declaration=None, selected_components=None):
        current, facts, inputs, endpoints = collected
        # Report construction must use collected evidence, never initiate I/O.
        with patch("subprocess.Popen", side_effect=AssertionError("Report process")), \
             patch("socket.socket", side_effect=AssertionError("Report network")), \
             patch("os.open", side_effect=AssertionError("Report filesystem")), \
             patch.object(HostStore, "current", side_effect=AssertionError("Report store")):
            return build_report(self.declaration if declaration is None else declaration,
                current, facts.as_dict(), host_id=HOST, now=NOW,
                input_observations=inputs, endpoint_observations=endpoints,
                selected_components=selected_components).as_dict()

    def assert_private(self, report, endpoints):
        public = json.dumps(report) + json.dumps(endpoints.as_dict())
        for value in (PRIVATE, str(self.config), self.reference,
                      hashlib.sha256(self.config.read_bytes()).hexdigest()):
            self.assertNotIn(value, public)
        self.assertFalse(report["executable"])
        self.assertIn("application_not_implemented", report["blockers"])
        self.assertEqual(report["protected_inputs"]["full_input_closure"], "unverified")
        self.assertTrue(all(row["functional_result"] == "unverified"
                            for row in endpoints.as_dict()["checks"]))
        self.assertEqual(report["endpoint_checks"]["functional_result"], "unverified")
        for resource in (*report["resources"], *report["retained_resources"],
                         *report["unselected_resources"]):
            for check in resource["checks"]:
                self.assertEqual(check["result"], "unknown")
                self.assertEqual(check["functional_result"], "unverified")

    def test_real_capture_metadata_and_http_worker_preserve_independent_evidence(self):
        before = self.files()
        collected = self.collect()
        report = self.report(collected)
        self.assertEqual(self.files(), before)
        self.assertEqual(self.requests, ["/" + PRIVATE])
        self.assertEqual(len(self.package_calls), 2)
        package = next(row for row in report["resources"] if row["resource_id"] == "package")
        self.assertEqual(package["properties"][0]["evidence_source"], "pacman_dependency_satisfaction")
        self.assertIn("native_resolution_not_performed", report["blockers"])
        self.assertTrue(all(prop["comparison"] == "agreement"
                            for row in report["resources"] for prop in row["properties"]))
        self.assertEqual(report["protected_inputs"]["entries"][0]["state"], "same")
        self.assertIn("input_freshness_unverified", report["blockers"])
        self.assertEqual([row["route_result"] for row in collected[3].as_dict()["checks"]], ["match", "match"])
        self.assertEqual(report["endpoint_checks"]["coverage"], "complete")
        daemon = next(row for row in report["resources"] if row["resource_id"] == "daemon")
        self.assertEqual([row["route_result"] for row in daemon["checks"]], ["match", "match"])
        self.assert_private(report, collected[3])

    def test_changed_protected_bytes_do_not_change_metadata_or_route_agreement(self):
        self.config.write_text(PRIVATE + "=changed\n")
        before = self.files()
        collected = self.collect()
        report = self.report(collected)
        self.assertEqual(self.files(), before)
        self.assertEqual(report["protected_inputs"]["entries"][0]["state"], "changed")
        self.assertIn("protected_input_changed", report["blockers"])
        self.assertTrue(all(prop["comparison"] == "agreement"
                            for row in report["resources"] for prop in row["properties"]))
        self.assertTrue(all(row["route_result"] == "match" for row in collected[3].as_dict()["checks"]))
        self.assertTrue(all(row["route_result"] == "match" for row in report["endpoint_checks"]["entries"]))
        self.assert_private(report, collected[3])

    def test_recorded_rename_keeps_original_route_predicate_without_automatic_probe(self):
        prepared = self.recorder.prepare(expected_revision=1, input_id="config-inputs",
                                         base_directory=str(self.inputs), path=self.config.name)
        self.reference = prepared.reference
        changed = self.make_declaration(expected_status=204, logical="renamed")
        self.recorder.record_intent(changed, 1, prepared_inputs=[prepared])
        self.assertEqual(self.requests, [])
        before = self.files()
        collected = self.collect(changed)
        report = self.report(collected, declaration=changed)
        self.assertEqual(self.files(), before)
        rows = collected[3].as_dict()["checks"]
        self.assertEqual([(row["role"], row["resource_id"], row["route_result"]) for row in rows],
                         [("accepted", "daemon", "match"), ("current", "renamed", "mismatch")])
        self.assertEqual(len(self.requests), 2)
        renamed = next(row for row in report["resources"] if row["resource_id"] == "renamed")
        self.assertEqual([(row["role"], row["route_result"]) for row in renamed["checks"]],
                         [("accepted", "match"), ("current", "mismatch")])
        self.assertEqual(report["protected_inputs"]["entries"][0]["state"], "same")
        self.assert_private(report, collected[3])

    def test_unrecorded_source_comment_invalidates_bound_inputs_not_live_metadata(self):
        collected = self.collect()
        changed = self.make_declaration(suffix="# exact source changed\n")
        self.assertEqual(changed.sha256, self.declaration.sha256)
        report = self.report(collected, declaration=changed)
        self.assertEqual(report["protected_inputs"]["reason"], "intent_not_recorded")
        self.assertEqual(report["endpoint_checks"]["reason"], "intent_not_recorded")
        self.assertTrue(all(row["route_result"] == "unavailable" for row in report["endpoint_checks"]["entries"]))
        self.assertTrue(all(prop["comparison"] == "agreement"
                            for row in report["resources"] for prop in row["properties"]))
        self.assert_private(report, collected[3])

    def test_route_mismatch_does_not_invalidate_matching_inputs_or_metadata(self):
        self.response_status[0] = 503
        before = self.files()
        collected = self.collect()
        report = self.report(collected)
        self.assertEqual(self.files(), before)
        self.assertEqual(report["protected_inputs"]["entries"][0]["state"], "same")
        self.assertTrue(all(prop["comparison"] == "agreement"
                            for row in report["resources"] for prop in row["properties"]))
        self.assertTrue(all(row["route_result"] == "mismatch" for row in report["endpoint_checks"]["entries"]))
        self.assertIn("required_check_unverified", report["blockers"])
        self.assert_private(report, collected[3])

    def test_empty_component_selection_keeps_complete_input_and_endpoint_evidence(self):
        collected = self.collect()
        report = self.report(collected, selected_components=[])
        self.assertEqual(report["resources"], [])
        self.assertEqual(len(report["unselected_resources"]), 3)
        self.assertEqual(report["protected_inputs"]["entries"][0]["state"], "same")
        self.assertEqual(report["endpoint_checks"]["coverage"], "complete")
        self.assertEqual(report["endpoint_checks"]["required_checks"], 2)
        self.assertTrue(all(row["route_result"] == "match" for row in report["endpoint_checks"]["entries"]))
        self.assert_private(report, collected[3])

    def test_unmet_package_request_stays_unknown_without_discarding_other_evidence(self):
        self.package_result = QueryResult("ok", b"virtual-fixture\n", 127)
        before = self.files()
        collected = self.collect()
        report = self.report(collected)
        self.assertEqual(self.files(), before)
        self.assertEqual(report["protected_inputs"]["entries"][0]["state"], "same")
        for row in report["resources"]:
            self.assertTrue(all(prop["comparison"] == ("unknown" if row["kind"] == "package" else "agreement")
                                for prop in row["properties"]))
        self.assertTrue(all(row["route_result"] == "match" for row in report["endpoint_checks"]["entries"]))
        self.assert_private(report, collected[3])


if __name__ == "__main__":
    unittest.main()
