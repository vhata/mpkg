"""Recorded endpoint coverage uses private stores and owned loopback fixtures."""
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager import endpoint_checks as collector
from mpkg_manager.declarations import load_declaration
from mpkg_manager._endpoint_process import ProbeResult
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T10:00:00Z"
PRIVATE = "private-collector-predicate"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


def declaration(*, logical="daemon", status=200, port=12345, kind="service", alias="local",
                checks=("health",), unlinked=(), timeout=1, source_suffix="", unit="example.service"):
    identity = (f'manager="system",unit="{unit}"' if kind == "service"
                else f'engine="{alias}",project="example"')
    text = f'''schema=1
components=[]
[[resources]]
id="{logical}"
kind="{kind}"
identity={{{identity}}}
checks={json.dumps(list(checks))}
'''
    for name in (*checks, *unlinked):
        text += f'''[[checks]]
id="{name}"
kind="endpoint"
resource="{logical}"
url="http://127.0.0.1:{port}/{PRIVATE}/{name}"
expected_status={status}
timeout_seconds={timeout}
'''
    return load_declaration((text + source_suffix).encode())


class EndpointCheckCollectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "records"
        self.store = HostStore.create(self.directory, HOST, owner_uid=os.geteuid(),
                                     engine_aliases={"local": "fixture-engine", "alias": "fixture-engine"})
        self.addCleanup(self.store.close)
        self.calls = []

    def runner(self, url, timeout):
        self.calls.append((url, timeout))
        return ProbeResult("ok", 200)

    def collect(self, **kwargs):
        current = self.store.current()
        with patch.object(collector, "utc_now", return_value=WHEN):
            return collector.collect_endpoint_checks(
                self.store, revision=current["revision"], snapshot_id=current["snapshot_id"],
                runner=kwargs.pop("runner", self.runner), **kwargs)

    def collect_valid(self, **kwargs):
        try:
            return self.collect(**kwargs)
        except collector.EndpointCollectionError as error:
            self.fail(f"Valid recorded endpoint context was refused: {error.code}")

    def assert_error(self, code, callback):
        with self.assertRaises(collector.EndpointCollectionError) as raised:
            callback()
        self.assertEqual(str(raised.exception), code)
        self.assertEqual(raised.exception.code, code)

    def test_identical_current_and_accepted_predicates_share_one_probe_without_losing_roles(self):
        original = declaration()
        decision = self.store.adopt(original, 0, ["daemon"])
        batch = self.collect()
        public = batch.as_dict()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(batch.probe_count, 1)
        self.assertEqual([row["role"] for row in public["checks"]], ["accepted", "current"])
        self.assertTrue(all(row["route_result"] == "match" for row in public["checks"]))
        self.assertIs(batch.checks[0].observation, batch.checks[1].observation)
        self.assertTrue(batch.matches_context(host_id=HOST, revision=1, snapshot_id=decision["snapshot_id"]))
        self.assertFalse(batch.matches_context(host_id=HOST, revision=2, snapshot_id=decision["snapshot_id"]))
        self.assertTrue(all(row.functional_result == "unverified" for row in batch.checks))
        self.assertTrue(all(row.limitations == collector.LIMITATIONS for row in batch.checks))
        self.assertFalse(public["executable"])
        self.assertTrue(public["coverage_complete"])

    def test_same_id_changed_predicate_gets_distinct_accepted_and_current_observations(self):
        original = declaration()
        first = self.store.adopt(original, 0, ["daemon"])
        latest = self.store.record_intent(declaration(status=204), 1)
        batch = self.collect_valid()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([row.as_dict()["route_result"] for row in batch.checks], ["match", "mismatch"])
        accepted = batch.checks[0]
        record = self.store.current()["resources"][0]
        context = dict(host_id=HOST, role="accepted", snapshot_id=first["snapshot_id"],
                       adoption_revision=1, stable_id=record["stable_id"])
        self.assertTrue(accepted.matches_context(original.model["checks"][0], original.model["resources"][0], **context))
        self.assertFalse(accepted.matches_context(declaration(status=204).model["checks"][0],
                                                 original.model["resources"][0], **context))
        self.assertFalse(accepted.matches_context(original.model["checks"][0], original.model["resources"][0],
                                                 **(context | {"snapshot_id": latest["snapshot_id"]})))
        self.assertFalse(accepted.matches_context(original.model["checks"][0], original.model["resources"][0],
                                                 **(context | {"role": "current"})))

    def test_removed_and_relinquished_accepted_checks_remain_explicit(self):
        self.store.adopt(declaration(), 0, ["daemon"])
        stable = self.store.current()["resources"][0]["stable_id"]
        self.store.relinquish([stable], 1)
        self.store.record_intent(EMPTY, 2)
        batch = self.collect()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(batch.checks), 1)
        row = batch.checks[0].as_dict()
        self.assertEqual((row["role"], row["management"], row["adoption_revision"]), ("accepted", "relinquished", 1))
        self.assertEqual(row["stable_id"], stable)
        self.assertEqual(row["functional_result"], "unverified")

    def test_logical_rename_preserves_original_accepted_labels_and_physical_binding(self):
        self.store.adopt(declaration(), 0, ["daemon"])
        self.store.record_intent(declaration(logical="renamed"), 1)
        batch = self.collect()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([row.as_dict()["resource_id"] for row in batch.checks], ["daemon", "renamed"])
        self.assertEqual([row.observation.as_dict()["resource_id"] for row in batch.checks], ["daemon", "renamed"])

    def test_unreferenced_root_checks_never_get_probed(self):
        self.store.record_intent(declaration(checks=(), unlinked=("unused",)), 0)
        self.assertEqual(self.collect().checks, ())
        self.assertEqual(self.calls, [])

    def test_count_and_time_limits_keep_complete_unavailable_coverage(self):
        self.store.record_intent(declaration(checks=("first", "second", "third")), 0)
        batch = self.collect(max_probes=1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual([row.as_dict()["reason"] for row in batch.checks],
                         ["status_matches", "collection_probe_limit", "collection_probe_limit"])
        self.calls.clear()
        with patch.object(collector.time, "monotonic", return_value=0):
            batch = self.collect(budget_seconds=1, runner=lambda url, timeout: ProbeResult("timeout"))
        self.assertEqual(batch.probe_count, 3)
        self.assertTrue(all(row.observation.reason == "timeout" for row in batch.checks))
        clock = [0]
        def consume(url, timeout):
            self.calls.append((url, timeout))
            clock[0] += 0.6
            return ProbeResult("ok", 200)
        with patch.object(collector.time, "monotonic", side_effect=lambda: clock[0]):
            batch = self.collect(budget_seconds=1, runner=consume)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][1], 1)
        self.assertEqual([row.as_dict()["reason"] for row in batch.checks],
                         ["status_matches", "collection_budget_exhausted", "collection_budget_exhausted"])

    def test_changed_revision_returns_no_batch(self):
        self.store.record_intent(declaration(), 0)
        def change(url, timeout):
            self.store.record_intent(EMPTY, 1)
            return ProbeResult("ok", 200)
        self.assert_error("endpoint_revision_changed", lambda: self.collect(runner=change))

    def test_public_projection_is_immutable_and_redacts_predicates_and_snapshot_digests(self):
        decision = self.store.adopt(declaration(), 0, ["daemon"])
        batch = self.collect()
        public = batch.as_dict()
        encoded = json.dumps(public) + repr(batch)
        for value in (PRIVATE, decision["snapshot_id"], "expected_status", "url", "example.service"):
            self.assertNotIn(value, encoded)
        self.assertEqual(public["observed_at"], WHEN)
        public["checks"][0]["limitations"].clear()
        public["checks"].clear()
        self.assertEqual(len(batch.as_dict()["checks"]), 2)
        self.assertTrue(batch.as_dict()["checks"][0]["limitations"])
        with self.assertRaises(FrozenInstanceError):
            batch.probe_count = 7
        with self.assertRaises(FrozenInstanceError):
            batch.checks[0].unavailable_reason = "changed"

    def test_exact_source_snapshot_is_required_even_when_normalized_model_is_unchanged(self):
        original = declaration()
        first = self.store.record_intent(original, 0)
        changed = declaration(source_suffix="# source-only change\n")
        self.assertEqual(original.canonical_bytes, changed.canonical_bytes)
        second = self.store.record_intent(changed, 1)
        self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])
        self.assert_error("endpoint_revision_changed", lambda: collector.collect_endpoint_checks(
            self.store, revision=2, snapshot_id=first["snapshot_id"], runner=self.runner))
        self.assert_error("endpoint_revision_changed", lambda: collector.collect_endpoint_checks(
            self.store, revision=1, snapshot_id=first["snapshot_id"], runner=self.runner))
        self.assertEqual(self.calls, [])
        batch = self.collect()
        self.assertFalse(batch.matches_context(host_id=HOST, revision=2, snapshot_id=first["snapshot_id"]))
        self.assertTrue(batch.matches_context(host_id=HOST, revision=2, snapshot_id=second["snapshot_id"]))

    def test_only_actual_host_store_and_bounded_request_parameters_are_accepted(self):
        decision = self.store.record_intent(declaration(), 0)
        valid = dict(revision=1, snapshot_id=decision["snapshot_id"], runner=self.runner)
        for field, values in {"revision": (True, 0, -1, 2**63, "1"),
                              "snapshot_id": (None, "private-invalid", "A" * 64),
                              "budget_seconds": (True, 0, 301, 1.5),
                              "max_probes": (True, 0, 257, 1.5), "runner": (7, {})}.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assert_error("invalid_endpoint_collection_request", lambda: collector.collect_endpoint_checks(
                        self.store, **(valid | {field: value})))
        for store in (None, self.store.current(), object()):
            self.assert_error("invalid_endpoint_collection_request", lambda: collector.collect_endpoint_checks(store, **valid))
        self.assertEqual(self.calls, [])

    def test_unbound_compose_context_is_covered_without_network(self):
        self.store.record_intent(declaration(kind="compose", alias="unknown"), 0)
        row = self.collect().checks[0]
        self.assertEqual(self.calls, [])
        self.assertIsNone(row.observation)
        self.assertEqual(row.as_dict()["reason"], "physical_identity_unbound")
        self.assertEqual(row.as_dict()["functional_result"], "unverified")

    def test_compose_alias_spelling_can_share_only_the_same_physical_engine(self):
        original = declaration(kind="compose")
        self.store.adopt(original, 0, ["daemon"])
        self.store.record_intent(declaration(kind="compose", alias="alias"), 1)
        batch = self.collect()
        self.assertEqual(len(self.calls), 1)
        self.assertIs(batch.checks[0].observation, batch.checks[1].observation)
        record = self.store.current()["resources"][0]
        scope = dict(host_id=HOST, role="accepted", stable_id=record["stable_id"], adoption_revision=1,
                     snapshot_id=record["accepted_checks"]["snapshot_id"])
        resource = original.model["resources"][0]
        self.assertTrue(batch.checks[0].matches_context(original.model["checks"][0], resource,
                                                       engine_aliases={"local": "fixture-engine"}, **scope))
        self.assertFalse(batch.checks[0].matches_context(original.model["checks"][0], resource,
                                                        engine_aliases={"local": "different-engine"}, **scope))

    def test_same_id_url_timeout_and_physical_replacements_never_share_evidence(self):
        self.store.adopt(declaration(), 0, ["daemon"])
        for revision, changes in enumerate(({"port": 12346}, {"timeout": 2}, {"unit": "replacement.service"}), 1):
            with self.subTest(changes=changes):
                self.store.record_intent(declaration(**changes), revision)
                self.calls.clear()
                batch = self.collect_valid()
                self.assertEqual(batch.probe_count, 2)
                self.assertEqual(len(self.calls), 2)
                self.assertIsNot(batch.checks[0].observation, batch.checks[1].observation)

    def test_fewer_current_links_cannot_hide_original_accepted_checks(self):
        self.store.adopt(declaration(checks=("old", "kept")), 0, ["daemon"])
        self.store.record_intent(declaration(checks=("kept",), unlinked=("old", "unused")), 1)
        batch = self.collect()
        self.assertEqual([(row.as_dict()["role"], row.as_dict()["check_id"]) for row in batch.checks],
                         [("accepted", "old"), ("accepted", "kept"), ("current", "kept")])
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(all("unused" not in url for url, _ in self.calls))

    def test_explicit_readoption_changes_accepted_baseline(self):
        self.store.adopt(declaration(), 0, ["daemon"])
        self.store.adopt(declaration(status=204), 1, ["daemon"])
        batch = self.collect()
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(all(row.as_dict()["route_result"] == "mismatch" for row in batch.checks))
        self.assertEqual(batch.checks[0].as_dict()["adoption_revision"], 2)

    def test_nonendpoint_linked_checks_stay_outside_endpoint_coverage(self):
        original = declaration(checks=())
        raw = original.source_bytes.replace(b'checks=[]', b'checks=["state"]')
        raw += b'''[[checks]]
id="state"
kind="service"
resource="daemon"
timeout_seconds=1
expected={running=true}
'''
        self.store.adopt(load_declaration(raw), 0, ["daemon"])
        self.assertEqual(self.collect().checks, ())
        self.assertEqual(self.calls, [])

    def test_whole_coverage_count_and_size_are_checked_before_any_request(self):
        self.store.adopt(declaration(checks=("first", "second")), 0, ["daemon"])
        for limit in (0, 3):
            with self.subTest(limit=limit), patch.object(collector, "MAX_CHECKS", limit):
                self.assert_error("endpoint_coverage_limit", self.collect)
        with patch.object(collector, "MAX_MANIFEST_BYTES", 100):
            self.assert_error("endpoint_coverage_limit", self.collect)
        self.assertEqual(self.calls, [])
        with patch.object(collector, "MAX_CHECKS", 4):
            self.assertEqual(len(self.collect().checks), 4)

    def test_late_total_and_per_probe_completions_cannot_return_matching_routes(self):
        self.store.record_intent(declaration(checks=("first", "second")), 0)
        for budget, elapsed, expected in ((2, 2.1, "collection_budget_exhausted"),
                                          (4, 1.1, "collection_probe_timeout")):
            with self.subTest(budget=budget):
                clock = [0]
                def late(url, timeout):
                    clock[0] += elapsed
                    return ProbeResult("ok", 200)
                with patch.object(collector.time, "monotonic", side_effect=lambda: clock[0]):
                    batch = self.collect(budget_seconds=budget, runner=late)
                self.assertTrue(all(row.observation is None for row in batch.checks))
                self.assertTrue(all(row.as_dict()["reason"] == expected for row in batch.checks))

    def test_original_long_timeout_is_not_rewritten_to_fit_the_budget(self):
        original = declaration(timeout=5)
        decision = self.store.record_intent(original, 0)
        batch = self.collect(budget_seconds=2)
        self.assertEqual(self.calls, [])
        self.assertEqual(batch.checks[0].as_dict()["reason"], "collection_budget_exhausted")
        self.assertTrue(batch.checks[0].matches_context(original.model["checks"][0], original.model["resources"][0],
                                                       host_id=HOST, role="current", snapshot_id=decision["snapshot_id"]))
        changed = original.model["checks"][0] | {"timeout_seconds": 2}
        self.assertFalse(batch.checks[0].matches_context(changed, original.model["resources"][0], host_id=HOST,
                                                        role="current", snapshot_id=decision["snapshot_id"]))

    def test_shorter_later_check_can_run_after_a_long_check_does_not_fit(self):
        raw = declaration(checks=("long", "short"), timeout=5).source_bytes
        before, after = raw.rsplit(b"timeout_seconds=5", 1)
        self.store.record_intent(load_declaration(before + b"timeout_seconds=1" + after), 0)
        batch = self.collect(budget_seconds=2)
        self.assertEqual([row.as_dict()["reason"] for row in batch.checks],
                         ["collection_budget_exhausted", "status_matches"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][1], 1)

    def test_runner_failures_stay_fixed_and_cancellation_propagates(self):
        self.store.record_intent(declaration(), 0)
        def error(url, timeout):
            raise RuntimeError(PRIVATE)
        self.assertEqual(self.collect(runner=error).checks[0].as_dict()["reason"], "endpoint_runner_failed")
        self.assertEqual(self.collect(runner=lambda url, timeout: {"code": "ok", "status": 200}).checks[0]
                         .as_dict()["reason"], "invalid_endpoint_result")
        def cancel(url, timeout):
            raise KeyboardInterrupt(PRIVATE)
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.collect(runner=cancel)
        self.assertEqual(str(raised.exception), PRIVATE)
        self.assertEqual(self.store.current()["revision"], 1)

    def test_final_store_failure_invalidates_the_entire_batch(self):
        self.store.record_intent(declaration(), 0)
        def close(url, timeout):
            self.store.close()
            return ProbeResult("ok", 200)
        self.assert_error("endpoint_store_unavailable", lambda: self.collect(runner=close))

    def test_readonly_collection_preserves_store_files_and_ownership_metadata(self):
        self.store.adopt(declaration(), 0, ["daemon"])
        self.store.close()
        def inventory():
            return {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode,
                                path.stat().st_uid, path.stat().st_gid) for path in self.directory.iterdir()}
        before = inventory()
        self.store = HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.assertEqual(len(self.collect().checks), 2)
        self.store.close()
        self.assertEqual(inventory(), before)

    def test_real_default_worker_uses_owned_fixture_and_no_store_write(self):
        import socketserver
        import threading
        requests = []
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                raw = b""
                while b"\r\n\r\n" not in raw and len(raw) < 8192:
                    chunk = self.request.recv(1024)
                    if not chunk:
                        break
                    raw += chunk
                requests.append(raw)
                self.request.sendall(b"HTTP/1.1 200 OK\r\nX-Private: private-response\r\n\r\nprivate-body")
        with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
            server.timeout = 3
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            self.store.adopt(declaration(port=server.server_address[1]), 0, ["daemon"])
            before = (self.directory / "state.sqlite3").read_bytes()
            batch = self.collect(runner=None)
            thread.join(4)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(requests), 1)
        self.assertIn(f"GET /{PRIVATE}/health HTTP/1.1\r\n".encode(), requests[0])
        self.assertEqual((self.directory / "state.sqlite3").read_bytes(), before)
        self.assertTrue(all(row.as_dict()["route_result"] == "match" for row in batch.checks))
        public = json.dumps(batch.as_dict())
        for value in (PRIVATE, "private-response", "private-body"):
            self.assertNotIn(value, public)

    def test_collection_start_time_is_shared_without_upgrading_functional_evidence(self):
        self.store.adopt(declaration(checks=("one", "two")), 0, ["daemon"])
        timestamps = []
        def runner(url, timeout):
            timestamps.append(WHEN)
            return ProbeResult("ok", 200)
        with patch.object(collector, "utc_now", return_value=WHEN) as clock:
            current = self.store.current()
            batch = collector.collect_endpoint_checks(self.store, revision=current["revision"],
                                                       snapshot_id=current["snapshot_id"], runner=runner)
        clock.assert_called_once_with()
        self.assertEqual(batch.observed_at, WHEN)
        self.assertTrue(all(row.observation.observed_at == WHEN for row in batch.checks))
        self.assertEqual(batch.functional_result, "unverified")
        self.assertTrue(set(collector.LIMITATIONS) <= set(batch.limitations))
        self.assertEqual(batch.as_dict()["limitations"], list(batch.limitations))
        self.assertTrue(all(row.as_dict()["functional_result"] == "unverified" for row in batch.checks))

    def test_result_context_and_batch_binding_cannot_be_mixed_accidentally(self):
        self.store.adopt(declaration(), 0, ["daemon"])
        original = self.collect()
        self.store.record_intent(declaration(status=204), 1)
        latest = self.collect()
        self.assert_error("invalid_endpoint_check_result", lambda: replace(
            latest.checks[1], observation=original.checks[0].observation))
        self.assert_error("invalid_endpoint_check_batch", lambda: replace(
            latest, checks=(original.checks[1],)))
        self.assert_error("invalid_endpoint_check_batch", lambda: replace(
            latest, checks=(latest.checks[0], latest.checks[0])))
        self.assert_error("invalid_endpoint_check_batch", lambda: replace(
            latest, host_id="22345678-1234-4234-8234-123456789abc"))
        self.assert_error("invalid_endpoint_check_batch", lambda: replace(
            latest, observed_at="2026-11-02T10:00:01Z"))

    def test_expensive_initial_store_reads_consume_the_network_scheduling_budget(self):
        self.store.record_intent(declaration(), 0)
        current_method = self.store.current
        clock = [0]
        def read():
            current = current_method()
            clock[0] += 2
            return current
        current = current_method()
        with patch.object(self.store, "current", side_effect=read), \
                patch.object(collector.time, "monotonic", side_effect=lambda: clock[0]):
            batch = collector.collect_endpoint_checks(self.store, revision=current["revision"],
                                                       snapshot_id=current["snapshot_id"],
                                                       budget_seconds=1, runner=self.runner)
        self.assertEqual(self.calls, [])
        self.assertEqual(batch.checks[0].as_dict()["reason"], "collection_budget_exhausted")
