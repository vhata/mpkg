"""Recorded check manifests and collection through private history and adapter seams."""
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager import runtime_checks as checks
from mpkg_manager._access_process import AccessResult
from mpkg_manager._endpoint_process import ProbeResult
from mpkg_manager.declarations import canonical_json, load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.query_process import QueryResult
from mpkg_manager.store import HostStore
import test_manager_consumer_access as access_fixture
import test_manager_runtime_endpoint as runtime_fixture


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T18:00:00Z"
NOW = datetime.fromisoformat(WHEN)
PRIVATE = "private-runtime-collection-sentinel"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


def declaration(*, endpoint=True, access=True, status=200, port=18080, logical="web",
                kind="service", services=("web",), alias="local", suffix="", operation="read",
                timeout=2, dependency=False, consumer="external:reader"):
    selected = [logical] if endpoint else (["data"] if access else [])
    source = f'''schema=1
[[components]]
id="main"
purpose="Main check fixture"
resources={json.dumps(selected)}
[[components]]
id="other"
purpose="Unselected check fixture"
resources=[]
'''
    if endpoint:
        identity = 'manager="system",unit="web.service"' if kind == "service" else f'engine="{alias}",project="example"'
        source += f'''[[resources]]
id="{logical}"
kind="{kind}"
identity={{{identity}}}
checks=["health"]
requires={json.dumps(["data"] if dependency else [])}
'''
        if kind == "compose":
            source += f'desired={{services={json.dumps(list(services))}}}\n'
        source += f'''[[checks]]
id="health"
kind="endpoint"
resource="{logical}"
url="http://127.0.0.1:{port}/{PRIVATE}"
expected_status={status}
timeout_seconds={timeout}
'''
    if access:
        source += f'''[[resources]]
id="data"
kind="file"
identity={{path="/{PRIVATE}/data"}}
consumers=["{consumer}"]
checks=["access"]
[[checks]]
id="access"
kind="access"
resource="data"
as_user="reader"
operation="{operation}"
consumer="{consumer}"
timeout_seconds={timeout}
'''
    return load_declaration((source + suffix).encode())


class RuntimeCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "store"
        self.aliases = {"local": "engine-1", "alias": "engine-1"}
        self.writer = HostStore.create(self.directory, HOST, owner_uid=os.geteuid(), engine_aliases=self.aliases)
        self.addCleanup(self.writer.close)
        self.policy_path = self.root / "policy.toml"
        self.policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={json.dumps(self.aliases).replace(":", "=")}\n'
                                    f'allowed_input_roots={json.dumps([str(self.root)])}\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.reader = HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.reader.close)
        self.runtime, self.proc = runtime_fixture.Replies(), runtime_fixture.FakeProc()
        self.accounts = access_fixture.Queries()
        self.probes, self.workers = [], []
        self.host_guards = []
        for target in ("subprocess.Popen", "socket.socket"):
            guard = patch(target, side_effect=AssertionError("unexpected real host operation"))
            guard.start()
            self.host_guards.append(guard)
            self.addCleanup(guard.stop)

    def record(self, source=None, *, adopt=False):
        source = declaration() if source is None else source
        revision = self.writer.current()["revision"]
        if adopt:
            return self.writer.adopt(source, revision, [row["id"] for row in source.model["resources"]])
        return self.writer.record_intent(source, revision)

    def context(self):
        current = self.writer.current()
        return {"revision": current["revision"], "snapshot_id": current["snapshot_id"]}

    def manifest(self, **kwargs):
        return checks.runtime_check_manifest(self.reader, self.policy, **(self.context() | kwargs))

    def probe(self, url, timeout):
        self.probes.append((url, timeout))
        return ProbeResult("ok", 200)

    def worker(self, request, *, timeout):
        self.workers.append((request, timeout))
        return AccessResult("ok")

    def collect(self, **kwargs):
        arguments = dict(self.context(), runtime_query_runner=self.runtime, proc_reader=self.proc,
                         probe_runner=self.probe, access_query_runner=self.accounts,
                         access_worker_runner=self.worker)
        arguments.update(kwargs)
        with patch.object(checks, "utc_now", return_value=WHEN):
            return checks.collect_runtime_checks(self.reader, self.policy, **arguments)

    def assert_error(self, code, callback):
        with self.assertRaises(checks.RuntimeCheckError) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)
        self.assertNotIn(PRIVATE, str(raised.exception))

    def test_manifest_and_default_collection_perform_no_runtime_or_access_operations(self):
        self.record(adopt=True)
        manifest = self.manifest()
        batch = self.collect()
        self.assertEqual(len(manifest.as_dict()["checks"]), 4)
        self.assertEqual((self.runtime.calls, self.proc.calls, self.accounts.calls, self.probes, self.workers),
                         ([], [], [], [], []))
        self.assertEqual({row["reason"] for row in batch.as_dict()["checks"]},
                         {"endpoint_collection_not_requested", "access_collection_not_requested"})
        self.assertTrue(batch.matches_manifest(manifest, now=NOW))

    def test_identical_roles_share_complete_observations_without_losing_coverage(self):
        self.record(adopt=True)
        before = {path.name: path.read_bytes() for path in self.directory.iterdir()}
        batch = self.collect(probe_endpoints=True, check_access=True)
        self.assertEqual((batch.endpoint_count, batch.access_count, batch.query_count), (1, 1, 16))
        self.assertEqual((len(self.probes), len(self.workers)), (1, 1))
        rows = batch.as_dict()["checks"]
        self.assertEqual([row["role"] for row in rows], ["accepted", "accepted", "current", "current"])
        self.assertEqual([row.get("route_result", row.get("access_result")) for row in rows], ["match"] * 4)
        accepted = {row.as_dict()["check_id"]: row.observation for row in batch.checks[:2]}
        for row in batch.checks[2:]:
            self.assertIs(accepted[row.as_dict()["check_id"]], row.observation)
        self.assertTrue(batch.matches_manifest(self.manifest(), now=NOW))
        self.assertEqual({path.name: path.read_bytes() for path in self.directory.iterdir()}, before)
        self.assertFalse(batch.as_dict()["executable"])
        self.assertTrue(all(row["functional_result"] == "unverified" for row in rows))

    def test_modes_are_independent(self):
        self.record()
        endpoints = self.collect(probe_endpoints=True)
        self.assertEqual((endpoints.endpoint_count, endpoints.access_count), (1, 0))
        self.assertEqual(self.accounts.calls, [])
        self.runtime.calls.clear()
        access = self.collect(check_access=True)
        self.assertEqual((access.endpoint_count, access.access_count), (0, 1))
        self.assertEqual(self.runtime.calls, [])

    def test_original_and_reused_check_ids_keep_different_predicates(self):
        self.record(declaration(access=False), adopt=True)
        self.record(declaration(access=False, status=204, port=18081))
        batch = self.collect(probe_endpoints=True)
        self.assertEqual([row["route_result"] for row in batch.as_dict()["checks"]], ["match", "mismatch"])
        self.assertEqual([url for url, timeout in self.probes],
                         [f"http://127.0.0.1:18080/{PRIVATE}", f"http://127.0.0.1:18081/{PRIVATE}"])
        self.assertEqual(batch.endpoint_count, 2)

    def test_logical_and_check_id_reuse_cannot_replace_old_target_or_consumer(self):
        self.record(declaration(endpoint=False), adopt=True)
        replacement = declaration(endpoint=False, consumer="external:replacement")
        replacement = load_declaration(replacement.source_bytes.replace(
            f"/{PRIVATE}/data".encode(), f"/{PRIVATE}/replacement".encode()))
        self.record(replacement)
        batch = self.collect(check_access=True)
        self.assertEqual(batch.access_count, 2)
        rows = batch.as_dict()["checks"]
        self.assertEqual([row["consumer_id"] for row in rows], ["external:reader", "external:replacement"])
        self.assertEqual([request["path"] for request, timeout in self.workers],
                         [f"/{PRIVATE}/data", f"/{PRIVATE}/replacement"])
        self.assertTrue(all(row["access_result"] == "match" for row in rows))

    def test_removed_and_relinquished_resources_keep_original_roles(self):
        self.record(adopt=True)
        stable = [row["stable_id"] for row in self.writer.current()["resources"]]
        self.writer.relinquish(stable, 1)
        self.record(EMPTY)
        batch = self.collect(probe_endpoints=True, check_access=True)
        rows = batch.as_dict()["checks"]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["role"] == "accepted" and row["management"] == "relinquished" for row in rows))
        self.assertTrue(all(row["adoption_revision"] == 1 for row in rows))

    def test_selection_keeps_accepted_first_and_excluded_current_explicit(self):
        self.record(adopt=True)
        batch = self.collect(probe_endpoints=True, check_access=True, selected_components=[], max_checks=1)
        rows = batch.as_dict()["checks"]
        self.assertEqual([row["role"] for row in rows], ["accepted", "accepted", "current", "current"])
        self.assertEqual(rows[0].get("route_result", rows[0].get("access_result")), "match")
        self.assertEqual(batch.endpoint_count + batch.access_count, 1)
        self.assertEqual([row["reason"] for row in rows[1:]],
                         ["collection_check_limit", "current_not_selected", "current_not_selected"])
        self.assertTrue(batch.matches_manifest(self.manifest(selected_components=[]), now=NOW))
        self.assertFalse(batch.matches_manifest(self.manifest(), now=NOW))

    def test_owned_listener_and_current_user_workers_with_only_native_queries_injected(self):
        for guard in self.host_guards:
            guard.stop()
        for module in (checks.runtime_endpoint, checks.consumer_access):
            guard = patch.object(module, "run_readonly", side_effect=AssertionError("unexpected native query"))
            guard.start()
            self.addCleanup(guard.stop)
        child = subprocess.Popen([sys.executable, "-I", "-c", runtime_fixture._SERVER],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        def stop():
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
            child.stdout.close()
        self.addCleanup(stop)
        port = int(child.stdout.readline())
        path = self.root / "content"
        path.write_text(PRIVATE)
        source = declaration(kind="compose", port=port, timeout=5)
        self.record(load_declaration(source.source_bytes.replace(
            f"/{PRIVATE}/data".encode(), str(path).encode())), adopt=True)
        self.runtime.container = runtime_fixture.container(child.pid)
        self.runtime.pids = "PID\n" + str(child.pid) + "\n"
        accounts = access_fixture.Queries(uid=os.getuid(), gid=os.getgid(), groups=tuple(os.getgroups()))
        before = (os.getresuid(), os.getresgid(), os.getgroups(),
                  {path.name: path.read_bytes() for path in self.directory.iterdir()})
        batch = self.collect(probe_endpoints=True, check_access=True, proc_reader=None,
                             probe_runner=None, access_worker_runner=None, access_query_runner=accounts)
        self.assertEqual((batch.endpoint_count, batch.access_count, batch.query_count), (1, 1, 28))
        for row in batch.as_dict()["checks"]:
            self.assertEqual(row.get("route_result", row.get("access_result")), "match")
        self.assertTrue(batch.matches_manifest(self.manifest(), now=NOW))
        self.assertEqual((os.getresuid(), os.getresgid(), os.getgroups(),
                          {path.name: path.read_bytes() for path in self.directory.iterdir()}), before)

    def test_selected_component_includes_transitive_resource_dependencies(self):
        self.record(declaration(dependency=True))
        batch = self.collect(probe_endpoints=True, check_access=True, selected_components=["main"])
        self.assertEqual((batch.endpoint_count, batch.access_count), (1, 1))
        self.assertTrue(all(row["selected"] for row in batch.as_dict()["checks"]))

    def test_selection_is_validated_before_queries_and_frozen(self):
        self.record()
        for selection in (["missing"], ["main", "main"], [1], "main", True):
            self.assert_error("invalid_runtime_check_selection", lambda: self.collect(selected_components=selection))
        selection = ["main"]
        self.runtime.before = lambda *args: selection.clear()
        batch = self.collect(probe_endpoints=True, selected_components=selection)
        self.assertEqual(batch._manifest._selection, ("main",))
        self.assertTrue(batch.matches_manifest(self.manifest(selected_components=["main"]), now=NOW))

    def test_compose_service_selection_is_part_of_private_binding(self):
        self.record(declaration(kind="compose", access=False), adopt=True)
        self.record(declaration(kind="compose", services=("different",), access=False))
        batch = self.collect(probe_endpoints=True)
        rows = batch.as_dict()["checks"]
        self.assertEqual((rows[0]["attribution"], rows[1]["attribution"]), ("verified", "unavailable"))
        self.assertEqual(batch.endpoint_count, 2)
        self.assertEqual(len(self.probes), 1)

    def test_unbound_current_engine_has_explicit_row_without_query(self):
        self.record(declaration(kind="compose", alias="missing", access=False))
        batch = self.collect(probe_endpoints=True)
        self.assertEqual(batch.as_dict()["checks"][0]["reason"], "physical_identity_unbound")
        self.assertEqual(self.runtime.calls, [])

    def test_revision_snapshot_policy_and_readonly_handles_are_required(self):
        decision = self.record()
        self.assert_error("invalid_runtime_check_request", lambda: checks.collect_runtime_checks(
            self.writer, self.policy, **self.context()))
        self.assert_error("invalid_runtime_check_request", lambda: checks.runtime_check_manifest(
            self.reader, self.policy.policy, **self.context()))
        self.assert_error("runtime_check_context_changed", lambda: self.collect(revision=2))
        self.assert_error("runtime_check_context_changed", lambda: self.collect(snapshot_id="0" * 64))
        self.assertTrue(self.manifest().matches_context(host_id=HOST, revision=1, snapshot_id=decision["snapshot_id"]))
        self.assertEqual(self.runtime.calls, [])

    def test_bounds_reject_bool_coercion_and_invalid_seams_before_queries(self):
        self.record()
        for options in ({"probe_endpoints": 1}, {"check_access": 1}, {"budget_seconds": True},
                        {"max_checks": 0}, {"max_queries": 4097}, {"max_query_bytes": 0},
                        {"proc_reader": object()}, {"probe_runner": 1}, {"access_worker_runner": []}):
            self.assert_error("invalid_runtime_check_request", lambda: self.collect(**options))
        self.assertEqual(self.runtime.calls, [])

    def test_missing_coverage_and_context_substitution_do_not_match_independent_manifest(self):
        self.record(adopt=True)
        batch = self.collect(probe_endpoints=True, check_access=True)
        manifest = self.manifest()
        shortened = replace(manifest, _scopes=manifest._scopes[:-1])
        partial = replace(batch, _manifest=shortened, checks=batch.checks[:-1])
        self.assertFalse(partial.matches_manifest(manifest, now=NOW))
        other = replace(manifest, _snapshot_id="0" * 64, _scopes=tuple(
            canonical_json(json.loads(raw) | {"snapshot_id": "0" * 64}) for raw in manifest._scopes))
        self.assertFalse(batch.matches_manifest(other, now=NOW))
        self.assertFalse(batch.matches_manifest(manifest.as_dict(), now=NOW))
        with self.assertRaises(checks.RuntimeCheckError):
            replace(manifest, _scopes=tuple(canonical_json(row) for row in manifest.as_dict()["checks"]))

    def test_exact_source_snapshot_and_observation_freshness_are_required(self):
        self.record(declaration(access=False))
        batch = self.collect(probe_endpoints=True)
        manifest = self.manifest()
        self.assertFalse(batch.matches_manifest(manifest, now=NOW + timedelta(seconds=61)))
        self.assertFalse(batch.matches_manifest(manifest, now=NOW - timedelta(microseconds=1)))
        self.assertFalse(batch.matches_manifest(manifest, now=NOW, max_age_seconds=True))
        self.record(declaration(access=False, suffix="# same model, new source\n"))
        self.assertFalse(batch.matches_manifest(self.manifest(), now=NOW))

    def test_query_count_and_reserved_output_bounds_discard_partial_results(self):
        self.record(declaration(access=False))
        limited = self.collect(probe_endpoints=True, max_queries=1)
        self.assertEqual(limited.query_count, 1)
        self.assertEqual(limited.as_dict()["checks"][0]["reason"], "collection_query_limit")
        self.assertEqual(self.probes, [])
        self.runtime.calls.clear()
        byte_limited = self.collect(probe_endpoints=True, max_query_bytes=checks.runtime_endpoint.MAX_OUTPUT - 1)
        self.assertEqual((byte_limited.query_count, byte_limited.query_output_bytes_reserved), (0, 0))
        self.assertEqual(byte_limited.as_dict()["checks"][0]["reason"], "collection_query_byte_limit")
        self.assertEqual(self.runtime.calls, [])

    def test_query_failures_oversize_and_late_return_have_fixed_unavailable_rows(self):
        self.record(declaration(access=False))
        for result in (object(), QueryResult("ok", b"x" * (checks.runtime_endpoint.MAX_OUTPUT + 1))):
            batch = self.collect(probe_endpoints=True, runtime_query_runner=lambda *a, **k: result)
            self.assertEqual(batch.as_dict()["checks"][0]["reason"], "collection_query_result_invalid")
        def failed(*args, **kwargs):
            raise OSError(PRIVATE)
        self.assertEqual(self.collect(probe_endpoints=True, runtime_query_runner=failed).as_dict()["checks"][0]["reason"],
                         "collection_query_failed")
        clock = [100.0]
        def late(argv, **kwargs):
            result = self.runtime(argv, **kwargs)
            clock[0] += 6
            return result
        with patch.object(checks.time, "monotonic", side_effect=lambda: clock[0]):
            batch = self.collect(probe_endpoints=True, runtime_query_runner=late)
        self.assertEqual(batch.as_dict()["checks"][0]["reason"], "collection_query_timeout")

    def test_unscheduled_checks_remain_explicit_when_original_timeout_cannot_fit(self):
        self.record(declaration(timeout=60))
        batch = self.collect(probe_endpoints=True, check_access=True, budget_seconds=1)
        self.assertEqual({row["reason"] for row in batch.as_dict()["checks"]}, {"collection_budget_exhausted"})
        self.assertEqual((batch.endpoint_count, batch.access_count), (0, 0))

    def test_total_deadline_discards_a_late_access_worker(self):
        self.record(declaration(endpoint=False))
        clock = [100.0]
        def late(request, **kwargs):
            clock[0] += 61
            return AccessResult("ok")
        with patch.object(checks.time, "monotonic", side_effect=lambda: clock[0]):
            batch = self.collect(check_access=True, access_worker_runner=late)
        self.assertEqual(batch.as_dict()["checks"][0]["reason"], "collection_budget_exhausted")

    def test_access_denial_and_runtime_failure_remain_distinct(self):
        self.record()
        self.runtime.service["ActiveState"] = "inactive"
        batch = self.collect(probe_endpoints=True, check_access=True,
                             access_worker_runner=lambda *a, **k: AccessResult("denied"))
        rows = batch.as_dict()["checks"]
        self.assertEqual(rows[0]["attribution"], "unavailable")
        self.assertEqual((rows[1]["access_result"], rows[1]["reason"]), ("mismatch", "access_denied"))

    def test_observer_substituted_predicate_or_timestamp_is_rejected(self):
        self.record(declaration(endpoint=False))
        original = checks.consumer_access.observe_consumer_access
        def substitute(check, resource, **kwargs):
            return original(check | {"as_user": "other"}, resource, **kwargs)
        with patch.object(checks.consumer_access, "observe_consumer_access", side_effect=substitute):
            self.assertEqual(self.collect(check_access=True).as_dict()["checks"][0]["reason"], "check_observation_invalid")
        def stale(check, resource, **kwargs):
            return original(check, resource, **(kwargs | {"observed_at": "2026-11-01T00:00:00Z"}))
        with patch.object(checks.consumer_access, "observe_consumer_access", side_effect=stale):
            self.assertEqual(self.collect(check_access=True).as_dict()["checks"][0]["reason"], "check_observation_invalid")

    def test_final_revision_change_after_adapter_failure_refuses_entire_batch(self):
        self.record(declaration(access=False))
        def failed(*args, **kwargs):
            self.record(EMPTY)
            raise OSError(PRIVATE)
        self.assert_error("runtime_check_context_changed", lambda: self.collect(
            probe_endpoints=True, runtime_query_runner=failed))

    def test_final_policy_change_invalidates_success(self):
        self.record(declaration(access=False))
        def probe(url, timeout):
            self.policy_path.write_text(self.policy_path.read_text() + "# changed\n")
            return ProbeResult("ok", 200)
        self.assert_error("runtime_check_policy_unavailable", lambda: self.collect(probe_endpoints=True, probe_runner=probe))

    def test_empty_and_disabled_scopes_still_cross_final_live_history_checks(self):
        self.record(EMPTY)
        original = checks._manifest
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.record(EMPTY)
            return result
        with patch.object(checks, "_manifest", side_effect=changed):
            self.assert_error("runtime_check_context_changed", lambda: self.collect())
            self.assert_error("runtime_check_context_changed", lambda: self.manifest())

    def test_coverage_limits_refuse_before_any_adapter_call(self):
        self.record(adopt=True)
        with patch.object(checks, "MAX_CHECKS", 1):
            self.assert_error("runtime_check_coverage_limit", lambda: self.collect(probe_endpoints=True, check_access=True))
        with patch.object(checks, "MAX_MANIFEST_BYTES", 1):
            self.assert_error("runtime_check_coverage_limit", lambda: self.collect(probe_endpoints=True, check_access=True))
        self.assertEqual((self.runtime.calls, self.accounts.calls), ([], []))

    def test_cancellation_propagates_without_publishing_partial_batch(self):
        self.record()
        before = self.writer.history()
        def cancel(*args, **kwargs):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.collect(probe_endpoints=True, runtime_query_runner=cancel)
        self.assertEqual(self.writer.history(), before)

    def test_private_contexts_and_observations_are_immutable_and_redacted(self):
        self.record(adopt=True)
        batch = self.collect(probe_endpoints=True, check_access=True)
        summary = batch.as_dict()
        for raw in (json.dumps(summary), repr(batch), repr(batch._manifest), repr(batch.checks[0])):
            for forbidden in (PRIVATE, "/system.slice/", "web.service", "expected_status", "as_user"):
                self.assertNotIn(forbidden, raw)
        summary["checks"].clear()
        self.assertEqual(len(batch.as_dict()["checks"]), 4)
        with self.assertRaises(FrozenInstanceError):
            batch.query_count = 0
        tampered = replace(batch)
        object.__setattr__(tampered, "checks", ())
        self.assertFalse(tampered.matches_manifest(self.manifest(), now=NOW))


if __name__ == "__main__":
    unittest.main()
