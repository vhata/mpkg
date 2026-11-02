"""Explicit installed status preserves private runtime/access role bindings."""
from contextlib import redirect_stdout
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import io
import json
import os
import unittest
from unittest.mock import patch

from mpkg_manager import runtime_checks, status_collection
from mpkg_manager.cli import main
from mpkg_manager.declarations import canonical_json, load_declaration
from mpkg_manager.host_client import _Reply
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.host_protocol import RequestError, parse_request
from mpkg_manager.planning import PlanningError, build_report
from mpkg_manager.query_process import QueryResult
from mpkg_manager.status_collection import StatusCollectionError, collect_status
from mpkg_manager.status_wire import validate_status
import test_manager_runtime_checks as fixture
from test_manager_status_cli import wire


_DEFAULT = object()


class Identities:
    def user(self, uid):
        return "reader"

    def group(self, gid):
        return "readers"


class RuntimeReportingTests(unittest.TestCase):
    setUp = fixture.RuntimeCheckTests.setUp
    record = fixture.RuntimeCheckTests.record
    context = fixture.RuntimeCheckTests.context
    manifest = fixture.RuntimeCheckTests.manifest
    probe = fixture.RuntimeCheckTests.probe
    worker = fixture.RuntimeCheckTests.worker
    collect = fixture.RuntimeCheckTests.collect

    def report(self, source=None, *, manifest=_DEFAULT, evidence=_DEFAULT, **kwargs):
        source = fixture.declaration() if source is None else source
        options = dict(host_id=fixture.HOST, engine_aliases=self.aliases, now=fixture.NOW,
            attribute_endpoints=True, check_consumer_access=True,
            runtime_check_manifest=self.manifest() if manifest is _DEFAULT else manifest,
            runtime_check_observations=self.collect(probe_endpoints=True, check_access=True)
                if evidence is _DEFAULT else evidence)
        options.update(kwargs)
        return build_report(source, self.writer.current_with_inputs(), None, **options).as_dict()

    def status(self, source=None, **kwargs):
        source = fixture.declaration() if source is None else source
        arguments = dict(complete_inputs=True, native_runner=lambda argv: QueryResult("io_error"),
            compose_runner=lambda argv: QueryResult("io_error"), identities=Identities(),
            runtime_query_runner=self.runtime, runtime_proc_reader=self.proc, runtime_probe_runner=self.probe,
            access_query_runner=self.accounts, access_worker_runner=self.worker)
        arguments.update(kwargs)
        return collect_status(source, self.reader, self.policy, **arguments).as_dict()

    def request(self, **options):
        return parse_request(wire(**options))

    @staticmethod
    def local_checks(report):
        return [check for resource in report["resources"] + report["retained_resources"]
                + report["unselected_resources"] for check in resource["checks"] if check["id"] == "access"]

    def unavailable(self, report, reason):
        summary = report["runtime_checks"]
        self.assertEqual((summary["state"], summary["reason"]), ("unavailable", reason))
        self.assertTrue(all(row.get("access_result", "unavailable") == "unavailable"
                            and row.get("attribution", "unavailable") == "unavailable"
                            for row in summary["entries"]))
        self.assertTrue(all(row["result"] == "unknown" for row in self.local_checks(report)))

    def test_default_preserves_reports_and_performs_no_new_collection(self):
        self.record(adopt=True)
        with patch.object(runtime_checks, "runtime_check_manifest", side_effect=AssertionError("manifest")), \
                patch.object(runtime_checks, "collect_runtime_checks", side_effect=AssertionError("collector")):
            result = self.status()
        self.assertNotIn("runtime_checks", result["report"])
        self.assertNotIn("runtime_check_reason", result["collection"])
        self.assertFalse(self.request().attribute_endpoints)
        validate_status(result, self.request())

    def test_both_modes_bind_exact_roles_and_keep_functionality_unverified(self):
        self.record(adopt=True)
        before = {p.name: p.read_bytes() for p in self.directory.iterdir() if p.is_file()}
        result = self.status(attribute_endpoints=True, check_consumer_access=True)
        validate_status(result, self.request(attribute_endpoints=True, check_consumer_access=True))
        report = result["report"]
        self.assertEqual(report["runtime_checks"]["required_checks"], 4)
        self.assertEqual({row["result"] for row in self.local_checks(report)}, {"passed"})
        endpoints = [row for row in report["runtime_checks"]["entries"] if row["check_kind"] == "endpoint"]
        self.assertEqual({(row["attribution"], row["route_result"]) for row in endpoints}, {("verified", "match")})
        self.assertTrue(all(row["functional_result"] == "unverified" for row in endpoints))
        self.assertFalse(report["executable"])
        self.assertEqual(result["collection"]["endpoint_reason"], "status_endpoint_collection_not_requested")
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.directory.iterdir() if p.is_file()})
        self.assertNotIn(fixture.PRIVATE, json.dumps(result))
        self.assertNotIn("reader", json.dumps(result).replace("external:reader", ""))

    def test_modes_are_independent_and_attribution_does_not_duplicate_route_probes(self):
        self.record(adopt=True)
        with patch.object(status_collection, "collect_endpoint_checks", side_effect=AssertionError("route-only")):
            result = self.status(attribute_endpoints=True)
        self.assertEqual(len(self.probes), 1)
        self.assertFalse(self.workers)
        self.assertTrue(all(row["result"] == "unknown" for row in self.local_checks(result["report"])))
        self.probes.clear()
        result = self.status(check_consumer_access=True)
        self.assertFalse(self.probes)
        self.assertEqual(len(self.workers), 1)
        validate_status(result, self.request(check_consumer_access=True))

    def test_retained_same_id_keeps_original_predicates_and_consumer_context(self):
        self.record(adopt=True)
        edited = fixture.declaration(status=201, consumer="external:other")
        self.record(edited)
        report = self.report(edited)
        endpoints = [row for row in report["runtime_checks"]["entries"] if row["check_kind"] == "endpoint"]
        self.assertEqual({(row["role"], row["route_result"]) for row in endpoints},
                         {("accepted", "match"), ("current", "mismatch")})
        self.assertEqual({row["consumer_id"] for row in report["runtime_checks"]["entries"]
                          if row["check_kind"] == "access"}, {"external:reader", "external:other"})

    def test_removed_relinquished_roles_remain_in_empty_selection(self):
        self.record(adopt=True)
        self.writer.relinquish([row["stable_id"] for row in self.writer.current()["resources"]], 1)
        self.record(fixture.EMPTY)
        manifest = self.manifest(selected_components=[])
        evidence = self.collect(probe_endpoints=True, check_access=True, selected_components=[])
        report = self.report(fixture.EMPTY, manifest=manifest, evidence=evidence, selected_components=[])
        self.assertEqual({row["management"] for row in report["runtime_checks"]["entries"]}, {"relinquished"})
        self.assertEqual(len(report["runtime_checks"]["entries"]), 2)
        self.assertEqual({row["result"] for row in self.local_checks(report)}, {"passed"})

    def test_component_selection_never_hides_retained_roles(self):
        self.record(adopt=True)
        result = self.status(attribute_endpoints=True, check_consumer_access=True, selected_components=["other"])
        rows = result["report"]["runtime_checks"]["entries"]
        self.assertTrue(all(row["selected"] == (row["role"] == "accepted") for row in rows))
        self.assertTrue(all(row["reason"] == "current_not_selected" for row in rows if row["role"] == "current"))
        self.assertEqual(len(self.probes), 1)
        self.assertEqual(len(self.workers), 1)

    def test_edited_intent_uses_recorded_inventory_without_runtime_or_access_operations(self):
        self.record(adopt=True)
        edited = load_declaration(fixture.declaration().source_bytes.replace(b'id="main"', b'id="new"'))
        with patch.object(runtime_checks, "collect_runtime_checks", side_effect=AssertionError("live operation")):
            result = self.status(edited, attribute_endpoints=True, check_consumer_access=True, selected_components=["new"])
        self.unavailable(result["report"], "intent_not_recorded")
        self.assertEqual(len(result["report"]["runtime_checks"]["entries"]), 4)
        self.assertEqual(result["collection"]["runtime_check_reason"], "status_target_not_recorded")

    def cross_kind(self, endpoint_first):
        endpoint = fixture.declaration(access=False)
        access = load_declaration(fixture.declaration(endpoint=False).source_bytes.replace(
            b'checks=["access"]', b'checks=["health"]').replace(b'id="access"', b'id="health"'))
        original, edited = (endpoint, access) if endpoint_first else (access, endpoint)
        self.record(original, adopt=True)
        with patch.object(runtime_checks, "collect_runtime_checks", side_effect=AssertionError("runtime read")):
            result = self.status(edited, attribute_endpoints=True, check_consumer_access=True)
        self.assertEqual(result["report"]["runtime_checks"]["reason"], "intent_not_recorded")
        for group in ("resources", "retained_resources", "unselected_resources"):
            self.assertTrue(all(check["result"] == "unknown" for resource in result["report"][group]
                                for check in resource["checks"]))
        request = self.request(source=edited.source_bytes.decode(), source_is_nonsecret=True,
                               attribute_endpoints=True, check_consumer_access=True)
        validate_status(result, request)
        self.record(edited)
        result = self.status(edited, attribute_endpoints=True, check_consumer_access=True)
        validate_status(result, self.request(attribute_endpoints=True, check_consumer_access=True))
        rows = result["report"]["runtime_checks"]["entries"]
        self.assertEqual({(row["role"], row["check_kind"]) for row in rows},
                         {("accepted", "endpoint" if endpoint_first else "access"),
                          ("current", "access" if endpoint_first else "endpoint")})
        self.assertTrue(all(row.get("access_result", "match") == "match" for row in rows))

    def test_edited_endpoint_id_reused_for_access_never_borrows_other_kind(self):
        self.cross_kind(True)

    def test_edited_access_id_reused_for_endpoint_keeps_accepted_access_separate(self):
        self.cross_kind(False)

    def test_typed_json_replay_and_missing_manifest_are_rejected(self):
        self.record(adopt=True)
        for options in ({"manifest": self.manifest().as_dict()}, {"evidence": self.collect().as_dict()}):
            with self.subTest(options=list(options)), self.assertRaises(PlanningError):
                self.report(**options)
        self.unavailable(self.report(manifest=None), "manifest_unavailable")
        self.unavailable(self.report(evidence=None), "not_observed")

    def test_independent_manifest_cannot_drop_current_or_retained_scope(self):
        self.record(adopt=True)
        original = self.manifest()
        for index in range(len(original._scopes)):
            scopes = original._scopes[:index] + original._scopes[index + 1:]
            self.unavailable(self.report(manifest=replace(original, _scopes=scopes)), "manifest_context_mismatch")

    def test_source_comments_full_snapshot_and_selection_replays_are_unavailable(self):
        self.record(adopt=True)
        manifest, evidence = self.manifest(), self.collect(probe_endpoints=True, check_access=True)
        self.record(fixture.declaration(suffix="# different source\n"))
        self.unavailable(self.report(fixture.declaration(suffix="# different source\n"),
                                    manifest=manifest, evidence=evidence), "manifest_context_mismatch")
        self.unavailable(self.report(fixture.declaration(suffix="# different source\n"),
                                    selected_components=["other"]), "manifest_context_mismatch")

    def test_stale_future_partial_context_and_wrong_modes_cannot_supply_results(self):
        self.record(adopt=True)
        batch = self.collect(probe_endpoints=True, check_access=True)
        self.unavailable(self.report(evidence=batch, now=fixture.NOW + timedelta(seconds=61)), "stale")
        self.unavailable(self.report(evidence=batch, now=fixture.NOW - timedelta(seconds=1)), "from_future")
        self.unavailable(self.report(evidence=self.collect(probe_endpoints=True)), "collection_modes_mismatch")
        manifest = replace(batch._manifest, _scopes=batch._manifest._scopes[:-1])
        partial = replace(batch, _manifest=manifest, checks=batch.checks[:-1])
        self.unavailable(self.report(evidence=partial), "context_mismatch")

    def test_shared_query_count_and_bytes_bound_metadata_and_new_queries(self):
        self.record(adopt=True)
        result = self.status(attribute_endpoints=True, check_consumer_access=True, max_queries=1)
        self.assertEqual(result["collection"]["query_count"], 1)
        self.assertIn("status_query_limit", result["collection"]["query_limits"])
        self.assertFalse(self.runtime.calls)
        self.assertFalse(self.accounts.calls)
        self.assertFalse(self.probes)
        self.assertFalse(self.workers)
        self.assertEqual(result["report"]["runtime_checks"]["query_count"], 0)
        self.assertEqual(result["report"]["runtime_checks"]["query_output_bytes_reserved"], 0)
        result = self.status(attribute_endpoints=True, check_consumer_access=True, max_query_bytes=1)
        self.assertEqual(result["collection"]["query_output_bytes_reserved"], 0)
        self.assertIn("status_query_byte_limit", result["collection"]["query_limits"])

    def test_remaining_reservations_include_exact_new_query_costs(self):
        self.record(adopt=True)
        result = self.status(attribute_endpoints=True, check_consumer_access=True)
        runtime, total = result["report"]["runtime_checks"], result["collection"]
        self.assertEqual(total["query_count"], runtime["query_count"] + 1)
        self.assertEqual(total["query_output_bytes_reserved"], runtime["query_output_bytes_reserved"] + 16384)
        result = self.status(attribute_endpoints=True, check_consumer_access=True, max_query_bytes=16385)
        runtime, total = result["report"]["runtime_checks"], result["collection"]
        self.assertEqual(runtime["query_count"], 0)
        self.assertEqual(runtime["query_output_bytes_reserved"], 0)
        self.assertEqual(total["query_output_bytes_reserved"], 16384)
        self.assertIn("collection_query_byte_limit", runtime["query_limits"])
        self.assertIn("status_query_byte_limit", total["query_limits"])

    def test_access_denial_is_only_the_declared_predicate_failure(self):
        self.record(adopt=True)
        result = self.status(check_consumer_access=True,
                             access_worker_runner=lambda *a, **k: fixture.AccessResult("denied"))
        self.assertEqual({check["result"] for check in self.local_checks(result["report"])}, {"failed"})
        self.assertEqual({check["reason"] for check in self.local_checks(result["report"])},
                         {"declared_local_user_access_only"})
        self.assertEqual(result["report"]["runtime_checks"]["functional_result"], "unverified")
        self.assertIn("required_check_unverified", result["report"]["blockers"])
        validate_status(result, self.request(check_consumer_access=True))

    def test_runtime_query_late_return_is_reserved_but_discarded(self):
        budget = status_collection._Budget(60, 4, 1000000, {})
        clock = [status_collection.time.monotonic()]
        def runner(*args, **kwargs):
            clock[0] += 3
            return QueryResult("ok", b"private")
        with patch.object(status_collection.time, "monotonic", side_effect=lambda: clock[0]):
            result = budget.runtime_runner("endpoint", runner)(("fixed",), timeout=2, max_output=65536)
        self.assertEqual(result.code, "timeout")
        self.assertEqual((budget.query_count, budget.reserved_bytes), (1, 65536))
        self.assertIn("status_query_timeout", budget.reasons)

    def test_query_exception_is_reserved_sanitized_and_unknown(self):
        self.record(adopt=True)
        def fail(*args, **kwargs):
            raise OSError(fixture.PRIVATE)
        result = self.status(attribute_endpoints=True, runtime_query_runner=fail)
        self.assertGreater(result["collection"]["query_count"], 1)
        self.assertGreaterEqual(result["collection"]["query_output_bytes_reserved"], 65536)
        self.assertIn("status_query_failed", result["collection"]["query_limits"])
        self.assertNotIn(fixture.PRIVATE, json.dumps(result))
        self.assertTrue(all(row.get("attribution", "unavailable") == "unavailable"
                            for row in result["report"]["runtime_checks"]["entries"]))

    def test_late_entire_collection_is_discarded(self):
        self.record(adopt=True)
        actual = runtime_checks.collect_runtime_checks
        late = [False]
        def collect(*args, **kwargs):
            result = actual(*args, **kwargs)
            late[0] = True
            return result
        original = status_collection._Budget.remaining
        def remaining(budget):
            return -1 if late[0] else original(budget)
        with patch.object(runtime_checks, "collect_runtime_checks", side_effect=collect), \
                patch.object(status_collection._Budget, "remaining", remaining):
            result = self.status(attribute_endpoints=True)
        self.unavailable(result["report"], "not_observed")
        self.assertEqual(result["collection"]["runtime_check_reason"], "status_collection_budget_exhausted")

    def test_failed_and_empty_collections_still_recheck_manifest(self):
        self.record(fixture.EMPTY)
        actual = runtime_checks.runtime_check_manifest
        for fail in (False, True):
            calls = []
            def manifest(*args, **kwargs):
                result = actual(*args, **kwargs)
                calls.append(result)
                return replace(result, _selection=()) if len(calls) == 2 else result
            with patch.object(runtime_checks, "runtime_check_manifest", side_effect=manifest):
                if fail:
                    with patch.object(runtime_checks, "collect_runtime_checks", side_effect=runtime_checks.RuntimeCheckError(fixture.PRIVATE)):
                        with self.assertRaises(StatusCollectionError) as raised:
                            self.status(fixture.EMPTY, check_consumer_access=True)
                else:
                    with self.assertRaises(StatusCollectionError) as raised:
                        self.status(fixture.EMPTY, check_consumer_access=True)
            self.assertEqual(raised.exception.code, "status_context_changed")
            self.assertEqual(len(calls), 2)

    def test_policy_or_history_race_after_observation_refuses_report(self):
        self.record(adopt=True)
        actual = runtime_checks.collect_runtime_checks
        def collect(*args, **kwargs):
            result = actual(*args, **kwargs)
            self.record(fixture.declaration(suffix="# changed\n"))
            return result
        with patch.object(runtime_checks, "collect_runtime_checks", side_effect=collect), \
                self.assertRaises(StatusCollectionError) as raised:
            self.status(attribute_endpoints=True)
        self.assertEqual(raised.exception.code, "status_context_changed")

    def test_request_flags_are_optional_closed_and_strict_booleans(self):
        for name in ("attribute_endpoints", "check_consumer_access"):
            for invalid in (0, 1, None, "true", [], {}):
                with self.subTest(name=name, invalid=invalid), self.assertRaises(RequestError):
                    self.request(**{name: invalid})
            self.assertTrue(getattr(self.request(**{name: True}), name))

    def test_closed_wire_rejects_private_unknown_and_unrequested_success(self):
        self.record(adopt=True)
        result = self.status(attribute_endpoints=True, check_consumer_access=True)
        request = self.request(attribute_endpoints=True, check_consumer_access=True)
        mutations = [
            lambda v: v["report"]["runtime_checks"].update(private_path=fixture.PRIVATE),
            lambda v: v["report"]["runtime_checks"]["entries"][0].update(reason=fixture.PRIVATE),
            lambda v: v["report"]["runtime_checks"].update(functional_result="passed"),
            lambda v: v["report"]["runtime_checks"].update(check_consumer_access=False),
            lambda v: v["report"]["runtime_checks"].update(required_checks=0),
            lambda v: v["report"]["runtime_checks"]["entries"].append(v["report"]["runtime_checks"]["entries"][0]),
        ]
        for mutation in mutations:
            value = deepcopy(result)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_status(value, request)
        with self.assertRaises(ValueError):
            validate_status(result, self.request())

    def test_cli_helper_and_human_output_preserve_redaction_and_explicit_flags(self):
        self.record(adopt=True)
        boundary = HostBoundary(policy_path=self.policy_path, store_directory=self.directory,
            mutation_lock=self.root / "unused-lock", owner_uid=os.geteuid())
        calls = []
        def collect(source, store, policy, **kwargs):
            return status_collection.StatusResult(canonical_json(self.status(source, **kwargs)))
        def sender(raw):
            calls.append(raw)
            reply = handle_request(raw, boundary=boundary)
            return _Reply(reply, 0 if json.loads(reply)["ok"] else 2)
        for arguments in (["--json"], ["--attribute-endpoints", "--check-consumer-access", "--json"],
                          ["--attribute-endpoints", "--check-consumer-access"]):
            output = io.StringIO()
            with redirect_stdout(output), patch("mpkg_manager.host_helper.collect_status", side_effect=collect):
                code = main(["status", *arguments], _sender=sender)
            self.assertEqual(code, 0, output.getvalue())
            self.assertNotIn(fixture.PRIVATE, output.getvalue())
            sent = json.loads(calls[-1])["arguments"]
            self.assertEqual("attribute_endpoints" in sent, "--attribute-endpoints" in arguments)
            if "--json" not in arguments:
                self.assertIn("attribution verified, route match", output.getvalue())
                self.assertIn("local-user access match", output.getvalue())
                self.assertIn("do not establish application functionality", output.getvalue())


if __name__ == "__main__":
    unittest.main()
