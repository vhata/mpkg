"""Pure reports consume actual-store endpoint evidence without new observations."""
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager import endpoint_checks as collector
from mpkg_manager.declarations import canonical_json, load_declaration
from mpkg_manager.observations import Observation, ObservationBatch
from mpkg_manager._endpoint_process import ProbeResult
from mpkg_manager.planning import PlanningError, build_report
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
OTHER_HOST = "22345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T10:00:00Z"
NOW = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
PRIVATE = "private-endpoint-report-predicate"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


def declaration(*specs, suffix=""):
    if not specs:
        specs = ({"id": "web", "check": "health"},)
    source = "schema=1\n"
    for item in specs:
        source += f'''[[components]]
id="{item['id']}"
purpose="Fixture component"
resources=["{item['id']}"]
'''
    for item in specs:
        kind = item.get("kind", "service")
        identity = (f'manager="system",unit="{item.get("unit", item["id"] + ".service")}"' if kind == "service"
                    else f'engine="{item.get("engine", "local")}",project="{item.get("project", item["id"])}"')
        source += f'''[[resources]]
id="{item['id']}"
kind="{kind}"
identity={{{identity}}}
checks=["{item['check']}"]
'''
        if kind == "service":
            source += 'manage=["running"]\ndesired={running=true}\n'
    for item in specs:
        source += f'''[[checks]]
id="{item['check']}"
kind="endpoint"
resource="{item['id']}"
url="http://127.0.0.1:{item.get('port', 12345)}/{PRIVATE}/{item['check']}"
expected_status={item.get('status', 200)}
timeout_seconds={item.get('timeout', 1)}
'''
    return load_declaration((source + suffix).encode())


class EndpointPlanningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.store = HostStore.create(self.directory / "records", HOST, owner_uid=os.geteuid(),
                                     engine_aliases={"local": "fixture-engine", "alias": "fixture-engine"})
        self.addCleanup(self.store.close)
        self.declaration = declaration()
        self.store.adopt(self.declaration, 0, ["web"])

    def collect(self, *, store=None, **kwargs):
        store = self.store if store is None else store
        current = store.current()
        with patch.object(collector, "utc_now", return_value=WHEN):
            return collector.collect_endpoint_checks(
                store, revision=current["revision"], snapshot_id=current["snapshot_id"],
                runner=kwargs.pop("runner", lambda url, timeout: ProbeResult("ok", 200)), **kwargs)

    def report(self, evidence=None, *, declaration=None, current=None, **kwargs):
        model = self.declaration if declaration is None else declaration
        facts = tuple(Observation(HOST, item["id"], item["kind"], item["identity"], "running", "known", True,
                                  WHEN, "systemd_unit_properties")
                      for item in model.model["resources"] if item["kind"] == "service")
        observations = ObservationBatch(HOST, WHEN, facts, tuple(item.resource_id for item in facts))
        return build_report(model, self.store.current() if current is None else current, observations.as_dict(),
                            host_id=HOST, now=kwargs.pop("now", NOW), engine_aliases=self.store.engine_aliases,
                            endpoint_observations=evidence, **kwargs)

    def assert_unavailable(self, report, reason):
        value = report.as_dict()
        summary = value["endpoint_checks"]
        self.assertEqual(summary["state"], "unavailable")
        self.assertEqual(summary["reason"], reason)
        self.assertEqual(summary["coverage"], "unavailable")
        self.assertTrue(all(row["route_result"] == "unavailable" for row in summary["entries"]))
        self.assertTrue(all(row["functional_result"] == "unverified" for row in summary["entries"]))
        return value

    def test_route_match_remains_separate_from_functional_and_application_status(self):
        evidence = self.collect()
        report = self.report(evidence).as_dict()
        summary = report["endpoint_checks"]
        self.assertEqual((summary["state"], summary["coverage"], summary["required_checks"]),
                         ("available", "complete", 2))
        self.assertEqual(summary["observed_at"], WHEN)
        self.assertEqual(summary["functional_result"], "unverified")
        self.assertEqual(report["resources"][0]["properties"][0]["comparison"], "agreement")
        self.assertEqual([row["role"] for row in report["resources"][0]["checks"]], ["accepted", "current"])
        for row in report["resources"][0]["checks"]:
            self.assertEqual((row["result"], row["route_result"], row["functional_result"]),
                             ("unknown", "match", "unverified"))
            self.assertEqual(row["route_reason"], "status_matches")
            self.assertEqual(row["limitations"], list(collector.LIMITATIONS))
        self.assertTrue({"required_check_unverified", "functional_health_not_established",
                         "application_not_implemented", "attempt_history_unavailable"} <= set(report["blockers"]))
        self.assertFalse(report["executable"])

    def test_same_id_keeps_distinct_original_accepted_and_current_predicates(self):
        changed = declaration({"id": "web", "check": "health", "status": 204})
        self.store.record_intent(changed, 1)
        value = self.report(self.collect(), declaration=changed).as_dict()
        checks = value["resources"][0]["checks"]
        self.assertEqual([(row["role"], row["route_result"]) for row in checks],
                         [("accepted", "match"), ("current", "mismatch")])
        self.assertEqual(checks[0]["adoption_revision"], 1)
        self.assertTrue(all(row["result"] == "unknown" for row in checks))

    def test_missing_partial_and_extra_coverage_cannot_supply_any_matching_routes(self):
        evidence = self.collect()
        self.assert_unavailable(self.report(), "not_observed")
        self.assert_unavailable(self.report(replace(evidence, checks=evidence.checks[:1])), "coverage_incomplete")
        self.assert_unavailable(self.report(replace(evidence, checks=())), "coverage_incomplete")
        scope = json.loads(evidence.checks[1]._scope)
        scope["context"]["check"]["id"] = "extra"
        scope["context"]["resource"]["checks"] = ["extra"]
        extra = collector.EndpointCheckResult(canonical_json(scope), None, "collection_probe_limit")
        self.assert_unavailable(self.report(replace(evidence, checks=(*evidence.checks, extra))), "coverage_incomplete")

    def test_stale_future_and_exact_age_boundary_use_collection_start(self):
        evidence = self.collect()
        self.assert_unavailable(self.report(evidence, now=NOW + timedelta(seconds=61)), "stale")
        self.assert_unavailable(self.report(evidence, now=NOW - timedelta(microseconds=1)), "from_future")
        self.assertEqual(self.report(evidence, now=NOW + timedelta(seconds=60)).as_dict()
                         ["endpoint_checks"]["state"], "available")

    def test_unrecorded_source_comments_and_later_revisions_refuse_old_evidence(self):
        evidence = self.collect()
        edited = declaration(suffix="# different exact source\n")
        self.assertEqual(edited.canonical_bytes, self.declaration.canonical_bytes)
        self.assert_unavailable(self.report(evidence, declaration=edited), "intent_not_recorded")
        self.store.record_intent(edited, 1)
        self.assert_unavailable(self.report(evidence, declaration=edited), "target_mismatch")
        self.assertEqual(self.report(self.collect(), declaration=edited).as_dict()["endpoint_checks"]["state"], "available")

    def test_removed_and_relinquished_records_preserve_accepted_route_evidence(self):
        stable = self.store.current()["resources"][0]["stable_id"]
        self.store.relinquish([stable], 1)
        self.store.record_intent(EMPTY, 2)
        value = self.report(self.collect(), declaration=EMPTY).as_dict()
        retained = value["retained_resources"][0]
        self.assertEqual(retained["management"], "relinquished")
        self.assertEqual(retained["stable_id"], stable)
        self.assertEqual(retained["checks"][0]["route_result"], "match")
        self.assertEqual(retained["checks"][0]["result"], "unknown")
        self.assertEqual(value["endpoint_checks"]["required_checks"], 1)

    def test_selected_components_still_require_complete_global_role_coverage(self):
        model = declaration({"id": "web", "check": "health"}, {"id": "other", "check": "other-health"})
        self.store.adopt(model, 1, ["web", "other"])
        evidence = self.collect()
        value = self.report(evidence, declaration=model, selected_components=["web"]).as_dict()
        self.assertEqual(len(value["resources"]), 1)
        self.assertEqual(value["endpoint_checks"]["required_checks"], 4)
        self.assertEqual(value["unselected_resources"][0]["checks"][0]["route_result"], "match")
        self.assertIn(("current", "other"), {(row["role"], row["resource_id"])
                                               for row in value["endpoint_checks"]["entries"]})
        incomplete = replace(evidence, checks=tuple(row for row in evidence.checks
                                                    if row.as_dict()["resource_id"] != "other"))
        self.assert_unavailable(self.report(incomplete, declaration=model, selected_components=["web"]),
                                "coverage_incomplete")

    def test_json_and_malformed_typed_batches_have_fixed_diagnostics(self):
        evidence = self.collect()
        malformed = object.__new__(collector.EndpointCheckBatch)
        for value in (evidence.as_dict(), json.dumps(evidence.as_dict()), {}, malformed):
            with self.subTest(type=type(value)), self.assertRaises(PlanningError) as raised:
                self.report(value)
            self.assertEqual(raised.exception.code, "invalid_endpoint_observation")
            self.assertEqual(str(raised.exception), "invalid_endpoint_observation")

    def test_report_building_performs_no_store_file_socket_or_process_operations(self):
        evidence = self.collect()
        current = self.store.current()
        aliases = self.store.engine_aliases
        resource = self.declaration.model["resources"][0]
        observation = Observation(HOST, "web", "service", resource["identity"], "running", "known", True,
                                  WHEN, "systemd_unit_properties")
        facts = ObservationBatch(HOST, WHEN, (observation,), ("web",)).as_dict()
        forbidden = ("builtins.open", "os.open", "pathlib.Path.open", "sqlite3.connect", "socket.socket",
                     "socket.create_connection", "subprocess.Popen", "mpkg_manager.store.HostStore.current",
                     "mpkg_manager.store.HostStore.snapshot", "mpkg_manager.endpoint_checks.collect_endpoint_checks",
                     "mpkg_manager.observe_endpoint.observe_endpoint", "mpkg_manager._endpoint_process.run_probe")
        with ExitStack() as stack:
            for target in forbidden:
                stack.enter_context(patch(target, side_effect=AssertionError("Pure planner attempted I/O")))
            report = build_report(self.declaration, current, facts, host_id=HOST, now=NOW,
                                  engine_aliases=aliases, endpoint_observations=evidence)
        self.assertEqual(report.as_dict()["endpoint_checks"]["state"], "available")

    def test_foreign_host_and_missing_history_do_not_expose_matching_routes(self):
        other = HostStore.create(self.directory / "other", OTHER_HOST, owner_uid=os.geteuid())
        self.addCleanup(other.close)
        other.adopt(self.declaration, 0, ["web"])
        foreign = self.collect(store=other)
        self.assert_unavailable(self.report(foreign), "host_mismatch")
        report = build_report(self.declaration, None, None, host_id=HOST, now=NOW,
                              endpoint_observations=self.collect())
        self.assert_unavailable(report, "history_unavailable")
        self.assertIn("history_unavailable", report.as_dict()["blockers"])

    def test_same_revision_with_a_different_snapshot_cannot_use_evidence(self):
        evidence = self.collect()
        row = evidence.checks[1]
        scope = json.loads(row._scope)
        scope["snapshot_id"] = "a" * 64
        changed = replace(row, _scope=canonical_json(scope))
        foreign = replace(evidence, _snapshot_id="a" * 64, revision=2, checks=(changed,))
        current = self.store.current()
        current["revision"] = 2
        self.assert_unavailable(self.report(foreign, current=current), "target_mismatch")

    def test_same_role_ids_with_changed_predicate_physical_target_or_adoption_are_unavailable(self):
        evidence = self.collect()
        accepted = evidence.checks[0]
        for change in ("predicate", "physical", "adoption_snapshot", "management"):
            with self.subTest(change=change):
                scope = json.loads(accepted._scope)
                if change == "predicate":
                    scope["context"]["check"]["expected_status"] = 204
                elif change == "physical":
                    scope["context"]["resource"]["identity"]["unit"] = "other.service"
                    scope["context"]["target"][-1] = "other.service"
                elif change == "adoption_snapshot":
                    scope["snapshot_id"] = "b" * 64
                else:
                    scope["management"] = "relinquished"
                altered = collector.EndpointCheckResult(canonical_json(scope), None, "collection_probe_limit")
                # Move to a later intent revision so an old adoption snapshot
                # differs structurally without contradicting batch revision.
                self.store.record_intent(self.declaration, self.store.current()["revision"])
                current = self.store.current()
                current_row = self.collect().checks[1]
                changed = collector.EndpointCheckBatch(HOST, current["revision"], current["snapshot_id"],
                                                       WHEN, (altered, current_row), 1)
                self.assert_unavailable(self.report(changed), "context_mismatch")

    def test_adoption_revision_and_stable_id_cannot_be_replaced_by_same_check_id(self):
        self.store.record_intent(self.declaration, 1)
        evidence = self.collect()
        for field, value, reason in (("adoption_revision", 2, "context_mismatch"),
                                     ("stable_id", "32345678-1234-4234-8234-123456789abc", "coverage_incomplete")):
            with self.subTest(field=field):
                scope = json.loads(evidence.checks[0]._scope)
                scope[field] = value
                row = replace(evidence.checks[0], _scope=canonical_json(scope))
                self.assert_unavailable(self.report(replace(evidence, checks=(row, evidence.checks[1]))), reason)

    def test_logical_rename_uses_original_accepted_context_and_current_route(self):
        renamed = declaration({"id": "renamed", "check": "health", "unit": "web.service"})
        self.store.record_intent(renamed, 1)
        report = self.report(self.collect(), declaration=renamed).as_dict()
        resource = report["resources"][0]
        self.assertEqual(resource["resource_id"], "renamed")
        self.assertTrue(all(row["route_result"] == "match" for row in resource["checks"]))
        self.assertEqual([(entry["role"], entry["resource_id"]) for entry in report["endpoint_checks"]["entries"]],
                         [("accepted", "web"), ("current", "renamed")])

    def test_same_logical_id_with_replaced_physical_target_keeps_old_retained_route(self):
        replacement = declaration({"id": "web", "check": "health", "unit": "replacement.service", "status": 204})
        self.store.record_intent(replacement, 1)
        report = self.report(self.collect(), declaration=replacement).as_dict()
        self.assertEqual(report["resources"][0]["management"], "unadopted")
        self.assertEqual(report["resources"][0]["checks"][0]["route_result"], "mismatch")
        self.assertEqual(report["retained_resources"][0]["checks"][0]["route_result"], "match")
        self.assertEqual(report["retained_resources"][0]["checks"][0]["role"], "accepted")
        self.assertIn("retained_resource_disposition_required", report["blockers"])

    def test_budget_and_transport_gaps_are_complete_coverage_but_unverified_routes(self):
        for options, reason in (({"budget_seconds": 1}, "collection_budget_exhausted"),
                                ({"runner": lambda url, timeout: ProbeResult("timeout")}, "timeout")):
            with self.subTest(reason=reason):
                evidence = self.collect(**options)
                report = self.report(evidence).as_dict()
                summary = report["endpoint_checks"]
                self.assertEqual((summary["state"], summary["coverage"]), ("available", "complete"))
                self.assertTrue(all(row["route_result"] == "unavailable" and row["route_reason"] == reason
                                    for row in summary["entries"]))
                self.assertTrue(all(row["result"] == "unknown" for row in report["resources"][0]["checks"]))

    def test_missing_accepted_definitions_cannot_silently_drop_historical_coverage(self):
        evidence = self.collect()
        current = self.store.current()
        del current["resources"][0]["accepted_checks"]
        report = self.assert_unavailable(self.report(evidence, current=current), "accepted_check_definition_unavailable")
        self.assertIn("accepted_check_definition_unavailable", report["blockers"])
        self.assertEqual(report["resources"][0]["checks"][0]["reason"], "accepted_check_unavailable")

    def test_summary_inventory_limit_never_claims_truncated_coverage(self):
        evidence = self.collect()
        with patch("mpkg_manager.planning.MAX_CHECKS", 1):
            report = self.assert_unavailable(self.report(evidence), "coverage_limit")
        self.assertEqual(report["endpoint_checks"]["required_checks"], 2)
        self.assertEqual(report["endpoint_checks"]["entries"], [])
        self.assertTrue(all(row["route_result"] == "unavailable" for row in report["resources"][0]["checks"]))

    def test_no_new_endpoint_summary_exposes_predicates_or_mutable_evidence(self):
        evidence = self.collect()
        report = self.report(evidence)
        public = report.as_dict()
        encoded = json.dumps(public)
        for value in (PRIVATE, "expected_status", "timeout_seconds", "web.service", "http://", "_scope", "_binding"):
            self.assertNotIn(value, encoded)
        new_summary = json.dumps(public["endpoint_checks"])
        self.assertNotIn(evidence._snapshot_id, new_summary)
        public["endpoint_checks"]["entries"][0]["limitations"].clear()
        public["endpoint_checks"]["entries"].clear()
        public["resources"][0]["checks"][0]["route_result"] = "changed"
        fresh = report.as_dict()
        self.assertEqual(len(fresh["endpoint_checks"]["entries"]), 2)
        self.assertTrue(fresh["endpoint_checks"]["entries"][0]["limitations"])
        self.assertEqual(fresh["resources"][0]["checks"][0]["route_result"], "match")

    def test_unreferenced_root_predicates_do_not_expand_report_coverage(self):
        raw = self.declaration.source_bytes + f'''[[checks]]
id="unused"
kind="endpoint"
resource="web"
url="http://127.0.0.1:12346/{PRIVATE}/unused"
expected_status=204
timeout_seconds=1
'''.encode()
        model = load_declaration(raw)
        self.store.record_intent(model, 1)
        evidence = self.collect()
        report = self.report(evidence, declaration=model).as_dict()
        self.assertEqual(report["endpoint_checks"]["required_checks"], 2)
        self.assertTrue(all(row["id"] == "health" for row in report["endpoint_checks"]["entries"]))
        self.assertEqual(report["endpoint_checks"]["state"], "available")

    def test_empty_component_selection_retains_global_coverage_and_functional_blockers(self):
        evidence = self.collect()
        report = self.report(evidence, selected_components=[]).as_dict()
        self.assertEqual(report["resources"], [])
        self.assertEqual(report["endpoint_checks"]["required_checks"], 2)
        self.assertEqual(report["unselected_resources"][0]["checks"][0]["route_result"], "match")
        self.assertIn("required_check_unverified", report["blockers"])
        self.assertEqual(report["blockers"], self.report(selected_components=[]).as_dict()["blockers"])
        self.assertFalse(report["executable"])

    def test_compose_alias_context_is_physical_and_unbound_routes_never_match(self):
        model = declaration({"id": "app", "check": "app-health", "kind": "compose", "engine": "local"})
        self.store.adopt(model, 1, ["app"])
        renamed_alias = declaration({"id": "app", "check": "app-health", "kind": "compose", "engine": "alias"})
        self.store.record_intent(renamed_alias, 2)
        report = self.report(self.collect(), declaration=renamed_alias).as_dict()
        self.assertEqual(report["endpoint_checks"]["state"], "available")
        self.assertTrue(all(row["route_result"] == "match" for row in report["resources"][0]["checks"]))
        unknown = declaration({"id": "app", "check": "app-health", "kind": "compose", "engine": "unknown"})
        self.store.record_intent(unknown, 3)
        report = self.report(self.collect(), declaration=unknown).as_dict()
        current = report["resources"][0]["checks"][0]
        self.assertEqual(current["route_result"], "unavailable")
        self.assertEqual(current["route_reason"], "physical_identity_unbound")
        self.assertEqual(current["functional_result"], "unverified")
        self.assertIn("physical_identity_unbound", report["blockers"])

    def test_typed_subclasses_and_forged_noninteger_revisions_are_refused(self):
        evidence = self.collect()
        class Subclass(collector.EndpointCheckBatch):
            pass
        subclass = Subclass(evidence.host_id, evidence.revision, evidence._snapshot_id,
                            evidence.observed_at, evidence.checks, evidence.probe_count)
        forged = object.__new__(collector.EndpointCheckBatch)
        for name in evidence.__dataclass_fields__:
            object.__setattr__(forged, name, getattr(evidence, name))
        object.__setattr__(forged, "revision", True)
        for value in (subclass, forged):
            with self.subTest(type=type(value)):
                with self.assertRaises(PlanningError) as raised:
                    self.report(value)
                self.assertEqual(raised.exception.code, "invalid_endpoint_observation")
