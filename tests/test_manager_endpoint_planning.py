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
