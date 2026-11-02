"""Actual Compose parser capabilities bound supplied scalar report facts."""
from copy import deepcopy
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.observe_compose import ENGINE_QUERY, observe_compose
from mpkg_manager.planning import build_report
from mpkg_manager.query_process import QueryResult
from mpkg_manager.store import HostStore
from test_manager_compose_observations import CID, ENGINE, HOST, WHEN, Queries, container


NOW = datetime.fromisoformat(WHEN.replace("Z", "+00:00"))
PRIVATE = "private-capability-sentinel"


def declaration(*, profiles=True, retained=False):
    component = (f'''[[components]]
id="app"
purpose="retained profile requirement"
resources=["deployment"]
requirements=[{{resource="deployment",property="profiles",value=["{PRIVATE}"]}}]
''' if retained else "components=[]\n")
    profile = f',profiles=["{PRIVATE}"]' if profiles else ""
    managed = ',"profiles"' if profiles else ""
    return load_declaration(('schema=1\n' + component + f'''[[resources]]
id="deployment"
kind="compose"
identity={{engine="local",project="example"}}
desired={{running=true,services=["app"]{profile},images=[{{service="app",policy="any",reference="{PRIVATE}:latest"}}]}}
manage=["running","services","images"{managed}]
''').encode())


class ComposeCapabilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "records"
        self.store = HostStore.create(self.path, HOST, owner_uid=os.geteuid(),
                                     engine_aliases={"local": ENGINE})
        self.addCleanup(self.store.close)
        self.model = declaration()
        self.store.adopt(self.model, 0, ["deployment"])

    def observe(self, *, model=None, runner=None):
        model = self.model if model is None else model
        with patch("subprocess.Popen", side_effect=AssertionError("Unexpected Docker invocation")):
            return observe_compose(model.model["resources"][0], host_id=HOST,
                accepted_engine_id=ENGINE, observed_at=WHEN,
                runner=Queries() if runner is None else runner).observations.as_dict()

    def report(self, wire, *, model=None, now=NOW):
        current = self.store.current()
        with patch("subprocess.Popen", side_effect=AssertionError("Unexpected report query")), \
             patch.object(HostStore, "current", side_effect=AssertionError("Unexpected report store read")):
            return build_report(self.model if model is None else model, current, wire,
                host_id=HOST, engine_aliases={"local": ENGINE}, now=now).as_dict()

    def properties(self, report):
        return {row["property"]: row for row in report["resources"][0]["properties"]}

    def files(self):
        return {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                for path in self.path.iterdir()}

    def claim(self, wire, prop, value):
        template = deepcopy(next(row for row in wire["facts"] if row["property"] == "present"))
        template.update(property=prop, state="known", value=value, limitations=[])
        wire["facts"] = [row for row in wire["facts"] if row["property"] != prop] + [template]

    def test_supplied_known_scalars_cannot_exceed_declared_inventory_capabilities(self):
        original = self.observe()
        baseline = self.properties(self.report(original))
        self.assertEqual(baseline["running"]["comparison"], "agreement")
        self.assertTrue(all(baseline[prop]["comparison"] == "unknown"
                            for prop in ("profiles", "services", "images")))
        before = self.files()
        for prop in ("profiles", "services", "images"):
            for value in (PRIVATE, True, 1, None):
                with self.subTest(property=prop, value=value):
                    supplied = deepcopy(original)
                    self.claim(supplied, prop, value)
                    report = self.report(supplied)
                    row = self.properties(report)[prop]
                    self.assertEqual(row["comparison"], "unknown")
                    self.assertEqual(row["limitations"], ["observation_property_unsupported"])
                    self.assertEqual(row["evidence_source"], "docker_selected_project_inventory")
                    self.assertTrue(row["authority"])
                    self.assertIn("observation_property_unsupported", report["blockers"])
                    self.assertFalse(report["executable"])
                    self.assertNotIn(PRIVATE, json.dumps(report))
                    self.assertNotIn(ENGINE, json.dumps(report))
        self.assertEqual(self.files(), before)

    def test_supported_running_keeps_context_freshness_and_failure_checks(self):
        for status, active, expected in (("running", True, "agreement"), ("exited", False, "difference")):
            wire = self.observe(runner=Queries(containers={CID: container(status=status, running=active)}))
            self.assertEqual(self.properties(self.report(wire))["running"]["comparison"], expected)
            self.assertTrue(next(row for row in wire["facts"] if row["property"] == "present")["value"])
            self.assertEqual(next(row for row in wire["facts"] if row["property"] == "container_count")["value"], 1)
        original = self.observe()
        for change, reason in (("engine", "compose_observed_engine_mismatch"),
                               ("scope", "compose_observed_service_scope_mismatch"),
                               ("legacy", "compose_observation_context_missing")):
            wire = deepcopy(original)
            fact = next(row for row in wire["facts"] if row["property"] == "running")
            if change == "engine":
                fact["compose_context"]["engine_id"] = "different-accepted-engine"
            elif change == "scope":
                fact["compose_context"]["services"] = ["different-service"]
            else:
                fact.pop("compose_context")
            row = self.properties(self.report(wire))["running"]
            self.assertEqual(row["comparison"], "unknown")
            self.assertEqual(row["limitations"], [reason])
        self.assertEqual(self.properties(self.report(original, now=NOW + timedelta(seconds=61)))
                         ["running"]["comparison"], "unknown")
        failed = self.observe(runner=Queries(overrides={ENGINE_QUERY: [QueryResult("command_failed")]}))
        self.assertEqual(self.properties(self.report(failed))["running"]["comparison"], "unknown")

    def test_retained_profile_requirement_cannot_gain_evidence_from_a_scalar_claim(self):
        accepted = declaration(retained=True)
        self.store.adopt(accepted, 1, ["deployment"])
        changed = declaration(profiles=False)
        self.store.record_intent(changed, 2)
        wire = self.observe(model=changed)
        self.claim(wire, "profiles", PRIVATE)
        before = self.files()
        report = self.report(wire, model=changed)
        row = self.properties(report)["profiles"]
        self.assertEqual(row["comparison"], "unknown")
        self.assertEqual(row["limitations"], ["observation_property_unsupported"])
        self.assertFalse(row["authority"])
        self.assertIn("app", report["resources"][0]["known_consumers"])
        self.assertEqual(self.files(), before)

    def test_claimed_health_and_input_values_cannot_clear_capability_blockers(self):
        wire = self.observe()
        for prop in ("health", "input_closure"):
            self.claim(wire, prop, True)
        self.claim(wire, "images", PRIVATE)
        report = self.report(wire)
        self.assertEqual(self.properties(report)["images"]["comparison"], "unknown")
        self.assertTrue({"functional_health_not_established", "input_freshness_unverified",
                         "application_not_implemented", "attempt_history_unavailable"} <= set(report["blockers"]))
        self.assertNotIn("health", self.properties(report))
        self.assertNotIn("input_closure", self.properties(report))
        self.assertFalse(report["executable"])
        self.assertNotIn(PRIVATE, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
