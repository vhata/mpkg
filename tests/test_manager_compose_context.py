"""Real Compose parsers and private host records preserve collected context."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.observations import ComposeContext, MAX_COMPOSE_SERVICES, Observation
from mpkg_manager.observe_compose import ENGINE_QUERY, observe_compose
from mpkg_manager.planning import PlanningError, build_report
from mpkg_manager.query_process import QueryResult
from mpkg_manager.store import HostStore
from test_manager_compose_observations import CID, ENGINE, HOST, SECOND, WHEN, Queries, container


NOW = datetime.fromisoformat(WHEN.replace("Z", "+00:00"))


def declaration(services=("app",), *, engine="local"):
    return load_declaration(f'''schema=1
components=[]
[[resources]]
id="deployment"
kind="compose"
identity={{engine="{engine}",project="example"}}
desired={{running=true,services={json.dumps(list(services))}}}
manage=["running"]
'''.encode())


def running(report):
    return next(row for row in report["resources"][0]["properties"] if row["property"] == "running")


class ComposeContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = HostStore.create(self.root / "records", HOST, owner_uid=os.geteuid(),
                                     engine_aliases={"local": ENGINE, "alias": ENGINE})
        self.addCleanup(self.store.close)
        self.model = declaration()
        self.store.adopt(self.model, 0, ["deployment"])

    def observe(self, model=None, runner=None):
        model = self.model if model is None else model
        return observe_compose(model.model["resources"][0], host_id=HOST, accepted_engine_id=ENGINE,
                               runner=Queries() if runner is None else runner, observed_at=WHEN)

    def report(self, wire, *, model=None, store=None):
        model = self.model if model is None else model
        store = self.store if store is None else store
        current = store.current()
        with patch("subprocess.Popen", side_effect=AssertionError("Unexpected native query")), \
             patch.object(HostStore, "current", side_effect=AssertionError("Unexpected planner store read")):
            return build_report(model, current, wire, host_id=HOST,
                                engine_aliases=store.engine_aliases, now=NOW).as_dict()

    def files(self):
        return {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                for path in (self.root / "records").iterdir()}

    def test_old_service_scope_cannot_satisfy_changed_recorded_intent(self):
        old = self.observe().observations.as_dict()
        changed = declaration(("worker",))
        self.store.record_intent(changed, 1)
        before = self.files()
        stale = self.report(old, model=changed)
        fresh = self.report(self.observe(changed).observations.as_dict(), model=changed)
        self.assertEqual(running(stale)["comparison"], "unknown")
        self.assertEqual(running(stale)["limitations"], ["compose_observed_service_scope_mismatch"])
        self.assertEqual(running(fresh)["comparison"], "unknown")
        self.assertEqual(running(fresh)["limitations"], ["observation_unknown"])
        self.assertTrue(running(stale)["authority"])
        self.assertFalse(stale["executable"])
        self.assertEqual(self.files(), before)

    def test_verified_observed_engine_cannot_be_rebound_through_current_alias(self):
        with HostStore.create(self.root / "other", HOST, owner_uid=os.geteuid(),
                              engine_aliases={"local": "different-accepted-engine"}) as other:
            other.adopt(self.model, 0, ["deployment"])
            observed = self.observe()
            self.assertEqual(observed.as_dict()["accepted_engine_id"], ENGINE)
            report = self.report(observed.observations.as_dict(), store=other)
        self.assertEqual(running(report)["comparison"], "unknown")
        self.assertEqual(running(report)["limitations"], ["compose_observed_engine_mismatch"])
        self.assertFalse(report["executable"])

    def test_matching_context_retains_known_true_false_and_private_output(self):
        for status, active, expected in (("running", True, "agreement"), ("exited", False, "difference")):
            with self.subTest(status=status):
                observed = self.observe(runner=Queries(containers={CID: container(status=status, running=active)}))
                for fact in observed.observations.facts:
                    context = fact.as_dict()["compose_context"]
                    self.assertEqual(context["engine_id"], ENGINE)
                    self.assertEqual("services" in context, fact.property == "running")
                report = self.report(observed.observations.as_dict())
                self.assertEqual(running(report)["comparison"], expected)
                self.assertNotIn("compose_context", json.dumps(report))
                self.assertNotIn(ENGINE, json.dumps(report))
                self.assertIn("functional_health_not_established", report["blockers"])

    def test_legacy_facts_are_readable_but_missing_context_is_unknown(self):
        wire = self.observe().observations.as_dict()
        for fact in wire["facts"]:
            fact.pop("compose_context")
        report = self.report(wire)
        self.assertEqual(running(report)["comparison"], "unknown")
        self.assertEqual(running(report)["limitations"], ["compose_observation_context_missing"])

    def test_missing_empty_and_changed_service_context_never_supply_a_running_result(self):
        original = self.observe().observations.as_dict()
        for services in (None, [], ["worker"]):
            wire = deepcopy(original)
            context = next(row for row in wire["facts"] if row["property"] == "running")["compose_context"]
            if services is None:
                context.pop("services")
            else:
                context["services"] = services
            self.assertEqual(running(self.report(wire))["comparison"], "unknown")
        no_services = declaration(())
        self.store.record_intent(no_services, 1)
        self.assertEqual(running(self.report(original, model=no_services))["comparison"], "unknown")

    def test_service_order_and_equivalent_engine_alias_keep_the_same_scope(self):
        first = declaration(("worker", "app"))
        self.store.record_intent(first, 1)
        queries = Queries(containers={CID: container(), SECOND: container(id=SECOND, service="worker")})
        wire = self.observe(first, queries).observations.as_dict()
        scope = next(row for row in wire["facts"] if row["property"] == "running")["compose_context"]
        self.assertEqual(scope["services"], ["app", "worker"])
        second = declaration(("app", "worker"), engine="alias")
        self.store.record_intent(second, 2)
        self.assertEqual(running(self.report(wire, model=second))["comparison"], "agreement")
        scope["services"].reverse()
        self.assertEqual(running(self.report(wire, model=second))["comparison"], "agreement")

    def test_mutating_caller_input_during_queries_cannot_rebind_collected_facts(self):
        resource = self.model.model["resources"][0]
        queries = Queries()
        def mutate(argv):
            resource["id"] = "different-logical-id"
            resource["identity"]["project"] = "different-project"
            resource["desired"]["services"][:] = ["worker"]
            return queries(argv)
        batch = observe_compose(resource, host_id=HOST, accepted_engine_id=ENGINE,
                                runner=mutate, observed_at=WHEN).observations
        self.assertEqual(batch.coverage, ("deployment",))
        for fact in batch.facts:
            self.assertEqual(fact.resource_id, "deployment")
            self.assertEqual(fact.identity["project"], "example")
        self.assertEqual(running(self.report(batch.as_dict()))["comparison"], "agreement")

    def test_scope_is_deeply_immutable_and_bounded_without_losing_other_observations(self):
        batch = self.observe().observations
        fact = next(row for row in batch.facts if row.property == "running")
        scope = fact.compose_context
        self.assertEqual(scope.services, ("app",))
        with self.assertRaises(FrozenInstanceError):
            scope.engine_id = "different"
        with self.assertRaises(FrozenInstanceError):
            scope.services = ("worker",)
        wire = fact.as_dict()
        wire["compose_context"]["services"].append("worker")
        self.assertEqual(fact.as_dict()["compose_context"]["services"], ["app"])
        names = tuple(f"service{i}" for i in range(MAX_COMPOSE_SERVICES))
        self.assertEqual(len(ComposeContext(ENGINE, names).services), MAX_COMPOSE_SERVICES)
        with self.assertRaisesRegex(ValueError, "invalid_compose_observation_context"):
            ComposeContext(ENGINE, (*names, "excess"))
        oversized = declaration((*names, "excess"))
        inventory = self.observe(oversized)
        facts = {row.property: row for row in inventory.observations.facts}
        self.assertTrue(facts["present"].value)
        self.assertEqual(facts["running"].state, "unknown")
        self.assertIsNone(facts["running"].compose_context.services)
        self.assertLess(len(json.dumps(inventory.observations.as_dict())), 10000)

    def test_malformed_context_uses_fixed_projection_errors(self):
        original = self.observe().observations.as_dict()
        invalid = (None, [], {}, {"engine_id": True}, {"engine_id": ""},
                   {"engine_id": "private bad engine"}, {"engine_id": ENGINE, "extra": "private"},
                   {"engine_id": ENGINE, "services": None}, {"engine_id": ENGINE, "services": "app"},
                   {"engine_id": ENGINE, "services": [True]}, {"engine_id": ENGINE, "services": ["app", "app"]},
                   {"engine_id": ENGINE, "services": ["private bad service"]},
                   {"engine_id": ENGINE, "services": [f"s{i}" for i in range(MAX_COMPOSE_SERVICES + 1)]})
        for context in invalid:
            with self.subTest(context=context):
                wire = deepcopy(original)
                next(row for row in wire["facts"] if row["property"] == "running")["compose_context"] = context
                with self.assertRaises(PlanningError) as raised:
                    self.report(wire)
                self.assertEqual(str(raised.exception), "invalid_observation_projection")
        for prop, kind, identity in (("present", "compose", {"engine": "local", "project": "example"}),
                                     ("running", "service", {"manager": "system", "unit": "example.service"})):
            wire = deepcopy(original)
            row = next(row for row in wire["facts"] if row["property"] == "running")
            wire["facts"] = [row]
            row.update(property=prop, kind=kind, identity=identity)
            with self.assertRaisesRegex(PlanningError, "invalid_observation_projection"):
                self.report(wire)

    def test_context_constructor_rejects_foreign_or_forged_shapes(self):
        fact = next(row for row in self.observe().observations.facts if row.property == "running")
        for context in ({"engine_id": ENGINE}, object()):
            with self.assertRaisesRegex(ValueError, "invalid_compose_observation_context"):
                replace(fact, compose_context=context)
        for context in (ComposeContext(ENGINE, ("app",)),):
            with self.assertRaisesRegex(ValueError, "invalid_compose_observation_context"):
                replace(fact, kind="service", compose_context=context)
            with self.assertRaisesRegex(ValueError, "invalid_compose_observation_context"):
                replace(fact, property="present", compose_context=context)
        plain = Observation(HOST, "service", "service", {"manager": "system", "unit": "example.service"},
                            "running", "known", True, WHEN, "systemd_unit_properties")
        self.assertNotIn("compose_context", plain.as_dict())

    def test_unavailable_or_changed_inventory_cannot_gain_known_results_from_context(self):
        failed = self.observe(runner=Queries(overrides={ENGINE_QUERY: [QueryResult("command_failed")]}))
        self.assertTrue(all(row.state == "unknown" for row in failed.observations.facts))
        self.assertEqual(running(self.report(failed.observations.as_dict()))["comparison"], "unknown")
        oneoff = self.observe(runner=Queries(containers={CID: container(oneoff="True")}))
        self.assertEqual(running(self.report(oneoff.observations.as_dict()))["comparison"], "unknown")


if __name__ == "__main__":
    unittest.main()
