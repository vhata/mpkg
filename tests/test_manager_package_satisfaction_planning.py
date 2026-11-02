"""Positive request evidence cannot become direct inventory or apply authority."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.observe_packages import QUERY, SOURCE, observe_package_requests
from mpkg_manager.planning import build_report
from mpkg_manager.query_process import QueryResult
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
OTHER_HOST = "22345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T12:00:00Z"
NOW = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)


def declaration():
    return load_declaration(b'''schema=1
components=[]
[[resources]]
id="request"
kind="package"
identity={name="virtual-request"}
desired={present=true,source="repository",version={policy="any"}}
manage=["present","source","version"]
checks=["satisfied","versioned","reasoned"]
[[checks]]
id="satisfied"
kind="package"
resource="request"
timeout_seconds=2
expected={present=true}
[[checks]]
id="versioned"
kind="package"
resource="request"
timeout_seconds=2
expected={version="1-1"}
[[checks]]
id="reasoned"
kind="package"
resource="request"
timeout_seconds=2
expected={reason="explicit"}
''')


class PackageSatisfactionPlanningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "records"
        self.store = HostStore.create(self.path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.declaration = declaration()
        self.store.adopt(self.declaration, 0, ["request"])

    def observations(self, *, unmet=False):
        calls = []
        def runner(argv):
            calls.append(argv)
            return QueryResult("ok", b"virtual-request\n" if unmet else b"", 127 if unmet else 0)
        batch = observe_package_requests(self.declaration.model["resources"], host_id=HOST,
                                         observed_at=WHEN, runner=runner)
        self.assertEqual(calls, [QUERY + ("virtual-request",)] * 2)
        return batch.as_dict()

    def report(self, observations, *, declaration=None, current=None, **kwargs):
        return build_report(self.declaration if declaration is None else declaration,
                            self.store.current() if current is None else current,
                            observations, host_id=HOST, now=NOW, **kwargs).as_dict()

    @staticmethod
    def properties(report):
        return {item["property"]: item for item in report["resources"][0]["properties"]}

    @staticmethod
    def checks(report):
        return {(item["id"], item["role"]): item for item in report["resources"][0]["checks"]}

    @staticmethod
    def extra_fact(observations, prop, value, source=SOURCE):
        fact = dict(observations["facts"][0])
        fact.update(property=prop, value=value, state="known", evidence_source=source, limitations=[])
        return fact

    def files(self):
        return {path.name: (path.read_bytes(), path.stat().st_mtime_ns,
                            path.stat().st_mode, path.stat().st_uid, path.stat().st_gid)
                for path in self.path.iterdir()}

    def test_real_adapter_store_report_path_keeps_scope_authority_and_storage(self):
        observations = self.observations()
        before = self.files()
        current = self.store.current()
        # Pure comparison may consume projections but must not query or write.
        with patch("subprocess.Popen", side_effect=AssertionError("planner launched a process")), \
                patch("builtins.open", side_effect=AssertionError("planner opened a file")):
            report = self.report(observations, current=current)
        self.assertEqual(self.files(), before)
        props = self.properties(report)
        self.assertEqual(props["present"]["comparison"], "agreement")
        self.assertEqual(props["present"]["evidence_source"], SOURCE)
        self.assertTrue(props["present"]["authority"])
        self.assertEqual(props["version"]["comparison"], "unknown")
        self.assertEqual(props["source"]["comparison"], "unknown")
        checks = self.checks(report)
        for role in ("accepted", "current"):
            self.assertEqual(checks[("satisfied", role)]["result"], "passed")
            self.assertEqual(checks[("satisfied", role)]["reason"], "property_predicates_only")
            self.assertEqual(checks[("versioned", role)]["result"], "unknown")
            self.assertEqual(checks[("reasoned", role)]["result"], "unknown")
        self.assertFalse(report["executable"])
        self.assertTrue({"application_not_implemented", "attempt_history_unavailable",
                         "native_resolution_not_performed"} <= set(report["blockers"]))
        encoded = json.dumps(report)
        self.assertNotIn("virtual-request", encoded)
        self.assertNotIn('"value"', encoded)

    def test_unmet_and_fabricated_non_true_presence_cannot_prove_absence(self):
        for value in (False, 0, 1, "true", None):
            observations = self.observations()
            observations["facts"][0]["value"] = value
            report = self.report(observations)
            with self.subTest(value=value):
                self.assertEqual(self.properties(report)["present"]["comparison"], "unknown")
                self.assertEqual(self.properties(report)["present"]["limitations"],
                                 ["package_request_resolution_unknown"])
                self.assertEqual({item["result"] for item in self.checks(report).values()}, {"unknown"})
        for state in ("unknown", "absent"):
            observations = self.observations(unmet=True)
            observations["facts"][0]["state"] = state
            report = self.report(observations)
            self.assertEqual(self.properties(report)["present"]["comparison"], "unknown")
            self.assertEqual(self.properties(report)["present"]["limitations"], ["observation_" + state])

    def test_satisfaction_source_cannot_supply_other_package_properties(self):
        observations = self.observations()
        observations["facts"] += [self.extra_fact(observations, prop, value) for prop, value in
                                   (("version", "1-1"), ("install_reason", "explicit"),
                                    ("source", "repository"), ("provider", "installed-provider"))]
        report = self.report(observations)
        props = self.properties(report)
        self.assertEqual(props["present"]["comparison"], "agreement")
        for prop in ("version", "source"):
            self.assertEqual(props[prop]["comparison"], "unknown")
            self.assertEqual(props[prop]["limitations"], ["observation_property_unsupported"])
            self.assertEqual(props[prop]["evidence_source"], SOURCE)
        for role in ("accepted", "current"):
            self.assertEqual(self.checks(report)[("versioned", role)]["result"], "unknown")
            self.assertEqual(self.checks(report)[("reasoned", role)]["result"], "unknown")
        self.assertNotIn("installed-provider", json.dumps(report))

    def test_mixed_inventory_properties_require_direct_inventory_presence(self):
        observations = self.observations()
        observations["facts"] += [self.extra_fact(observations, prop, value, "pacman_installed_inventory")
                                   for prop, value in (("version", "1-1"), ("install_reason", "explicit"))]
        report = self.report(observations)
        self.assertEqual(self.properties(report)["present"]["comparison"], "agreement")
        self.assertEqual(self.properties(report)["version"]["comparison"], "unknown")
        self.assertEqual(self.properties(report)["version"]["limitations"], ["package_request_resolution_unknown"])
        for role in ("accepted", "current"):
            self.assertEqual(self.checks(report)[("versioned", role)]["result"], "unknown")
            self.assertEqual(self.checks(report)[("reasoned", role)]["result"], "unknown")
        # The existing direct inventory contract still supports all three.
        observations["facts"][0]["evidence_source"] = "pacman_installed_inventory"
        direct = self.report(observations)
        self.assertEqual(self.properties(direct)["version"]["comparison"], "agreement")
        self.assertEqual({item["result"] for item in self.checks(direct).values()}, {"passed"})

    def test_direct_presence_cannot_bless_other_satisfaction_properties(self):
        observations = self.observations()
        observations["facts"][0]["evidence_source"] = "pacman_installed_inventory"
        observations["facts"] += [self.extra_fact(observations, prop, value) for prop, value in
                                   (("version", "1-1"), ("install_reason", "explicit"))]
        report = self.report(observations)
        self.assertEqual(self.properties(report)["version"]["comparison"], "unknown")
        self.assertEqual(self.properties(report)["version"]["limitations"], ["observation_property_unsupported"])
        for role in ("accepted", "current"):
            self.assertEqual(self.checks(report)[("reasoned", role)]["result"], "unknown")

    def test_foreign_stale_future_uncovered_or_mismatched_evidence_remains_unknown(self):
        cases = [("host", OTHER_HOST, "observations_host_mismatch"),
                 ("time", "2026-11-02T11:58:59Z", "observations_stale"),
                 ("time", "2026-11-02T12:00:01Z", "observations_from_future"),
                 ("identity", {"name": "different"}, "observation_identity_mismatch"),
                 ("coverage", None, "resource_not_inspected"),
                 ("source", "systemd_unit_properties", "observation_source_unsupported")]
        for change, value, reason in cases:
            observations = self.observations()
            if change == "host":
                observations["host_id"] = observations["facts"][0]["host_id"] = value
            elif change == "time":
                observations["observed_at"] = observations["facts"][0]["observed_at"] = value
            elif change == "identity":
                observations["facts"][0]["identity"] = value
            elif change == "coverage":
                observations.update(facts=[], coverage=[])
            else:
                observations["facts"][0]["evidence_source"] = value
            with self.subTest(change=change, value=value):
                report = self.report(observations)
                self.assertEqual(self.properties(report)["present"]["comparison"], "unknown")
                self.assertEqual(self.properties(report)["present"]["limitations"], [reason])
        observations = self.observations()
        observations["observed_at"] = observations["facts"][0]["observed_at"] = "2026-11-02T11:59:00Z"
        self.assertEqual(self.properties(self.report(observations))["present"]["comparison"], "agreement")

    def test_new_source_is_unsupported_for_other_resource_kinds(self):
        declared = load_declaration(b'''schema=1
components=[]
[[resources]]
id="file"
kind="file"
identity={path="/fixture/private/path"}
desired={present=true}
manage=["present"]
''')
        observations = self.observations()
        observations["coverage"] = ["file"]
        observations["facts"][0].update(resource_id="file", kind="file", identity={"path": "/fixture/private/path"})
        report = self.report(observations, declaration=declared)
        self.assertEqual(self.properties(report)["present"]["comparison"], "unknown")
        self.assertEqual(self.properties(report)["present"]["limitations"], ["observation_source_unsupported"])

    def test_source_changes_and_renames_do_not_create_application_or_new_adoption(self):
        original = self.store.current()
        stable = original["resources"][0]["stable_id"]
        renamed = load_declaration(self.declaration.source_bytes.replace(b'"request"', b'"renamed"'))
        self.store.record_intent(renamed, 1)
        observations = self.observations()
        observations["coverage"] = ["renamed"]
        observations["facts"][0]["resource_id"] = "renamed"
        report = self.report(observations, declaration=renamed)
        self.assertEqual(report["resources"][0]["stable_id"], stable)
        self.assertEqual(self.properties(report)["present"]["comparison"], "agreement")
        for role in ("accepted", "current"):
            self.assertEqual(self.checks(report)[("satisfied", role)]["result"], "passed")
        comment = load_declaration(renamed.source_bytes + b"# working copy\n")
        report = self.report(observations, declaration=comment)
        self.assertIn("intent_not_recorded", report["blockers"])
        self.assertFalse(report["executable"])
        self.assertEqual(self.store.current()["resources"][0]["accepted_checks"]["adoption_revision"], 1)

    def test_same_check_id_keeps_accepted_and_current_presence_predicates_distinct(self):
        changed = load_declaration(self.declaration.source_bytes.replace(
            b'expected={present=true}', b'expected={present=false}'))
        self.store.record_intent(changed, 1)
        report = self.report(self.observations(), declaration=changed)
        checks = self.checks(report)
        self.assertEqual(checks[("satisfied", "accepted")]["result"], "passed")
        self.assertEqual(checks[("satisfied", "current")]["result"], "failed")
        self.assertEqual(checks[("satisfied", "accepted")]["adoption_revision"], 1)
        self.assertFalse(report["executable"])


if __name__ == "__main__":
    unittest.main()
