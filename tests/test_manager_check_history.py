"""Accepted predicates through real temporary stores and synthetic observations."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.planning import PlanningError, build_report
from mpkg_manager.store import HostStore, ProtectedInput, StoreError


HOST = "12345678-1234-4234-8234-123456789abc"
OTHER_HOST = "22345678-1234-4234-8234-123456789abc"
NOW = datetime(2026, 11, 1, 23, 0, tzinfo=timezone.utc)
WHEN = "2026-11-01T23:00:00Z"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


def service(expected="{running=true,enabled=true}", logical="web", checks=True):
    raw = f'''schema=1
components=[]
[[resources]]
id="{logical}"
kind="service"
identity={{manager="system",unit="web.service"}}
desired={{running=true}}
manage=["running"]
checks={('["state"]' if checks else '[]')}
'''
    if checks:
        raw += f'''[[checks]]
id="state"
kind="service"
resource="{logical}"
timeout_seconds=3
expected={expected}
'''
    return load_declaration(raw.encode())


def package(version):
    return load_declaration(f'''schema=1
components=[]
[[resources]]
id="pkg"
kind="package"
identity={{name="example"}}
desired={{present=true}}
checks=["version"]
[[checks]]
id="version"
kind="package"
resource="pkg"
timeout_seconds=3
expected={{present=true,version="{version}"}}
'''.encode())


def observations(declaration, values, *, host=HOST, when=WHEN):
    facts = []
    for resource in declaration.model["resources"]:
        for prop, value in values.get(resource["id"], {}).items():
            facts.append({"host_id": host, "resource_id": resource["id"], "kind": resource["kind"],
                          "identity": resource["identity"], "property": prop, "state": "known",
                          "value": value, "observed_at": when, "evidence_source": (
                              "pacman_installed_inventory" if resource["kind"] == "package"
                              else "systemd_unit_properties"), "limitations": []})
    return {"host_id": host, "observed_at": when, "facts": facts,
            "coverage": list(values), "limitations": []}


def results(row):
    return {(check["role"], check["id"]): check["result"] for check in row["checks"]}


class AcceptedCheckHistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "records"
        self.store = HostStore.create(self.directory, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.original = service()

    def adopt(self, declaration=None, revision=0):
        declaration = self.original if declaration is None else declaration
        return self.store.adopt(declaration, revision,
                                [resource["id"] for resource in declaration.model["resources"]])

    def report(self, declaration=None, values=None, *, evidence=None, current=None, **kwargs):
        declaration = self.original if declaration is None else declaration
        values = {"web": {"running": True, "enabled": True}} if values is None else values
        return build_report(declaration, self.store.current() if current is None else current,
                            observations(declaration, values) if evidence is None else evidence,
                            host_id=HOST, now=NOW, **kwargs).as_dict()

    def assert_error(self, kind, code, callback):
        with self.assertRaises(kind) as error:
            callback()
        self.assertEqual(str(error.exception), code)
        self.assertEqual(error.exception.code, code)

    def test_unchanged_predicates_have_separate_bound_results(self):
        decision = self.adopt()
        binding = self.store.current()["resources"][0]["accepted_checks"]
        self.assertEqual(binding, {"adoption_revision": 1, "snapshot_id": decision["snapshot_id"],
                                   "definitions": self.original.model["checks"]})
        report = self.report()
        self.assertEqual(results(report["resources"][0]),
                         {("accepted", "state"): "passed", ("current", "state"): "passed"})
        accepted = report["resources"][0]["checks"][0]
        self.assertEqual(accepted["adoption_revision"], 1)
        self.assertEqual(accepted["snapshot_id"], decision["snapshot_id"])
        self.assertNotIn("accepted_check_definition_unavailable", report["blockers"])
        self.assertFalse(report["executable"])

    def test_same_id_weakening_cannot_replace_accepted_predicate(self):
        decision = self.adopt()
        weaker = service("{running=true}")
        self.store.record_intent(weaker, 1)
        report = self.report(weaker, {"web": {"running": True, "enabled": False}})
        self.assertEqual(results(report["resources"][0]),
                         {("accepted", "state"): "failed", ("current", "state"): "passed"})
        self.assertIn("required_check_unverified", report["blockers"])
        self.assertEqual(self.store.current()["resources"][0]["accepted_checks"]["snapshot_id"],
                         decision["snapshot_id"])
        self.assertNotEqual(self.store.current()["snapshot_id"], decision["snapshot_id"])

    def test_stronger_current_predicate_is_evaluated_independently(self):
        self.adopt(service("{running=true}"))
        report = self.report(values={"web": {"running": True, "enabled": False}})
        self.assertEqual(results(report["resources"][0]),
                         {("accepted", "state"): "passed", ("current", "state"): "failed"})

    def test_same_id_different_package_version_remains_two_constraints(self):
        self.adopt(package("1-ORIGINAL_VALUE"))
        current = package("2-CURRENT_VALUE")
        report = self.report(current, {"pkg": {"present": True, "version": "2-CURRENT_VALUE"}})
        self.assertEqual(results(report["resources"][0]),
                         {("accepted", "version"): "failed", ("current", "version"): "passed"})
        public = json.dumps(report)
        self.assertNotIn("ORIGINAL_VALUE", public)
        self.assertNotIn("CURRENT_VALUE", public)

    def test_rebinding_check_id_to_other_resource_cannot_satisfy_original(self):
        self.adopt()
        rebound = load_declaration(service(checks=False).source_bytes + b'''[[resources]]
id="other"
kind="service"
identity={manager="system",unit="other.service"}
checks=["state"]
[[checks]]
id="state"
kind="service"
resource="other"
timeout_seconds=3
expected={running=true}
''')
        self.store.record_intent(rebound, 1)
        report = self.report(rebound, {"web": {"running": False, "enabled": False},
                                      "other": {"running": True}})
        self.assertEqual(results(report["resources"][0]), {("accepted", "state"): "failed"})
        self.assertEqual(results(report["resources"][1]), {("current", "state"): "passed"})
        self.assertIn("required_check_unverified", report["blockers"])

    def test_removed_check_remains_required_after_intent_recording(self):
        self.adopt()
        removed = service(checks=False)
        self.store.record_intent(removed, 1)
        report = self.report(removed, {"web": {"running": True}})
        self.assertEqual(results(report["resources"][0]), {("accepted", "state"): "unknown"})
        self.assertIn("required_check_unverified", report["blockers"])

    def test_removed_declaration_keeps_checks_and_accepts_only_matching_evidence(self):
        self.adopt()
        self.store.record_intent(EMPTY, 1)
        missing = self.report(EMPTY, {})
        self.assertEqual(results(missing["retained_resources"][0]), {("accepted", "state"): "unknown"})
        evidence = observations(self.original, {"web": {"running": True, "enabled": True}})
        present = self.report(EMPTY, evidence=evidence)
        self.assertEqual(results(present["retained_resources"][0]), {("accepted", "state"): "passed"})
        self.assertEqual(present["retained_resources"][0]["required_decision"], "retire_or_relinquish")
        evidence["facts"][0]["identity"]["unit"] = "wrong.service"
        wrong = self.report(EMPTY, evidence=evidence)
        self.assertEqual(results(wrong["retained_resources"][0]), {("accepted", "state"): "unknown"})

    def test_logical_rename_maps_original_checks_by_stable_physical_identity(self):
        self.adopt()
        original = self.store.current()["resources"][0]
        renamed = service(logical="renamed")
        self.store.record_intent(renamed, 1)
        report = self.report(renamed, {"renamed": {"running": True, "enabled": True}})
        row = report["resources"][0]
        self.assertEqual(row["stable_id"], original["stable_id"])
        self.assertEqual(results(row), {("accepted", "state"): "passed", ("current", "state"): "passed"})
        self.assertEqual(self.store.current()["resources"][0]["accepted_checks"], original["accepted_checks"])

    def test_explicit_readoption_records_a_distinct_check_baseline(self):
        first = self.adopt()
        weaker = service("{running=true}")
        self.store.record_intent(weaker, 1)
        latest = self.adopt(weaker, 2)
        binding = self.store.current()["resources"][0]["accepted_checks"]
        self.assertEqual(binding["adoption_revision"], 3)
        self.assertEqual(binding["snapshot_id"], latest["snapshot_id"])
        self.assertNotEqual(binding["snapshot_id"], first["snapshot_id"])
        self.assertEqual(binding["definitions"], weaker.model["checks"])
        self.assertEqual(self.store.snapshot(first["snapshot_id"]).model["checks"], self.original.model["checks"])
        self.assertEqual(results(self.report(weaker, {"web": {"running": True}})["resources"][0]),
                         {("accepted", "state"): "passed", ("current", "state"): "passed"})

    def test_unselected_resources_keep_accepted_check_results(self):
        self.adopt()
        report = self.report(selected_components=[])
        self.assertEqual(report["resources"], [])
        self.assertEqual(results(report["unselected_resources"][0]), {("accepted", "state"): "passed"})

    def test_relinquishment_preserves_predicates_without_management_authority(self):
        self.adopt()
        recorded = self.store.current()["resources"][0]
        self.store.relinquish([recorded["stable_id"]], 1)
        weaker = service("{running=true}")
        self.store.record_intent(weaker, 2)
        self.assertEqual(self.store.current()["resources"][0]["accepted_checks"], recorded["accepted_checks"])
        report = self.report(weaker, {"web": {"running": True, "enabled": False}})
        row = report["resources"][0]
        self.assertEqual(row["management"], "relinquished")
        self.assertEqual(results(row), {("accepted", "state"): "failed", ("current", "state"): "passed"})
        self.assertTrue(all(not prop["authority"] for prop in row["properties"]))

    def test_unsupported_shared_consumer_access_checks_stay_unknown(self):
        original = load_declaration(b'''schema=1
[[components]]
id="first"
purpose="First reader"
resources=["shared"]
requirements=[{resource="shared",property="mode",value=448}]
[[components]]
id="second"
purpose="Second reader"
resources=["shared"]
requirements=[{resource="shared",property="mode",value=448}]
[[resources]]
id="shared"
kind="directory"
identity={path="/fixture/shared"}
desired={mode=448}
checks=["read"]
[[checks]]
id="read"
kind="access"
resource="shared"
timeout_seconds=3
as_user="nobody"
operation="list"
consumer="first"
''')
        self.adopt(original)
        removed = load_declaration(b'''schema=1
components=[]
[[resources]]
id="shared"
kind="directory"
identity={path="/fixture/shared"}
desired={mode=448}
''')
        self.store.record_intent(removed, 1)
        report = self.report(removed, {"shared": {"mode": 448}})
        row = report["resources"][0]
        self.assertEqual(row["known_consumers"], ["first", "second"])
        self.assertEqual(results(row), {("accepted", "read"): "unknown"})
        self.assertEqual(row["checks"][0]["reason"], "check_not_implemented")
        self.assertFalse(row["properties"][0]["authority"])

    def test_stale_wrong_host_wrong_kind_and_unavailable_evidence_stay_unknown(self):
        self.adopt()
        evidence = observations(self.original, {"web": {"running": True, "enabled": True}})
        wrong_kind = deepcopy(evidence)
        wrong_kind["facts"][0]["kind"] = "package"
        wrong_kind["facts"][0]["identity"] = {"name": "web"}
        wrong_identity = deepcopy(evidence)
        wrong_identity["facts"][0]["identity"]["unit"] = "other.service"
        wrong_source = deepcopy(evidence)
        wrong_source["facts"][0]["evidence_source"] = "unsupported_adapter"
        for value in (wrong_kind, wrong_identity, wrong_source,
                      observations(self.original, {}, host=OTHER_HOST),
                      observations(self.original, {"web": {"running": True, "enabled": True}},
                                   when="2026-11-01T22:00:00Z"),
                      observations(self.original, {})):
            report = self.report(evidence=value)
            self.assertEqual(results(report["resources"][0])[("accepted", "state")], "unknown")
            self.assertIn("required_check_unverified", report["blockers"])

    def test_endpoint_predicates_remain_unknown_without_exporting_or_probing_url(self):
        original = load_declaration(service(checks=False).source_bytes.replace(b"checks=[]", b'checks=["health"]') + b'''[[checks]]
id="health"
kind="endpoint"
resource="web"
timeout_seconds=3
url="http://127.0.0.1:8080/PRIVATE_ENDPOINT_PATH"
expected_status=200
''')
        self.adopt(original)
        report = self.report(original)
        self.assertEqual(results(report["resources"][0]),
                         {("accepted", "health"): "unknown", ("current", "health"): "unknown"})
        self.assertNotIn("PRIVATE_ENDPOINT_PATH", json.dumps(report))
        self.assertTrue(all(item["reason"] == "check_not_implemented"
                            for item in report["resources"][0]["checks"]))

    def test_historical_binding_survives_reopen_without_touching_store(self):
        self.adopt()
        before = self.store.current()["resources"][0]["accepted_checks"]
        self.store.record_intent(service("{running=true}", logical="renamed"), 1)
        self.store.close()
        inventory = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.directory.iterdir()}
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as reader:
            self.assertEqual(reader.current()["resources"][0]["accepted_checks"], before)
        self.assertEqual(inventory, {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                                     for path in self.directory.iterdir()})

    def test_missing_projection_blocks_and_invalid_bindings_fail_closed(self):
        self.adopt()
        original = self.store.current()
        legacy = deepcopy(original)
        del legacy["resources"][0]["accepted_checks"]
        report = self.report(current=legacy)
        self.assertIn("accepted_check_definition_unavailable", report["blockers"])
        self.assertEqual(results(report["resources"][0])[("accepted", "state")], "unknown")
        changes = [
            {"adoption_revision": 0}, {"adoption_revision": 2}, {"adoption_revision": True},
            {"snapshot_id": "b" * 64}, {"definitions": []},
            {"definitions": [self.original.model["checks"][0] | {"resource": "wrong"}]},
            {"definitions": [self.original.model["checks"][0] | {"private": "SECRET"}]},
        ]
        for change in changes:
            malformed = deepcopy(original)
            malformed["resources"][0]["accepted_checks"].update(change)
            self.assert_error(PlanningError, "invalid_management_projection",
                              lambda: self.report(current=malformed))

    def test_corrupt_or_missing_historical_snapshot_never_becomes_empty_checks(self):
        self.adopt()
        self.store.record_intent(EMPTY, 1)
        with sqlite3.connect(self.directory / "state.sqlite3") as db:
            trigger = db.execute("SELECT sql FROM sqlite_schema WHERE name='snapshots_delete'").fetchone()[0]
            db.execute("DROP TRIGGER snapshots_delete")
            db.execute("DELETE FROM snapshots WHERE id=(SELECT snapshot_id FROM decisions WHERE revision=1)")
            db.execute(trigger)
        self.assert_error(StoreError, "store_corrupt", self.store.current)

    def test_projection_copies_secrecy_and_pure_comparison(self):
        raw = b"PROTECTED_CAPTURE_SENTINEL"
        identity = {"path": "/fixture/private", "device": 1, "inode": 2, "size": len(raw),
                    "mtime_ns": 3, "uid": 0, "gid": 0, "mode": stat.S_IFREG | 0o600, "links": 1}
        self.store.adopt(self.original, 0, ["web"],
                         protected_inputs=[ProtectedInput("private", raw, identity, "fixture")])
        projected = self.store.current()
        projected["resources"][0]["accepted_checks"]["definitions"][0]["expected"]["running"] = False
        self.assertTrue(self.store.current()["resources"][0]["accepted_checks"]["definitions"][0]["expected"]["running"])
        current = self.store.current()
        reference, token = self.store._db.execute("SELECT id,token FROM protected_inputs").fetchone()
        public = json.dumps(current).encode()
        for private in (raw, reference.encode(), token.hex().encode(), hashlib.sha256(raw).hexdigest().encode()):
            self.assertNotIn(private, public)
        evidence = observations(self.original, {"web": {"running": True, "enabled": True}})
        before = deepcopy((current, evidence))
        inventory = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.directory.iterdir()}
        with patch("builtins.open", side_effect=AssertionError("unexpected file read")), \
             patch("subprocess.run", side_effect=AssertionError("unexpected process")), \
             patch("subprocess.Popen", side_effect=AssertionError("unexpected process")):
            report = build_report(self.original, current, evidence, host_id=HOST, now=NOW)
        self.assertEqual((current, evidence), before)
        altered = report.as_dict()
        altered["resources"][0]["checks"].clear()
        self.assertTrue(report.as_dict()["resources"][0]["checks"])
        self.assertNotIn(raw, report.canonical_bytes)
        self.assertEqual(inventory, {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                                     for path in self.directory.iterdir()})


if __name__ == "__main__":
    unittest.main()
