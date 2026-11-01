"""Pure comparisons and temporary-store integration; no host observations."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager.declarations import load_declaration, physical_key
from mpkg_manager.planning import PlanningError, build_report
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
OTHER_HOST = "22345678-1234-4234-8234-123456789abc"
NOW = datetime(2026, 11, 1, 23, 0, tzinfo=timezone.utc)
WHEN = "2026-11-01T23:00:00Z"


def service(logical="web", unit="web.service", desired="{running=true, enabled=false}",
            manage='["running", "enabled"]', extra="", prefix="components=[]"):
    return load_declaration((f'''schema=1
{prefix}
[[resources]]
id="{logical}"
kind="service"
identity={{manager="system", unit="{unit}"}}
desired={desired}
manage={manage}
{extra}
''').encode())


def resource(declaration, index=0):
    return declaration.model["resources"][index]


def current(declaration, *, aliases=None):
    rows = []
    for item in declaration.model["resources"]:
        requirements = [{"consumer": component["id"], "property": requirement["property"],
                         "value": requirement["value"]}
                        for component in declaration.model["components"]
                        for requirement in component["requirements"] if requirement["resource"] == item["id"]]
        rows.append({"stable_id": str(uuid.uuid5(uuid.NAMESPACE_URL, item["id"])),
                     "logical_id": item["id"], "physical_key": list(physical_key(item, HOST, aliases or {})),
                     "definition": item, "requirements": requirements, "management": "accepted",
                     "declaration_state": "present", "pending_disposition": False,
                     "observation": {"state": "unknown", "reason": "not_observed"}})
    return {"host_id": HOST, "revision": 1, "snapshot_id": "a" * 64,
            "snapshot": {"id": "a" * 64, "source_sha256": hashlib.sha256(declaration.source_bytes).hexdigest(),
                         "canonical_sha256": declaration.sha256, "schema_version": 1,
                         "normalization_version": 1}, "resources": rows}


def fact(item, prop, value, *, state="known", identity=None):
    return {"host_id": HOST, "resource_id": item["id"], "kind": item["kind"],
            "identity": item["identity"] if identity is None else identity, "property": prop,
            "state": state, "value": value, "observed_at": WHEN,
            "evidence_source": ("pacman_installed_inventory" if item["kind"] == "package"
                                else "systemd_unit_properties"),
            "limitations": ["query_unavailable"] if state == "unknown" else []}


def batch(declaration, facts, *, when=WHEN, host=HOST, coverage=None):
    facts = deepcopy(facts)
    for item in facts:
        item["host_id"], item["observed_at"] = host, when
    return {"host_id": host, "observed_at": when, "facts": facts,
            "coverage": [item["id"] for item in declaration.model["resources"]] if coverage is None else coverage,
            "limitations": []}


def properties(report, index=0):
    return {item["property"]: item for item in report["resources"][index]["properties"]}


class PlanningTests(unittest.TestCase):
    def setUp(self):
        self.declaration = service()
        self.record = current(self.declaration)
        self.observations = batch(self.declaration, [fact(resource(self.declaration), "running", True),
                                                    fact(resource(self.declaration), "enabled", False)])

    def report(self, declaration=None, record=None, observations=None, **kwargs):
        return build_report(declaration or self.declaration,
                            self.record if record is None else record,
                            self.observations if observations is None else observations,
                            host_id=HOST, now=NOW, **kwargs).as_dict()

    def assert_error(self, code, callback):
        with self.assertRaises(PlanningError) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def test_agreement_difference_unknown_coexist_without_executable_plan(self):
        declaration = load_declaration(b'''schema=1
components=[]
[[resources]]
id="service"
kind="service"
identity={manager="system", unit="example.service"}
manage=["running", "enabled"]
desired={running=true, enabled=false}
[[resources]]
id="package"
kind="package"
identity={name="example"}
desired={source="repository"}
''')
        item = resource(declaration)
        result = self.report(declaration, current(declaration), batch(declaration, [
            fact(item, "running", True), fact(item, "enabled", True),
            fact(resource(declaration, 1), "source", None, state="unknown")]))
        self.assertEqual({key: value["comparison"] for key, value in properties(result).items()},
                         {"running": "agreement", "enabled": "difference"})
        self.assertEqual(properties(result, 1)["source"]["comparison"], "unknown")
        self.assertFalse(result["executable"])
        self.assertIn("application_not_implemented", result["blockers"])
        self.assertIn("attempt_history_unavailable", result["blockers"])
        self.assertNotIn("actions", result)

    def test_missing_or_wrong_host_history_never_grants_authority(self):
        for record, expected in [(None, "history_unavailable"),
                                 ({**self.record, "host_id": OTHER_HOST, "resources": []}, "history_host_mismatch")]:
            with self.subTest(record=record):
                result = build_report(self.declaration, record, self.observations,
                                      host_id=HOST, now=NOW).as_dict()
                self.assertIn(expected, result["blockers"])
                self.assertTrue(all(not row["authority"] for row in properties(result).values()))
                self.assertEqual(result["management"]["revision"], None)

    def test_stale_future_and_wrong_host_evidence_are_unknown(self):
        for observations, reason in [
            (batch(self.declaration, self.observations["facts"], when="2026-11-01T22:58:59Z"), "stale"),
            (batch(self.declaration, self.observations["facts"], when="2026-11-01T23:00:01Z"), "from_future"),
            (batch(self.declaration, self.observations["facts"], host=OTHER_HOST), "host_mismatch"),
            (None, "unavailable"),
        ]:
            with self.subTest(reason=reason):
                result = build_report(self.declaration, self.record, observations,
                                      host_id=HOST, now=NOW).as_dict()
                self.assertIn("observations_" + reason, result["blockers"])
                self.assertTrue(all(row["comparison"] == "unknown" for row in properties(result).values()))

    def test_freshness_boundary_and_identity_are_checked_per_property(self):
        at_limit = batch(self.declaration, self.observations["facts"], when="2026-11-01T22:59:00Z")
        self.assertEqual(properties(self.report(observations=at_limit))["running"]["comparison"], "agreement")
        wrong = deepcopy(self.observations)
        wrong["facts"][0]["identity"]["unit"] = "other.service"
        result = self.report(observations=wrong)
        self.assertEqual(properties(result)["running"]["limitations"], ["observation_identity_mismatch"])
        self.assertEqual(properties(result)["enabled"]["comparison"], "agreement")

    def test_observation_identity_requires_exact_fields_for_its_kind(self):
        for identity in ({"a": "system", "b": "web.service"},
                         {"manager": "system", "unit": "web.service", "ignored": "extra"},
                         {"manager": "user", "unit": "web.service"}):
            with self.subTest(identity=identity):
                observations = deepcopy(self.observations)
                observations["facts"][0]["identity"] = identity
                self.assert_error("invalid_observation_projection",
                                  lambda: self.report(observations=observations))
        record = deepcopy(self.record)
        record["resources"][0]["definition"]["identity"] = {"a": "system", "b": "web.service"}
        self.assert_error("invalid_management_projection", lambda: self.report(record=record))

    def test_missing_coverage_and_properties_are_not_empty_clean_results(self):
        empty = batch(self.declaration, [], coverage=[])
        self.assertEqual(properties(self.report(observations=empty))["running"]["limitations"],
                         ["resource_not_inspected"])
        missing = batch(self.declaration, [])
        self.assertEqual(properties(self.report(observations=missing))["running"]["limitations"],
                         ["property_not_inspected"])

    def test_boolean_and_integer_values_do_not_compare_equal(self):
        observations = deepcopy(self.observations)
        observations["facts"][0]["value"] = 1
        result = self.report(observations=observations)
        self.assertEqual(properties(result)["running"]["comparison"], "difference")

    def test_any_and_exact_package_versions_do_not_pin_or_resolve_requests(self):
        for policy, comparison in [('{policy="any"}', "agreement"),
                                   ('{policy="exact",value="1-1"}', "difference")]:
            declaration = load_declaration(('''schema=1
components=[]
[[resources]]
id="requested"
kind="package"
identity={name="virtual-request"}
manage=["present", "version"]
desired={present=true, version=''' + policy + '}\n').encode())
            item = resource(declaration)
            before = declaration.canonical_bytes
            result = self.report(declaration, current(declaration), batch(declaration, [
                fact(item, "present", True), fact(item, "version", "2-1")]))
            self.assertEqual(properties(result)["version"]["comparison"], comparison)
            self.assertIn("native_resolution_not_performed", result["blockers"])
            self.assertEqual(declaration.canonical_bytes, before)
            absent = self.report(declaration, current(declaration), batch(declaration, [
                fact(item, "present", False), fact(item, "version", "2-1")]))
            self.assertEqual(properties(absent)["present"]["comparison"], "unknown")
            self.assertEqual(properties(absent)["version"]["comparison"], "unknown")
            self.assertIn("package_request_resolution_unknown", absent["blockers"])

    def test_reference_requirements_cannot_acquire_management_authority(self):
        declaration = service(manage="[]", prefix='''[[components]]
id="app"
purpose="fixture"
resources=["web"]
requirements=[{resource="web",property="running",value=true}]''')
        observations = batch(declaration, [fact(resource(declaration), "running", False)])
        result = self.report(declaration, current(declaration), observations)
        self.assertFalse(properties(result)["running"]["authority"])
        self.assertIn("property_authority_missing", result["blockers"])

    def test_new_declaration_grant_does_not_upgrade_accepted_authority(self):
        old = service(manage="[]")
        observations = batch(self.declaration, [fact(resource(self.declaration), "running", False)])
        result = self.report(record=current(old), observations=observations)
        self.assertFalse(properties(result)["running"]["authority"])
        self.assertIn("property_authority_missing", result["blockers"])

    def test_currently_unrequested_grant_and_relinquishment_never_grant_authority(self):
        requested = service(manage="[]")
        self.assertFalse(properties(self.report(requested))["running"]["authority"])
        relinquished = deepcopy(self.record)
        relinquished["resources"][0]["management"] = "relinquished"
        result = self.report(record=relinquished)
        self.assertEqual(result["resources"][0]["management"], "relinquished")
        self.assertFalse(properties(result)["running"]["authority"])

    def test_recipe_binding_is_not_proven_by_an_installed_version(self):
        declaration = load_declaration(('''schema=1
components=[]
[[resources]]
id="package"
kind="package"
identity={name="example"}
desired={source="aur",version={policy="exact",value="1-1",recipe_revision="'''
            + "a" * 40 + '"}}\n').encode())
        item = resource(declaration)
        result = self.report(declaration, current(declaration), batch(declaration, [
            fact(item, "present", True), fact(item, "version", "1-1")]))
        self.assertEqual(properties(result)["version"]["comparison"], "unknown")
        self.assertIn("recipe_provenance_unverified", result["blockers"])

    def test_recorded_consumer_constraints_remain_and_can_conflict(self):
        record = deepcopy(self.record)
        record["resources"][0]["definition"]["consumers"] = ["external:backup"]
        record["resources"][0]["requirements"] = [
            {"consumer": "external:backup", "property": "running", "value": False}]
        result = self.report(record=record)
        self.assertEqual(properties(result)["running"]["comparison"], "conflict")
        self.assertIn("consumer_requirement_conflict", result["blockers"])
        self.assertIn("consumer_change_requires_recording", result["blockers"])
        self.assertEqual(result["resources"][0]["known_consumers"], ["external:backup"])

    def test_retained_package_requirements_validate_the_combined_version_context(self):
        old = load_declaration(b'''schema=1
[[components]]
id="consumer"
purpose="fixture"
resources=["package"]
requirements=[{resource="package",property="source",value="aur"}]
[[resources]]
id="package"
kind="package"
identity={name="example"}
''')
        new = load_declaration(b'''schema=1
components=[]
[[resources]]
id="package"
kind="package"
identity={name="example"}
desired={version={policy="exact",value="1-1"}}
''')
        item = resource(new)
        result = self.report(new, current(old), batch(new, [fact(item, "present", True),
            fact(item, "source", "aur"), fact(item, "version", "1-1")]))
        self.assertEqual({row["comparison"] for row in properties(result).values()}, {"conflict"})
        self.assertIn("consumer_context_conflict", result["blockers"])
        self.assertTrue(all(not row["authority"] for row in properties(result).values()))

    def test_retained_file_input_requirements_keep_context_and_exclusivity(self):
        old = load_declaration(b'''schema=1
[[components]]
id="consumer"
purpose="fixture"
resources=["config"]
requirements=[{resource="config",property="content_input",value="bundle"}]
[[resources]]
id="config"
kind="file"
identity={path="/fixture/config"}
[[inputs]]
id="bundle"
base_directory="/fixture"
files=[{path="config",classification="nonsecret"}]
''')
        matching = self.report(old, current(old), batch(old, [
            fact(resource(old), "content_input", "bundle")]))
        self.assertEqual(properties(matching)["content_input"]["comparison"], "unknown")
        self.assertNotIn("consumer_context_conflict", matching["blockers"])
        self.assertFalse(properties(matching)["content_input"]["authority"])
        for desired, bundle in [('content="inline"', ""), ("mode=0o600", ""),
                               ("mode=0o600", '''[[inputs]]
id="bundle"
base_directory="/fixture"
files=[{path="config",classification="nonsecret"},
       {path="second",classification="nonsecret"}]
''')]:
            with self.subTest(desired=desired, bundle=bool(bundle)):
                new = load_declaration(('''schema=1
components=[]
[[resources]]
id="config"
kind="file"
identity={path="/fixture/config"}
desired={''' + desired + '}\n' + bundle).encode())
                item = resource(new)
                observations = batch(new, [fact(item, "content_input", "bundle"),
                    fact(item, "mode", 0o600), fact(item, "content", "inline")])
                result = self.report(new, current(old), observations)
                self.assertEqual({row["comparison"] for row in properties(result).values()}, {"conflict"})
                self.assertIn("consumer_context_conflict", result["blockers"])

    def test_physical_identity_survives_logical_rename(self):
        declaration = service(logical="renamed")
        observations = batch(declaration, [fact(resource(declaration), "running", True)])
        result = self.report(declaration, self.record, observations)
        self.assertTrue(properties(result)["running"]["authority"])
        self.assertEqual(result["retained_resources"], [])

    def test_path_kind_change_does_not_inherit_a_different_kinds_authority(self):
        def path_kind(kind):
            return load_declaration((f'''schema=1
components=[]
[[resources]]
id="path"
kind="{kind}"
identity={{path="/fixture"}}
manage=["mode"]
desired={{mode=0o750}}
''').encode())
        old, new = path_kind("file"), path_kind("directory")
        result = self.report(new, current(old), batch(new, [fact(resource(new), "mode", 0o700)]))
        self.assertFalse(properties(result)["mode"]["authority"])
        self.assertEqual(result["resources"][0]["management"], "identity_mismatch")

    def test_removed_declaration_keeps_a_decision_without_deletion_default(self):
        empty = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")
        result = self.report(empty, self.record, batch(empty, []), selected_components=[])
        self.assertEqual(result["retained_resources"][0]["required_decision"], "retire_or_relinquish")
        self.assertIn("retained_resource_disposition_required", result["blockers"])
        self.assertNotIn("delete", result["retained_resources"][0])
        relinquished = deepcopy(self.record)
        relinquished["resources"][0]["management"] = "relinquished"
        result = self.report(empty, relinquished, batch(empty, []))
        self.assertIsNone(result["retained_resources"][0]["required_decision"])
        self.assertEqual(result["retained_resources"][0]["management"], "relinquished")

    def test_selection_includes_prerequisites_and_cannot_hide_retained_history(self):
        raw = b'''schema=1
[[components]]
id="app"
purpose="fixture"
resources=["web"]
[[resources]]
id="web"
kind="service"
identity={manager="system",unit="web.service"}
requires=["support"]
desired={running=true}
[[resources]]
id="support"
kind="package"
identity={name="support"}
desired={present=true}
'''
        declaration = load_declaration(raw)
        retained = current(service(logical="removed", unit="removed.service"))
        result = self.report(declaration, retained, batch(declaration, []), selected_components=["app"])
        self.assertEqual([row["resource_id"] for row in result["resources"]], ["web", "support"])
        self.assertEqual(result["retained_resources"][0]["logical_id"], "removed")
        existing = self.report(declaration, current(declaration), batch(declaration, []),
                               selected_components=[])
        self.assertEqual(existing["resources"], [])
        self.assertEqual([row["logical_id"] for row in existing["unselected_resources"]],
                         ["web", "support"])

    def test_reintroduced_declaration_does_not_clear_recorded_disposition(self):
        record = deepcopy(self.record)
        record["resources"][0]["pending_disposition"] = True
        record["resources"][0]["declaration_state"] = "absent"
        self.assertIn("recorded_disposition_pending", self.report(record=record)["blockers"])

    def test_comments_change_exact_source_binding_without_changing_model(self):
        changed = load_declaration(b"# changed source\n" + self.declaration.source_bytes)
        self.assertEqual(changed.sha256, self.declaration.sha256)
        self.assertFalse(self.report(changed)["target"]["recorded"])
        self.assertTrue(self.report()["target"]["recorded"])

    def test_required_checks_remain_separate_and_removed_checks_not_forgotten(self):
        declaration = service(extra='''checks=["state", "endpoint"]
[[checks]]
id="state"
kind="service"
resource="web"
timeout_seconds=3
expected={running=true}
[[checks]]
id="endpoint"
kind="endpoint"
resource="web"
timeout_seconds=3
url="http://127.0.0.1:8080/"
expected_status=200''')
        result = self.report(declaration, current(declaration), batch(declaration, self.observations["facts"]))
        checks = {row["id"]: row for row in result["resources"][0]["checks"]}
        self.assertEqual(checks["state"]["result"], "passed")
        self.assertEqual(checks["endpoint"]["result"], "unknown")
        self.assertIn("functional_health_not_established", result["blockers"])
        self.assertIn("accepted_check_definition_unavailable", result["blockers"])
        result = self.report(record=current(declaration))
        self.assertTrue(all(row["reason"] == "accepted_check_unavailable"
                            for row in result["resources"][0]["checks"]))

    def test_unbound_engine_cannot_be_matched_by_symbolic_alias(self):
        declaration = load_declaration(b'''schema=1
components=[]
[[resources]]
id="app"
kind="compose"
identity={engine="local",project="example"}
manage=["running"]
desired={running=true}
''')
        record = current(declaration, aliases={"local": "accepted-engine"})
        observations = batch(declaration, [fact(resource(declaration), "running", True)])
        result = self.report(declaration, record, observations)
        self.assertIn("physical_identity_unbound", result["blockers"])
        self.assertFalse(properties(result)["running"]["authority"])
        self.assertEqual(result["retained_resources"][0]["required_decision"], "identity_unresolved")

    def test_accepted_engine_definitions_must_match_the_recorded_physical_key(self):
        declaration = load_declaration(b'''schema=1
components=[]
[[resources]]
id="app"
kind="compose"
identity={engine="local",project="example"}
manage=["running"]
desired={running=true}
''')
        aliases = {"local": "accepted-engine"}
        record = current(declaration, aliases=aliases)
        observations = batch(declaration, [fact(resource(declaration), "running", True)])
        wrong = deepcopy(record)
        wrong["resources"][0]["definition"]["identity"]["project"] = "different-project"
        self.assert_error("invalid_management_projection", lambda: self.report(
            declaration, wrong, observations, engine_aliases=aliases))
        renamed = load_declaration(declaration.source_bytes.replace(b'engine="local"', b'engine="new"'))
        observations = batch(renamed, [fact(resource(renamed), "running", True)])
        result = self.report(renamed, record, observations, engine_aliases={"new": "accepted-engine"})
        self.assertFalse(properties(result)["running"]["authority"])
        self.assertIn("physical_identity_unbound", result["blockers"])
        self.assertEqual(result["retained_resources"][0]["required_decision"], "identity_unresolved")
        complete = self.report(renamed, record, observations,
                               engine_aliases={"local": "accepted-engine", "new": "accepted-engine"})
        self.assertTrue(properties(complete)["running"]["authority"])
        self.assertEqual(complete["retained_resources"], [])

    def test_required_service_check_rejects_a_mismatched_evidence_source(self):
        declaration = service(extra='''checks=["state"]
[[checks]]
id="state"
kind="service"
resource="web"
timeout_seconds=3
expected={running=true}''')
        observations = deepcopy(self.observations)
        observations["facts"][0]["evidence_source"] = "pacman_installed_inventory"
        result = self.report(declaration, current(declaration), observations)
        self.assertEqual(result["resources"][0]["checks"][0]["result"], "unknown")
        self.assertEqual(properties(result)["running"]["limitations"],
                         ["observation_source_unsupported"])

    def test_compose_reports_the_implemented_source_and_rejects_other_sources(self):
        declaration = load_declaration(b'''schema=1
components=[]
[[resources]]
id="app"
kind="compose"
identity={engine="local",project="example"}
desired={running=true}
''')
        aliases = {"local": "accepted-engine"}
        record = current(declaration, aliases=aliases)
        for source in ("docker_selected_project_inventory", "systemd_unit_properties",
                       "unsupported_adapter", "unknown-private-source"):
            observation = fact(resource(declaration), "running", True)
            observation["evidence_source"] = source
            result = self.report(declaration, record, batch(declaration, [observation]),
                                 engine_aliases=aliases)
            found = properties(result)["running"]
            if source == "docker_selected_project_inventory":
                self.assertEqual(found["comparison"], "agreement")
                self.assertEqual(found["evidence_source"], source)
            else:
                self.assertEqual(found["comparison"], "unknown")
                self.assertEqual(found["limitations"], ["observation_source_unsupported"])

    def test_unimplemented_resource_observers_cannot_supply_known_facts(self):
        declaration = load_declaration(b'''schema=1
components=[]
[[resources]]
id="data"
kind="directory"
identity={path="/fixture/data"}
desired={present=true}
''')
        for source in ("systemd_unit_properties", "docker_selected_project_inventory",
                       "pacman_installed_inventory", "unsupported_adapter", "future_observer"):
            observation = fact(resource(declaration), "present", True)
            observation["evidence_source"] = source
            result = self.report(declaration, current(declaration), batch(declaration, [observation]))
            self.assertEqual(properties(result)["present"]["comparison"], "unknown")
            self.assertIn("observation_source_unsupported", result["blockers"])

    def test_invalid_context_and_selection_fail_with_fixed_codes(self):
        for context in ({"host_id": "bad"}, {"max_age_seconds": True}, {"max_age_seconds": 0},
                        {"now": datetime(2026, 1, 1)}, {"engine_aliases": {"local": ""}}):
            self.assert_error("invalid_report_context", lambda: build_report(
                self.declaration, self.record, self.observations,
                **({"host_id": HOST, "now": NOW} | context)))
        self.assert_error("invalid_report_inputs", lambda: self.report(selected_components=["missing"]))

    def test_duplicate_facts_and_malformed_projections_have_fixed_errors(self):
        duplicate = deepcopy(self.observations)
        duplicate["facts"].append(duplicate["facts"][0])
        variants = [duplicate, {**self.observations, "facts": "SECRET_SENTINEL"},
                    {**self.observations, "coverage": ["web", "web"]},
                    {**self.observations, "unexpected": "SECRET_SENTINEL"}]
        for observation in variants:
            self.assert_error("invalid_observation_projection", lambda: self.report(observations=observation))
        invalid = deepcopy(self.record)
        invalid["resources"][0]["requirements"] = "SECRET_SENTINEL"
        self.assert_error("invalid_management_projection", lambda: self.report(record=invalid))
        invalid = deepcopy(self.record)
        invalid["resources"][0]["definition"]["identity"]["unit"] = "different.service"
        self.assert_error("invalid_management_projection", lambda: self.report(record=invalid))
        forged = replace(self.declaration, canonical_bytes=b"SECRET_SENTINEL")
        self.assert_error("invalid_declaration_snapshot", lambda: self.report(forged))

    def test_report_is_immutable_and_does_not_export_values_or_private_diagnostics(self):
        declaration = load_declaration(b'''schema=1
components=[]
[[resources]]
id="config"
kind="file"
identity={path="/fixture/config"}
manage=["content"]
desired={content="SOURCE_SECRET_SENTINEL"}
''')
        observations = batch(declaration, [fact(resource(declaration), "content", "OBSERVED_SECRET_SENTINEL")])
        observations["facts"][0]["evidence_source"] = "SOURCE_DIAGNOSTIC_SECRET"
        observations["facts"][0]["limitations"] = ["PRIVATE_LIMIT_SECRET"]
        report = build_report(declaration, current(declaration), observations, host_id=HOST, now=NOW)
        for secret in (b"SOURCE_SECRET", b"OBSERVED_SECRET", b"SOURCE_DIAGNOSTIC", b"PRIVATE_LIMIT"):
            self.assertNotIn(secret, report.canonical_bytes)
        view = report.as_dict()
        view["resources"].clear()
        self.assertTrue(report.as_dict()["resources"])
        self.assertEqual(hashlib.sha256(report.canonical_bytes).hexdigest(), report.sha256)

    def test_build_report_does_not_read_or_write_host_state(self):
        before = deepcopy((self.record, self.observations))
        with patch("builtins.open", side_effect=AssertionError("unexpected file access")), \
             patch("subprocess.run", side_effect=AssertionError("unexpected subprocess")), \
             patch("subprocess.Popen", side_effect=AssertionError("unexpected subprocess")):
            self.report()
        self.assertEqual((self.record, self.observations), before)

    def test_actual_store_projection_retains_uncommitted_removal_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state"
            with HostStore.create(path, HOST, owner_uid=os.geteuid()) as store:
                store.adopt(self.declaration, 0, ["web"])
                projection = store.current()
                before = {entry.name: (entry.read_bytes(), entry.stat().st_mtime_ns) for entry in path.iterdir()}
                empty = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")
                result = build_report(empty, projection, batch(empty, []), host_id=HOST, now=NOW).as_dict()
                self.assertFalse(result["target"]["recorded"])
                self.assertEqual(result["retained_resources"][0]["required_decision"], "retire_or_relinquish")
                after = {entry.name: (entry.read_bytes(), entry.stat().st_mtime_ns) for entry in path.iterdir()}
                self.assertEqual(before, after)

    def test_actual_relinquishment_preserves_external_consumer_requirements(self):
        old = service(desired="{running=true}", manage='["running"]', prefix='''[[components]]
id="backup"
purpose="continuing consumer"
resources=["web"]
requirements=[{resource="web",property="running",value=true}]''')
        new = service(desired="{running=false}", manage='["running"]')
        with tempfile.TemporaryDirectory() as directory:
            with HostStore.create(Path(directory) / "state", HOST, owner_uid=os.geteuid()) as store:
                store.adopt(old, 0, ["web"])
                stable_id = store.current()["resources"][0]["stable_id"]
                store.relinquish([stable_id], 1)
                result = self.report(new, store.current(), batch(new, [fact(resource(new), "running", False)]))
        self.assertEqual(result["resources"][0]["management"], "relinquished")
        self.assertEqual(result["resources"][0]["known_consumers"], ["backup"])
        self.assertEqual(properties(result)["running"]["comparison"], "conflict")
        self.assertFalse(properties(result)["running"]["authority"])


if __name__ == "__main__":
    unittest.main()
