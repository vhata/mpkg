"""Inventory capabilities stay narrower than caller-supplied fact projections."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest

from mpkg_manager.declarations import load_declaration
from mpkg_manager.observe_native import PACKAGE_EXPLICIT, PACKAGE_VERSIONS, observe_resources
from mpkg_manager.planning import build_report
from mpkg_manager.query_process import QueryResult
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T12:00:00Z"
NOW = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)


def declaration(*, retained_source=False):
    component = ('''[[components]]
id="app"
purpose="retained source requirement"
resources=["pkg"]
requirements=[{resource="pkg",property="source",value="aur"}]
''' if retained_source else "components=[]\n")
    return load_declaration(('''schema=1
''' + component + '''[[resources]]
id="pkg"
kind="package"
identity={name="fixture"}
desired={present=true,source="aur",version={policy="any"}}
manage=["present","source","version"]
checks=["installed"]
[[checks]]
id="installed"
kind="package"
resource="pkg"
timeout_seconds=2
expected={present=true,version="1-1",reason="explicit"}
''').encode())


class PackageProvenanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "records"
        self.store = HostStore.create(self.path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.declaration = declaration()
        self.store.adopt(self.declaration, 0, ["pkg"])

    def inventory(self, *, present=True, version="1-1", error=None):
        def runner(argv):
            self.assertIn(argv, (PACKAGE_VERSIONS, PACKAGE_EXPLICIT))
            if error:
                return QueryResult(error)
            if argv == PACKAGE_VERSIONS:
                return QueryResult("ok", f"fixture {version}\n".encode() if present else b"provider 3-1\n", 0)
            return QueryResult("ok", b"fixture\n" if present else b"provider\n", 0)
        return observe_resources(self.declaration.model["resources"], host_id=HOST,
                                 observed_at=WHEN, runner=runner).as_dict()

    def report(self, observations, declaration=None):
        return build_report(self.declaration if declaration is None else declaration,
                            self.store.current(), observations, host_id=HOST, now=NOW).as_dict()

    def properties(self, report):
        return {row["property"]: row for row in report["resources"][0]["properties"]}

    def files(self):
        return {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                for path in self.path.iterdir()}

    def test_known_provenance_cannot_exceed_the_real_inventory_source(self):
        inventory = self.inventory()
        baseline = self.report(inventory)
        self.assertEqual(self.properties(baseline)["source"]["comparison"], "unknown")
        before = self.files()
        for value in ("aur", "repository", "unknown"):
            with self.subTest(value=value):
                supplied = deepcopy(inventory)
                source = next(row for row in supplied["facts"] if row["property"] == "source")
                source.update(state="known", value=value, limitations=[])
                result = self.report(supplied)
                found = self.properties(result)["source"]
                self.assertEqual(found["comparison"], "unknown")
                self.assertEqual(found["limitations"], ["observation_property_unsupported"])
                self.assertEqual(found["evidence_source"], "pacman_installed_inventory")
                # Existing accepted/requested grants are unchanged; lack of
                # provenance evidence is independent of management authority.
                self.assertTrue(found["authority"])
                self.assertIn("observation_property_unsupported", result["blockers"])
                self.assertFalse(result["executable"])
        self.assertEqual(self.files(), before)

    def test_supported_presence_version_and_reason_keep_their_results(self):
        for version, outcome in (("1-1", "passed"), ("2-1", "failed")):
            with self.subTest(version=version):
                result = self.report(self.inventory(version=version))
                found = self.properties(result)
                self.assertEqual(found["present"]["comparison"], "agreement")
                self.assertEqual(found["version"]["comparison"], "agreement")
                self.assertEqual(found["source"]["comparison"], "unknown")
                self.assertEqual([row["result"] for row in result["resources"][0]["checks"]],
                                 [outcome, outcome])
                self.assertIn("native_resolution_not_performed", result["blockers"])

    def test_missing_direct_name_and_failed_inventory_still_leave_requests_unknown(self):
        for observations in (self.inventory(present=False), self.inventory(error="command_failed")):
            with self.subTest(observations=observations):
                result = self.report(observations)
                self.assertEqual({row["comparison"] for row in self.properties(result).values()}, {"unknown"})
                self.assertEqual({row["result"] for row in result["resources"][0]["checks"]}, {"unknown"})
                self.assertFalse(result["executable"])

    def test_retained_source_constraint_cannot_be_satisfied_by_a_projection_claim(self):
        accepted = declaration(retained_source=True)
        self.store.adopt(accepted, 1, ["pkg"])
        changed = load_declaration(self.declaration.source_bytes.replace(b'source="aur",', b'')
                                  .replace(b'"present","source","version"', b'"present","version"'))
        self.store.record_intent(changed, 2)
        observations = self.inventory()
        source = next(row for row in observations["facts"] if row["property"] == "source")
        source.update(state="known", value="aur", limitations=[])
        result = self.report(observations, changed)
        found = self.properties(result)["source"]
        self.assertEqual(found["comparison"], "unknown")
        self.assertEqual(found["limitations"], ["observation_property_unsupported"])
        self.assertFalse(found["authority"])
        self.assertIn("app", result["resources"][0]["known_consumers"])
        self.assertNotIn('"value"', json.dumps(result))


if __name__ == "__main__":
    unittest.main()
