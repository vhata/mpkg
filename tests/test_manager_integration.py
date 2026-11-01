"""Real recording and observer parsers, synthetic queries, no live host tools."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.observations import ObservationBatch
from mpkg_manager.observe_compose import (CONTAINER_QUERY, ENGINE_QUERY, IMAGE_QUERY,
                                           LIST_QUERY, PROJECT_FILTER, observe_compose)
from mpkg_manager.observe_native import PACKAGE_EXPLICIT, PACKAGE_VERSIONS, SERVICE_QUERY, observe_resources
from mpkg_manager.planning import build_report
from mpkg_manager.protected_capture import CaptureError, capture_protected
from mpkg_manager.query_process import QueryResult
from mpkg_manager.sonarr_xml import SonarrXmlError, transform_port
from mpkg_manager.store import HostStore, ProtectedInput


HOST = "98d1f834-494b-4a5e-bad0-ab8fb03fecb2"
OTHER_HOST = "22345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-01T23:00:00Z"
NOW = datetime(2026, 11, 1, 23, 0, tzinfo=timezone.utc)
ENGINE = "accepted-fixture-engine"
ALIASES = {"local": ENGINE}
CID, IMAGE, NETWORK = "a" * 64, "sha256:" + "b" * 64, "c" * 64
PRIVATE = "private-integration-sentinel"
REFERENCE = "b6df63a2-012b-4ae4-96b5-aedffb516c35"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")
SOURCE = f'''schema=1
[[components]]
id="native"
purpose="native fixture"
resources=["pkg","daemon"]
[[components]]
id="app"
purpose="container fixture"
resources=["deployment","volume"]
[[components]]
id="backup"
purpose="continuing shared data consumer"
resources=["data","volume"]
requirements=[{{resource="data",property="present",value=true}}]
[[resources]]
id="pkg"
kind="package"
identity={{name="example"}}
manage=["present"]
desired={{present=true,source="repository",version={{policy="any"}}}}
checks=["installed"]
[[resources]]
id="daemon"
kind="service"
identity={{manager="system",unit="example.service"}}
manage=["running","enabled"]
desired={{running=true,enabled=false}}
checks=["daemon-state"]
[[resources]]
id="deployment"
kind="compose"
identity={{engine="local",project="example"}}
manage=["running"]
desired={{running=true,services=["app"]}}
input={{bundle="application-inputs"}}
checks=["endpoint"]
[[resources]]
id="volume"
kind="volume"
identity={{engine="local",name="config"}}
desired={{present=true}}
consumers=["external:archive"]
[[resources]]
id="data"
kind="directory"
identity={{path="/srv/media"}}
desired={{mode=0o750}}
checks=["backup-access"]
[[inputs]]
id="application-inputs"
base_directory="/fixture/app"
files=[{{path="compose.yaml",classification="nonsecret"}},
       {{path=".env",classification="protected",reference="{REFERENCE}"}}]
[[checks]]
id="installed"
kind="package"
resource="pkg"
timeout_seconds=3
expected={{present=true,version="2-1",reason="explicit"}}
[[checks]]
id="daemon-state"
kind="service"
resource="daemon"
timeout_seconds=3
expected={{running=true}}
[[checks]]
id="endpoint"
kind="endpoint"
resource="deployment"
timeout_seconds=3
url="http://127.0.0.1:8080/"
expected_status=200
[[checks]]
id="backup-access"
kind="access"
resource="data"
timeout_seconds=3
as_user="backup"
operation="read"
consumer="backup"
'''.encode()


class NativeQueries:
    def __init__(self, *, present=True, running=True, failure=None):
        self.present, self.running, self.failure = present, running, failure
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if self.failure:
            return QueryResult(self.failure)
        if argv == PACKAGE_VERSIONS:
            return QueryResult("ok", b"example 2-1\n" if self.present else b"provider 3-1\n")
        if argv == PACKAGE_EXPLICIT:
            return QueryResult("ok", b"example\n" if self.present else b"provider\n")
        if argv == SERVICE_QUERY + ("example.service",):
            values = {"LoadState": "loaded", "ActiveState": "active" if self.running else "inactive",
                      "SubState": "running" if self.running else "dead", "UnitFileState": "enabled",
                      "Type": "simple", "MainPID": "142" if self.running else "0",
                      "InvocationID": "1234567890abcdef1234567890abcdef",
                      "ActiveEnterTimestampMonotonic": "100000"}
            return QueryResult("ok", "".join(f"{key}={value}\n" for key, value in values.items()).encode())
        raise AssertionError("Unexpected native query")


class DockerQueries:
    def __init__(self, *, running=True, private_failure=False):
        self.running, self.private_failure = running, private_failure
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if self.private_failure:
            return QueryResult("ok", (PRIVATE + " invalid daemon response").encode())
        if argv == ENGINE_QUERY:
            value = ENGINE
        elif argv == LIST_QUERY + (PROJECT_FILTER + "example",):
            return QueryResult("ok", (CID + "\n").encode())
        elif argv == CONTAINER_QUERY + (CID,):
            value = {"id": CID, "image_id": IMAGE, "status": "running" if self.running else "exited",
                     "running": self.running, "started_at": "2026-11-01T22:00:00Z",
                     "finished_at": "0001-01-01T00:00:00Z", "project": "example", "service": "app",
                     "number": "1", "oneoff": "False", "mounts": [
                         {"type": "volume", "source": "/private/docker/volume-backing",
                          "target": "/config", "name": "config", "driver": "local", "rw": True},
                         {"type": "bind", "source": "/srv/media", "target": "/media",
                          "name": None, "driver": None, "rw": False}],
                     "networks": [{"name": "example_default", "id": NETWORK}]}
        elif argv == IMAGE_QUERY + (IMAGE,):
            value = {"id": IMAGE, "os": "linux", "architecture": "amd64", "variant": None,
                     "repository_digests": ["example.org/app@sha256:" + "d" * 64]}
        else:
            raise AssertionError("Unexpected Docker query")
        return QueryResult("ok", json.dumps(value).encode())


def property_result(report, resource_id, prop):
    row = next(row for row in report["resources"] if row["resource_id"] == resource_id)
    return next(value for value in row["properties"] if value["property"] == prop)


def check_results(row):
    return {(check["role"], check["id"]): check["result"] for check in row["checks"]}


def stored_files(path):
    return {item.name: (item.read_bytes(), item.stat().st_mtime_ns, item.stat().st_mode)
            for item in path.iterdir()}


class ManagerIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "records"
        self.declaration = load_declaration(SOURCE)
        self.store = HostStore.create(self.path, HOST, engine_aliases=ALIASES, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        capture = ProtectedInput("application-env", PRIVATE.encode(),
            {"path": "/fixture/app/.env", "device": 1, "inode": 2, "size": len(PRIVATE),
             "mtime_ns": 3, "uid": os.geteuid(), "gid": os.getegid(),
             "mode": stat.S_IFREG | 0o600, "links": 1}, "fixture-only protected capture")
        self.decision = self.store.adopt(self.declaration, 0,
            [resource["id"] for resource in self.declaration.model["resources"]], protected_inputs=[capture])

    def observe(self, declaration=None, *, native=None, docker=None, host=HOST, when=WHEN):
        declaration = self.declaration if declaration is None else declaration
        native, docker = native or NativeQueries(), docker or DockerQueries()
        resources = declaration.model["resources"]
        with patch("subprocess.Popen", side_effect=AssertionError("Live process invocation")):
            observed = observe_resources([resource for resource in resources if resource["kind"] != "compose"],
                                         host_id=host, observed_at=when, runner=native)
            inventory = observe_compose(next(resource for resource in resources if resource["kind"] == "compose"),
                                        host_id=host, accepted_engine_id=ENGINE, observed_at=when, runner=docker)
        # Test assembly is explicit: each adapter owns a disjoint resource set
        # and supplies exactly the same host/time context. No production CLI
        # or general observation coordinator is implied by this helper.
        batch = ObservationBatch(host, when, observed.facts + inventory.observations.facts,
            observed.coverage + inventory.observations.coverage,
            tuple(dict.fromkeys(observed.limitations + inventory.observations.limitations)))
        return batch, inventory, native, docker

    def report(self, batch, declaration=None, **kwargs):
        return build_report(self.declaration if declaration is None else declaration,
                            self.store.current(), batch.as_dict() if isinstance(batch, ObservationBatch) else batch,
                            host_id=HOST, engine_aliases=ALIASES, now=NOW, **kwargs)

    def files(self):
        return stored_files(self.path)

    def capture_fixture(self):
        inputs = self.root / "inputs"
        inputs.mkdir(mode=0o700)
        source = inputs / "config.xml"
        original = ("<Config>\r\n  <Port>8989</Port><ApiKey>" + PRIVATE + "</ApiKey>\r\n</Config>").encode()
        source.write_bytes(original)
        source.chmod(0o600)
        policy_dir = self.root / "policy"
        policy_dir.mkdir(mode=0o700)
        policy_path = policy_dir / "host-policy.toml"
        policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{local="{ENGINE}"}}\n'
                               f'allowed_input_roots={json.dumps([str(inputs)])}\n')
        policy_path.chmod(0o600)
        declaration = load_declaration(f'''schema=1
components=[]
[[resources]]
id="sonarr"
kind="sonarr_xml"
identity={{path="{source}"}}
desired={{port=8990}}
manage=["port"]
input={{bundle="xml"}}
[[inputs]]
id="xml"
base_directory="{inputs}"
files=[{{path="config.xml",classification="protected",reference="{REFERENCE}"}}]
'''.encode())
        request = {"root": str(inputs), "relative_path": "config.xml", "name": "sonarr-config",
                   "purpose": "Integration fixture XML"}
        return policy_path, source, original, declaration, request

    def test_real_recording_observers_and_comparison_keep_separate_evidence(self):
        before = self.files()
        batch, inventory, native, docker = self.observe()
        report = self.report(batch)
        result = report.as_dict()
        self.assertEqual(self.files(), before)
        self.assertTrue(result["target"]["recorded"])
        self.assertEqual(result["management"]["revision"], 1)
        self.assertEqual(result["management"]["snapshot_id"], self.decision["snapshot_id"])
        self.assertEqual(property_result(result, "daemon", "running")["comparison"], "agreement")
        self.assertEqual(property_result(result, "daemon", "enabled")["comparison"], "difference")
        self.assertEqual(property_result(result, "pkg", "source")["comparison"], "unknown")
        self.assertEqual(property_result(result, "deployment", "running")["comparison"], "agreement")
        self.assertEqual(property_result(result, "deployment", "running")["evidence_source"],
                         "docker_selected_project_inventory")
        rows = {row["resource_id"]: row for row in result["resources"]}
        self.assertEqual(check_results(rows["pkg"]),
                         {("accepted", "installed"): "passed", ("current", "installed"): "passed"})
        self.assertEqual(check_results(rows["deployment"]),
                         {("accepted", "endpoint"): "unknown", ("current", "endpoint"): "unknown"})
        self.assertFalse(result["executable"])
        self.assertIn("functional_health_not_established", result["blockers"])
        self.assertIn("attempt_history_unavailable", result["blockers"])
        self.assertIn("input_freshness_unverified", result["blockers"])
        self.assertEqual(native.calls, [PACKAGE_VERSIONS, PACKAGE_EXPLICIT] * 2 +
                         [SERVICE_QUERY + ("example.service",)] * 2)
        self.assertEqual(docker.calls.count(ENGINE_QUERY), 2)
        self.assertEqual(inventory.as_dict()["state"], "known")
        for sentinel in (PRIVATE, REFERENCE, "/private/docker/volume-backing", IMAGE):
            self.assertNotIn(sentinel.encode(), report.canonical_bytes)
        self.assertNotIn("/private/docker/volume-backing", json.dumps(inventory.as_dict()))
        result["resources"].clear()
        self.assertTrue(report.as_dict()["resources"])
        self.assertEqual(hashlib.sha256(report.canonical_bytes).hexdigest(), report.sha256)

    def test_project_attachments_never_grant_exclusive_data_authority(self):
        batch, inventory, _, _ = self.observe(docker=DockerQueries(running=False))
        result = self.report(batch, selected_components=["app"]).as_dict()
        self.assertEqual(property_result(result, "deployment", "running")["comparison"], "difference")
        volume = next(row for row in result["resources"] if row["resource_id"] == "volume")
        self.assertIn("external:archive", volume["known_consumers"])
        self.assertIn("backup", volume["known_consumers"])
        self.assertFalse(property_result(result, "volume", "present")["authority"])
        self.assertEqual(property_result(result, "volume", "present")["comparison"], "unknown")
        self.assertEqual({row["logical_id"] for row in result["unselected_resources"]}, {"pkg", "daemon", "data"})
        self.assertFalse(inventory.as_dict()["consumers_exhaustive"])
        self.assertEqual(inventory.as_dict()["volumes"][0]["observed_container_ids"], [CID])
        self.assertEqual(inventory.as_dict()["binds"][0]["source"], "/srv/media")

    def test_removed_and_relinquished_data_remain_attributable_without_effects(self):
        stable = next(row["stable_id"] for row in self.store.current()["resources"] if row["logical_id"] == "volume")
        self.store.relinquish([stable], 1)
        self.store.record_intent(EMPTY, 2)
        before = self.files()
        batch, _, _, _ = self.observe()
        result = self.report(batch, EMPTY).as_dict()
        retained = {row["logical_id"]: row for row in result["retained_resources"]}
        self.assertEqual(result["resources"], [])
        self.assertEqual(retained["volume"]["management"], "relinquished")
        self.assertIsNone(retained["volume"]["required_decision"])
        self.assertEqual(retained["data"]["required_decision"], "retire_or_relinquish")
        self.assertEqual(check_results(retained["daemon"]), {("accepted", "daemon-state"): "passed"})
        record = next(row for row in self.store.current()["resources"] if row["logical_id"] == "volume")
        self.assertIn("external:archive", record["definition"]["consumers"])
        self.assertNotIn("delete", json.dumps(result))
        self.assertEqual(self.files(), before)

    def test_renamed_service_does_not_replace_accepted_predicates_with_weaker_intent(self):
        changed = SOURCE.replace(b'"daemon"', b'"renamed"').replace(
            b'desired={running=true,enabled=false}', b'desired={running=false,enabled=false}').replace(
            b'expected={running=true}', b'expected={running=false}')
        target = load_declaration(changed)
        self.store.record_intent(target, 1)
        batch, _, _, _ = self.observe(target, native=NativeQueries(running=False))
        result = self.report(batch, target).as_dict()
        row = next(row for row in result["resources"] if row["resource_id"] == "renamed")
        self.assertEqual(property_result(result, "renamed", "running")["comparison"], "agreement")
        self.assertEqual(check_results(row),
                         {("accepted", "daemon-state"): "failed", ("current", "daemon-state"): "passed"})
        self.assertTrue(property_result(result, "renamed", "running")["authority"])
        self.assertEqual(result["retained_resources"], [])
        self.assertIn("required_check_unverified", result["blockers"])

    def test_unavailable_native_and_private_docker_responses_never_become_absence(self):
        batch, inventory, _, _ = self.observe(native=NativeQueries(failure="permission_denied"),
                                             docker=DockerQueries(private_failure=True))
        result = self.report(batch).as_dict()
        for name, prop in (("pkg", "present"), ("daemon", "running"), ("deployment", "running")):
            self.assertEqual(property_result(result, name, prop)["comparison"], "unknown")
        self.assertEqual(inventory.as_dict()["state"], "unknown")
        self.assertEqual(inventory.as_dict()["containers"], [])
        for value in (batch.as_dict(), inventory.as_dict(), result):
            self.assertNotIn(PRIVATE, json.dumps(value))

    def test_real_adapter_evidence_is_bound_to_host_time_identity_and_source(self):
        for host, when, reason in ((OTHER_HOST, WHEN, "observations_host_mismatch"),
                                  (HOST, "2026-11-01T22:58:00Z", "observations_stale")):
            batch, _, _, _ = self.observe(host=host, when=when)
            result = self.report(batch).as_dict()
            self.assertIn(reason, result["blockers"])
            self.assertEqual(property_result(result, "deployment", "running")["comparison"], "unknown")
        batch, _, _, _ = self.observe()
        for identity, source in (({"engine": "local", "project": "other"}, "docker_selected_project_inventory"),
                                 ({"engine": "local", "project": "example"}, "systemd_unit_properties")):
            wire = deepcopy(batch.as_dict())
            row = next(row for row in wire["facts"] if row["resource_id"] == "deployment" and row["property"] == "running")
            row["identity"], row["evidence_source"] = identity, source
            result = self.report(wire).as_dict()
            self.assertEqual(property_result(result, "deployment", "running")["comparison"], "unknown")

    def test_missing_direct_package_stays_unresolved_through_the_whole_pipeline(self):
        batch, _, _, _ = self.observe(native=NativeQueries(present=False))
        self.assertIs(next(fact.value for fact in batch.for_resource("pkg") if fact.property == "present"), False)
        result = self.report(batch).as_dict()
        self.assertEqual(property_result(result, "pkg", "present")["comparison"], "unknown")
        self.assertIn("package_request_resolution_unknown", result["blockers"])
        row = next(row for row in result["resources"] if row["resource_id"] == "pkg")
        self.assertEqual(set(check_results(row).values()), {"unknown"})
        self.assertFalse(result["executable"])

    def test_protected_sonarr_candidate_does_not_become_observation_or_apply_authority(self):
        target = load_declaration(SOURCE + b'''\n[[resources]]
id="sonarr"
kind="sonarr_xml"
identity={path="/fixture/sonarr/config.xml"}
desired={port=8990}
manage=["port"]
''')
        original = ("<Config>\r\n  <Port>8989</Port><ApiKey>" + PRIVATE + "</ApiKey>\r\n</Config>").encode()
        identity = {"path": "/fixture/sonarr/config.xml", "device": 1, "inode": 3,
                    "size": len(original), "mtime_ns": 4, "uid": os.geteuid(), "gid": os.getegid(),
                    "mode": stat.S_IFREG | 0o600, "links": 1}
        self.store.adopt(target, 1, ["sonarr"],
                         protected_inputs=[ProtectedInput("sonarr-config", original, identity, "fixture XML")])
        before = self.files()
        candidate = transform_port(original, 8990, expected_original=original)
        self.assertEqual(candidate.candidate_bytes, original.replace(b"8989", b"8990"))
        self.assertFalse(candidate.as_dict()["apply_authorized"])
        self.assertEqual(self.store.compare_protected(2, "sonarr-config", original, identity), "same")
        batch, _, _, _ = self.observe(target)
        result = self.report(batch, target)
        self.assertEqual(property_result(result.as_dict(), "sonarr", "port")["comparison"], "unknown")
        self.assertFalse(result.as_dict()["executable"])
        for value in (result.canonical_bytes, json.dumps(candidate.as_dict()).encode()):
            self.assertNotIn(PRIVATE.encode(), value)
            self.assertNotIn(hashlib.sha256(original).hexdigest().encode(), value)
        self.assertEqual(self.files(), before)

    def test_loaded_policy_capture_store_and_candidate_keep_reference_resolution_unavailable(self):
        policy_path, source, original, target, request = self.capture_fixture()
        store_path = self.root / "captured-records"
        with patch("subprocess.Popen", side_effect=AssertionError("Live process invocation")), \
             load_host_policy(path=policy_path, owner_uid=os.geteuid()) as loaded:
            capture = capture_protected(loaded, **request)
            policy = loaded.policy
            with HostStore.create(store_path, policy.host_id, engine_aliases=policy.engine_aliases,
                                  owner_uid=os.geteuid()) as store:
                store.adopt(target, 0, ["sonarr"], protected_inputs=[capture])
                before = stored_files(store_path)
                current = capture_protected(loaded, **request)
                self.assertEqual(store.compare_protected(1, current.name, current.raw,
                                                        current.source_identity), "same")
                # The existing lookup is (decision, capture name). Declared
                # protected-reference UUIDs are not resolved by this API;
                # capturing and recording bytes does not close that gap.
                self.assertEqual(store.compare_protected(1, REFERENCE, current.raw,
                                                        current.source_identity), "unavailable")
                self.assertEqual(target.model["inputs"][0]["files"][0]["reference"], REFERENCE)
                candidate = transform_port(current.raw, 8990, expected_original=capture.raw)
                native = NativeQueries()
                evidence = observe_resources(target.model["resources"], host_id=policy.host_id,
                                             observed_at=WHEN, runner=native)
                report = build_report(target, store.current(), evidence.as_dict(), host_id=policy.host_id,
                                      engine_aliases=policy.engine_aliases, now=NOW).as_dict()
                self.assertEqual(native.calls, [])
                self.assertEqual(property_result(report, "sonarr", "port")["comparison"], "unknown")
                self.assertIn("input_freshness_unverified", report["blockers"])
                self.assertFalse(report["executable"])
                self.assertFalse(candidate.as_dict()["apply_authorized"])
                self.assertEqual(candidate.candidate_bytes, original.replace(b"8989", b"8990"))
                self.assertEqual(source.read_bytes(), original)
                self.assertEqual(stored_files(store_path), before)
                for public in (report, store.history(), candidate.as_dict()):
                    self.assertNotIn(PRIVATE, json.dumps(public))
                    self.assertNotIn(REFERENCE, json.dumps(public))
                    self.assertNotIn(hashlib.sha256(original).hexdigest(), json.dumps(public))

    def test_changed_real_capture_and_policy_block_stale_candidate_without_store_changes(self):
        policy_path, source, original, target, request = self.capture_fixture()
        store_path = self.root / "captured-records"
        with load_host_policy(path=policy_path, owner_uid=os.geteuid()) as loaded:
            capture = capture_protected(loaded, **request)
            policy = loaded.policy
            with HostStore.create(store_path, policy.host_id, engine_aliases=policy.engine_aliases,
                                  owner_uid=os.geteuid()) as store:
                store.record_intent(target, 0, protected_inputs=[capture])
                before = stored_files(store_path)
                changed_bytes = original.replace(b"8989", b"8991")
                source.write_bytes(changed_bytes)
                changed = capture_protected(loaded, **request)
                self.assertEqual(store.compare_protected(1, changed.name, changed.raw,
                                                        changed.source_identity), "changed")
                with self.assertRaises(SonarrXmlError) as stale:
                    transform_port(changed.raw, 8990, expected_original=capture.raw)
                self.assertEqual(stale.exception.code, "original_changed")
                policy_path.write_bytes(policy_path.read_bytes() + b"\n# changed policy\n")
                with self.assertRaises(CaptureError) as invalidated:
                    capture_protected(loaded, **request)
                self.assertEqual(invalidated.exception.code, "policy_unavailable")
                self.assertNotIn(PRIVATE, str(invalidated.exception))
                self.assertEqual(source.read_bytes(), changed_bytes)
                self.assertEqual(stored_files(store_path), before)


if __name__ == "__main__":
    unittest.main()
