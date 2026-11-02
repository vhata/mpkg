"""Trusted coordinator fixtures never query the production host."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import PropertyMock, patch

from mpkg_manager import status_collection
from mpkg_manager._endpoint_process import ProbeResult
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.observe_compose import ENGINE_QUERY, LIST_QUERY, PROJECT_FILTER
from mpkg_manager.observe_native import PACKAGE_EXPLICIT, PACKAGE_VERSIONS, SERVICE_QUERY
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.query_process import QueryResult
from mpkg_manager.status_collection import StatusCollectionError, collect_status
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
ENGINE = "accepted-fixture-engine"
PRIVATE = "private-coordinator-sentinel"


def service(name="daemon", unit="fixture.service", *, checks="", running=True):
    return f'''[[resources]]
id="{name}"
kind="service"
identity={{manager="system",unit="{unit}"}}
manage=["running"]
desired={{running={str(running).lower()}}}
checks=[{checks}]
'''


def predicate(resource="daemon", name="running-check", *, running=True):
    return f'''[[checks]]
id="{name}"
kind="service"
resource="{resource}"
expected={{running={str(running).lower()}}}
timeout_seconds=1
'''


def package(name="package", actual="fixture", *, version=False):
    desired = ',version={policy="exact",value="1"},source="repository"' if version else ""
    return f'''[[resources]]
id="{name}"
kind="package"
identity={{name="{actual}"}}
desired={{present=true{desired}}}
'''


def compose(*, engine="local", services='["app"]'):
    return f'''[[resources]]
id="deployment"
kind="compose"
identity={{engine="{engine}",project="example"}}
desired={{running=false,services={services}}}
'''


def declaration(body=""):
    return load_declaration(("schema=1\ncomponents=[]\n" + ("" if "[[resources]]" in body else "resources=[]\n") + body).encode())


class Identities:
    def user(self, uid):
        return "fixture-user"

    def group(self, gid):
        return "fixture-group"


class StatusCollectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.file = self.inputs / "private.env"
        self.file.write_text(PRIVATE)
        self.file.chmod(0o600)
        policy_dir = self.root / "policy"
        policy_dir.mkdir(mode=0o700)
        self.policy_path = policy_dir / "host-policy.toml"
        self.policy_path.write_text(f'schema=1\nhost_id="{HOST}"\n'
                                   f'engine_aliases={{local="{ENGINE}"}}\n'
                                   f'allowed_input_roots={json.dumps([str(self.inputs)])}\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.store_path = self.root / "store"
        self.writer = HostStore.create(self.store_path, HOST, engine_aliases={"local": ENGINE},
                                       owner_uid=os.geteuid())
        self.addCleanup(self.writer.close)
        self.store = HostStore.open_readonly(self.store_path, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.native_calls, self.package_calls, self.account_calls, self.compose_calls = [], [], [], []
        self.endpoint_calls = []
        self.installed, self.explicit = b"fixture 1\n", b"fixture\n"
        self.satisfaction = QueryResult("ok", b"", 0)
        self.native_hook = None
        self.runners = dict(native_runner=self.native, package_runner=self.packages,
                            account_runner=self.accounts, compose_runner=self.docker,
                            endpoint_runner=self.endpoint, identities=Identities())
        self.no_process = patch("subprocess.Popen", side_effect=AssertionError("unexpected production query"))
        process_mock = self.no_process.start()
        self.addCleanup(self.no_process.stop)
        self.addCleanup(process_mock.assert_not_called)

    def native(self, argv):
        self.native_calls.append(argv)
        if self.native_hook:
            self.native_hook()
        if argv == PACKAGE_VERSIONS:
            return QueryResult("ok", self.installed)
        if argv == PACKAGE_EXPLICIT:
            return QueryResult("ok", self.explicit)
        self.assertEqual(argv[:-1], SERVICE_QUERY)
        values = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                  "UnitFileState": "enabled", "Type": "simple", "MainPID": "123",
                  "InvocationID": "1234567890abcdef1234567890abcdef",
                  "ActiveEnterTimestampMonotonic": "100000"}
        return QueryResult("ok", "".join(f"{key}={value}\n" for key, value in values.items()).encode())

    def packages(self, argv):
        self.package_calls.append(argv)
        return self.satisfaction

    def accounts(self, argv, *, timeout):
        self.account_calls.append(argv)
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 2)
        database, key = argv[-2:]
        if database == "passwd":
            raw = f"fixture-user:{PRIVATE}:1001:1002:{PRIVATE}:/home/fixture:/usr/bin/nologin\n"
        else:
            raw = f"fixture-group:{PRIVATE}:1002:private-member\n"
        return QueryResult("ok", raw.encode(), 0)

    def docker(self, argv):
        self.compose_calls.append(argv)
        if argv == ENGINE_QUERY:
            return QueryResult("ok", json.dumps(ENGINE).encode())
        self.assertEqual(argv, LIST_QUERY + (PROJECT_FILTER + "example",))
        return QueryResult("ok", b"")

    def endpoint(self, url, timeout):
        self.endpoint_calls.append((url, timeout))
        return ProbeResult("ok", 200)

    def collect(self, source, **kwargs):
        return collect_status(source, self.store, self.policy, **(self.runners | kwargs)).as_dict()

    def record(self, source, *, adopt=False):
        revision = self.writer.current()["revision"]
        if adopt:
            self.writer.adopt(source, revision, [resource["id"] for resource in source.model["resources"]])
        else:
            self.writer.record_intent(source, revision)

    def files(self):
        return {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
                for path in self.store_path.iterdir()}

    def properties(self, result, resource):
        row = next(row for row in result["report"]["resources"] if row["resource_id"] == resource)
        return {prop["property"]: prop for prop in row["properties"]}

    def test_collects_every_supported_family_without_store_changes_or_private_export(self):
        source = declaration(service() + package(version=True) + compose() + f'''[[resources]]
id="account"
kind="user"
identity={{name="fixture-user"}}
desired={{present=true,home="/home/fixture",shell="/usr/bin/nologin",primary_group="fixture-group"}}
[[resources]]
id="config"
kind="file"
identity={{path={json.dumps(str(self.file))}}}
desired={{present=true,mode=0o600,owner="fixture-user"}}
''')
        self.record(source, adopt=True)
        before = self.files()
        result = self.collect(source)
        self.assertEqual(before, self.files())
        for resource, props in {"daemon": ["running"], "package": ["present", "version"],
                                "account": ["present", "home", "shell", "primary_group"],
                                "config": ["present", "mode", "owner"]}.items():
            for prop in props:
                self.assertEqual(self.properties(result, resource)[prop]["comparison"], "agreement")
        self.assertEqual(len(self.compose_calls), 4)
        self.assertEqual(len(self.package_calls), 2)
        self.assertEqual(len(self.account_calls), 16)
        self.assertEqual(result["collection"]["query_count"], 28)
        raw = json.dumps(result)
        for value in (PRIVATE, str(self.file), "fixture.service", "fixture-user", ENGINE, "private-member"):
            self.assertNotIn(value, raw)
        self.assertEqual(result["collection"]["endpoint_reason"], "status_endpoint_collection_not_requested")
        self.assertFalse(result["report"]["executable"])

    def test_provider_presence_never_supplies_version_reason_or_provenance(self):
        source = declaration(package(version=True))
        self.record(source)
        self.installed = self.explicit = b""
        result = self.collect(source)
        props = self.properties(result, "package")
        self.assertEqual(props["present"]["comparison"], "agreement")
        self.assertEqual(props["present"]["evidence_source"], "pacman_dependency_satisfaction")
        for prop in ("version", "source"):
            self.assertEqual(props[prop]["comparison"], "unknown")
        self.assertEqual(len(self.native_calls), 4)
        self.assertEqual(len(self.package_calls), 2)

    def test_missing_or_failed_package_queries_cannot_prove_absence(self):
        source = declaration(package(version=True))
        self.installed = self.explicit = b""
        self.satisfaction = QueryResult("ok", b"fixture\n", 127)
        result = self.collect(source)
        self.assertTrue(all(row["comparison"] == "unknown" for row in self.properties(result, "package").values()))
        result = self.collect(source, native_runner=lambda argv: QueryResult("permission_denied"))
        self.assertTrue(all(row["comparison"] == "unknown" for row in self.properties(result, "package").values()))

    def test_original_predicate_follows_rename_and_survives_selection_removal_and_relinquishment(self):
        old = declaration(service(checks='"running-check"') + predicate())
        self.record(old, adopt=True)
        renamed = declaration(service("renamed", checks='"running-check"', running=False)
                              + predicate("renamed", running=False))
        result = self.collect(renamed)
        checks = result["report"]["resources"][0]["checks"]
        self.assertEqual([(row["role"], row["result"]) for row in checks],
                         [("accepted", "passed"), ("current", "failed")])
        unselected = self.collect(renamed, selected_components=[])
        self.assertEqual(unselected["report"]["unselected_resources"][0]["checks"][0]["result"], "passed")
        removed = self.collect(declaration())
        self.assertEqual(removed["report"]["retained_resources"][0]["checks"][0]["result"], "passed")
        self.writer.relinquish([self.writer.current()["resources"][0]["stable_id"]], 1)
        relinquished = self.collect(declaration())
        row = relinquished["report"]["retained_resources"][0]
        self.assertEqual(row["management"], "relinquished")
        self.assertEqual(row["checks"][0]["result"], "passed")

    def test_reused_logical_label_cannot_mix_current_and_retained_physical_facts(self):
        self.record(declaration(service(checks='"running-check"') + predicate()), adopt=True)
        changed = declaration(service(unit="different.service", checks='"running-check"') + predicate())
        result = self.collect(changed)
        self.assertEqual(self.native_calls, [])
        self.assertEqual(result["collection"]["targets"][0]["reason"], "status_logical_identity_conflict")
        self.assertEqual(result["report"]["resources"][0]["checks"][0]["result"], "unknown")
        self.assertEqual(result["report"]["retained_resources"][0]["checks"][0]["result"], "unknown")

    def test_compose_scope_change_is_unavailable_and_unknown_alias_is_not_probed(self):
        self.record(declaration(compose()), adopt=True)
        result = self.collect(declaration(compose(services='["different"]')))
        self.assertEqual(self.compose_calls, [])
        self.assertEqual(result["collection"]["targets"][0]["reason"], "status_compose_service_scope_conflict")
        result = self.collect(declaration(compose(engine="unknown")))
        self.assertEqual(self.compose_calls, [])
        self.assertEqual(result["collection"]["targets"][0]["reason"], "status_physical_identity_unbound")

    def test_unsupported_resource_is_explicitly_unavailable(self):
        source = declaration('''[[resources]]
id="volume"
kind="volume"
identity={engine="local",name="data"}
desired={present=true}
''')
        result = self.collect(source)
        self.assertEqual(result["collection"]["targets"][0]["reason"], "status_resource_kind_unsupported")
        self.assertEqual(self.properties(result, "volume")["present"]["comparison"], "unknown")
        self.assertEqual(result["collection"]["query_count"], 0)

    def endpoint_source(self, *, status=200, suffix=""):
        return declaration(service(checks='"route"') + f'''[[checks]]
id="route"
kind="endpoint"
resource="daemon"
url="http://127.0.0.1:12345/{PRIVATE}"
expected_status={status}
timeout_seconds=1
{suffix}''')

    def test_endpoints_require_explicit_request_and_exact_recorded_source(self):
        source = self.endpoint_source()
        self.record(source, adopt=True)
        self.collect(source)
        self.assertEqual(self.endpoint_calls, [])
        mismatch = self.collect(self.endpoint_source(suffix="# changed source"), probe_endpoints=True)
        self.assertEqual(self.endpoint_calls, [])
        self.assertEqual(mismatch["collection"]["endpoint_reason"], "status_target_not_recorded")
        result = self.collect(source, probe_endpoints=True)
        self.assertEqual(len(self.endpoint_calls), 1)
        checks = result["report"]["resources"][0]["checks"]
        self.assertEqual([row["route_result"] for row in checks], ["match", "match"])
        self.assertEqual([row["result"] for row in checks], ["unknown", "unknown"])
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertNotIn("127.0.0.1", json.dumps(result))

    def test_endpoint_accepted_and_current_predicates_and_removed_roles_stay_separate(self):
        self.record(self.endpoint_source(), adopt=True)
        changed = self.endpoint_source(status=204)
        self.record(changed)
        result = self.collect(changed, probe_endpoints=True)
        checks = result["report"]["resources"][0]["checks"]
        self.assertEqual([row["route_result"] for row in checks], ["match", "mismatch"])
        self.assertEqual(len(self.endpoint_calls), 2)
        empty = declaration()
        self.record(empty)
        self.collect(empty)
        self.assertEqual(len(self.endpoint_calls), 2)
        result = self.collect(empty, probe_endpoints=True)
        self.assertEqual(len(self.endpoint_calls), 3)
        self.assertEqual(result["report"]["retained_resources"][0]["checks"][0]["route_result"], "match")

    def test_resource_query_and_output_limits_keep_unknown_coverage(self):
        source = declaration(service("first") + service("second", "other.service"))
        result = self.collect(source, max_resources=1)
        self.assertEqual(len(result["collection"]["targets"]), 2)
        self.assertEqual(result["collection"]["targets"][1]["reason"], "status_resource_limit")
        self.assertEqual(self.properties(result, "second")["running"]["comparison"], "unknown")
        self.native_calls.clear()
        result = self.collect(source, max_queries=1)
        self.assertEqual(len(self.native_calls), 1)
        self.assertIn("status_query_limit", result["collection"]["query_limits"])
        self.assertTrue(all(self.properties(result, name)["running"]["comparison"] == "unknown"
                            for name in ("first", "second")))
        self.native_calls.clear()
        result = self.collect(source, max_query_bytes=1)
        self.assertEqual(self.native_calls, [])
        self.assertEqual(result["collection"]["query_output_bytes_reserved"], 0)
        self.assertIn("status_query_byte_limit", result["collection"]["query_limits"])

    def test_late_query_and_unscheduled_targets_stay_unknown(self):
        clock = [0.0]
        self.native_hook = lambda: clock.__setitem__(0, 61.0)
        with patch.object(status_collection.time, "monotonic", side_effect=lambda: clock[0]):
            result = self.collect(declaration(service("first") + service("second", "other.service")))
        self.assertEqual(len(self.native_calls), 1)
        self.assertEqual(self.properties(result, "first")["running"]["comparison"], "unknown")
        self.assertEqual(result["collection"]["targets"][1]["reason"], "status_collection_budget_exhausted")

    def test_invalid_query_result_raw_errors_and_oversized_output_remain_private(self):
        source = declaration(service())
        for runner in (lambda argv: PRIVATE,
                       lambda argv: QueryResult("ok", (PRIVATE * 2000).encode())):
            result = self.collect(source, native_runner=runner)
            self.assertEqual(self.properties(result, "daemon")["running"]["comparison"], "unknown")
            self.assertNotIn(PRIVATE, json.dumps(result))
        def fail(argv):
            raise RuntimeError(PRIVATE)
        self.assertNotIn(PRIVATE, json.dumps(self.collect(source, native_runner=fail)))

    def test_revision_race_returns_no_mixed_report(self):
        source = declaration(service())
        self.record(source)
        def change():
            self.native_hook = None
            self.record(declaration())
        self.native_hook = change
        with self.assertRaisesRegex(StatusCollectionError, "status_context_changed"):
            self.collect(source)

    def test_policy_race_returns_no_mixed_report(self):
        source = declaration(service())
        self.native_hook = lambda: self.policy_path.chmod(0o644)
        with self.assertRaisesRegex(StatusCollectionError, "status_policy_unavailable"):
            self.collect(source)

    def test_empty_scope_still_rechecks_policy_and_snapshot(self):
        source = declaration()
        self.record(source)
        original = HostStore.snapshot
        count = [0]
        def snapshot(store, identity):
            count[0] += 1
            if count[0] == 2:
                raise status_collection.StoreError("private_unavailable")
            return original(store, identity)
        with patch.object(HostStore, "snapshot", snapshot):
            with self.assertRaisesRegex(StatusCollectionError, "status_store_unavailable"):
                self.collect(source)
        self.assertEqual(count[0], 2)
        with patch.object(status_collection, "_targets", side_effect=lambda *args: (self.policy.close() or [])):
            with self.assertRaisesRegex(StatusCollectionError, "status_policy_unavailable"):
                self.collect(source)

    def test_live_readonly_handles_and_exact_validated_declaration_are_required(self):
        source = declaration()
        for store, policy in ((self.writer, self.policy), ({}, self.policy), (self.store, {})):
            with self.assertRaisesRegex(StatusCollectionError, "invalid_status_collection_request"):
                collect_status(source, store, policy)
        with self.assertRaisesRegex(StatusCollectionError, "invalid_status_declaration_or_selection"):
            self.collect(replace(source, sha256="0" * 64))
        with self.assertRaisesRegex(StatusCollectionError, "invalid_status_declaration_or_selection"):
            self.collect(source, selected_components=["missing"])
        self.assertEqual(self.native_calls, [])

    def test_protected_freshness_is_separate_from_matching_properties_and_store_is_unchanged(self):
        recorder = ProtectedRecorder(self.writer, self.policy)
        prepared = recorder.prepare(expected_revision=0, input_id="private-inputs",
                                    base_directory=str(self.inputs), path=self.file.name)
        source = declaration(service() + f'''input={{bundle="private-inputs"}}
[[inputs]]
id="private-inputs"
base_directory={json.dumps(str(self.inputs))}
files=[{{path="private.env",classification="protected",reference="{prepared.reference}"}}]
''')
        recorder.record_intent(source, 0, prepared_inputs=[prepared])
        before = self.files()
        result = self.collect(source)
        self.assertEqual(result["report"]["protected_inputs"]["entries"][0]["state"], "same")
        self.file.write_text(PRIVATE + " changed")
        result = self.collect(source)
        self.assertEqual(result["report"]["protected_inputs"]["entries"][0]["state"], "changed")
        self.assertEqual(self.properties(result, "daemon")["running"]["comparison"], "agreement")
        self.assertEqual(before, self.files())
        self.assertNotIn(prepared.reference, json.dumps(result))
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertNotIn(hashlib.sha256(PRIVATE.encode()).hexdigest(), json.dumps(result))

    def test_result_is_immutable_and_public_copy_cannot_mutate_it(self):
        result = collect_status(declaration(), self.store, self.policy, **self.runners)
        original = result.canonical_bytes
        copy = result.as_dict()
        copy["collection"]["targets"].append({"private": PRIVATE})
        self.assertEqual(result.canonical_bytes, original)
        self.assertEqual(result.sha256, hashlib.sha256(original).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            result.canonical_bytes = b"changed"
        self.assertNotIn(PRIVATE, repr(result))

    def test_package_reason_check_needs_independent_direct_presence(self):
        source = declaration(package(version=True) + '''checks=["inventory-check"]
[[checks]]
id="inventory-check"
kind="package"
resource="package"
expected={version="1",reason="explicit"}
timeout_seconds=1
''')
        result = self.collect(source)
        self.assertEqual(result["report"]["resources"][0]["checks"][0]["result"], "passed")
        self.installed = self.explicit = b""
        result = self.collect(source)
        self.assertEqual(self.properties(result, "package")["present"]["comparison"], "agreement")
        self.assertEqual(result["report"]["resources"][0]["checks"][0]["result"], "unknown")

    def test_direct_inventory_keeps_version_when_satisfaction_is_unavailable(self):
        self.satisfaction = QueryResult("permission_denied")
        result = self.collect(declaration(package(version=True)))
        properties = self.properties(result, "package")
        for name in ("present", "version"):
            self.assertEqual(properties[name]["comparison"], "agreement")
            self.assertEqual(properties[name]["evidence_source"], "pacman_installed_inventory")
        self.assertEqual(properties["source"]["comparison"], "unknown")

    def test_per_query_deadline_rejects_late_trusted_runner_before_global_expiry(self):
        clock = [0.0]
        self.native_hook = lambda: clock.__setitem__(0, clock[0] + 11)
        with patch.object(status_collection.time, "monotonic", side_effect=lambda: clock[0]):
            result = self.collect(declaration(service()))
        self.assertLess(clock[0], 60)
        self.assertIn("status_query_timeout", result["collection"]["query_limits"])
        self.assertEqual(self.properties(result, "daemon")["running"]["comparison"], "unknown")

    def test_default_runners_receive_remaining_deadline_and_output_bounds(self):
        source = declaration(service() + compose())
        clock = [0.0]
        native_times, docker_times = [], []
        def native(argv, *, timeout, max_output):
            native_times.append(timeout)
            self.assertEqual(max_output, 16 * 1024)
            clock[0] += 1
            return self.native(argv)
        def docker(argv, *, timeout, max_output):
            docker_times.append(timeout)
            self.assertEqual(max_output, 256 * 1024)
            clock[0] += 0.1
            return self.docker(argv)
        with patch.object(status_collection.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(status_collection.observe_native, "run_readonly", side_effect=native), \
                patch.object(status_collection.observe_compose, "run_readonly", side_effect=docker):
            result = self.collect(source, budget_seconds=5, native_runner=None, compose_runner=None)
        self.assertEqual(native_times, [5, 4])
        self.assertTrue(all(0 < value <= 3 for value in docker_times))
        self.assertEqual(result["collection"]["query_count"], 6)

    def test_file_metadata_expiry_discards_that_result_and_stops_further_reads(self):
        source = declaration(f'''[[resources]]
id="file"
kind="file"
identity={{path={json.dumps(str(self.file))}}}
desired={{present=true}}
''' + service())
        clock = [0.0]
        original = status_collection.observe_files.observe_files
        def files(*args, **kwargs):
            result = original(*args, **kwargs)
            clock[0] = 61
            return result
        with patch.object(status_collection.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(status_collection.observe_files, "observe_files", side_effect=files):
            result = self.collect(source)
        self.assertEqual(self.native_calls, [])
        self.assertEqual(self.properties(result, "file")["present"]["comparison"], "unknown")
        self.assertTrue(all(row["reason"] == "status_collection_budget_exhausted"
                            for row in result["collection"]["targets"]))

    def test_kind_change_at_retained_path_is_unavailable_without_metadata_query(self):
        source = f'''[[resources]]
id="path"
kind="file"
identity={{path={json.dumps(str(self.file))}}}
desired={{present=true}}
'''
        self.record(declaration(source), adopt=True)
        with patch.object(status_collection.observe_files, "observe_files") as observer:
            result = self.collect(declaration(source.replace('kind="file"', 'kind="directory"')))
        observer.assert_not_called()
        self.assertEqual(result["collection"]["targets"][0]["reason"], "status_resource_kind_conflict")
        self.assertEqual(self.properties(result, "path")["present"]["comparison"], "unknown")

    def test_context_mismatch_and_scope_overflow_fail_before_queries(self):
        with patch.object(HostStore, "engine_aliases", new_callable=PropertyMock,
                          return_value={}):
            with self.assertRaisesRegex(StatusCollectionError, "status_policy_store_mismatch"):
                self.collect(declaration(service()))
        with patch.object(status_collection, "MAX_TARGETS", 0):
            with self.assertRaisesRegex(StatusCollectionError, "status_scope_limit"):
                self.collect(declaration(service()))
        with patch.object(status_collection, "MAX_SCOPE_BYTES", 1):
            with self.assertRaisesRegex(StatusCollectionError, "status_scope_limit"):
                self.collect(declaration(service()))
        self.assertEqual(self.native_calls, [])

    def test_no_endpoint_request_fits_expired_remaining_budget(self):
        source = self.endpoint_source()
        self.record(source)
        result = self.collect(source, probe_endpoints=True, budget_seconds=1)
        self.assertEqual(self.endpoint_calls, [])
        self.assertEqual(result["collection"]["endpoint_reason"], "status_collection_budget_exhausted")

    def test_cancellation_propagates(self):
        def cancel(argv):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.collect(declaration(service()), native_runner=cancel)


if __name__ == "__main__":
    unittest.main()
