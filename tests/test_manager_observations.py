"""Read-only host facts, using fake queries and private bounded child processes."""
from dataclasses import FrozenInstanceError
from datetime import datetime
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.observations import Observation, ObservationBatch
from mpkg_manager.planning import build_report
from mpkg_manager.observe_native import (
    ENVIRONMENT, PACKAGE_EXPLICIT, PACKAGE_VERSIONS, SERVICE_QUERY,
    QueryResult, observe_resources, run_readonly,
)


HOST = "98d1f834-494b-4a5e-bad0-ab8fb03fecb2"
WHEN = "2026-11-01T23:00:00Z"
SECRET = "fixture-private-token-never-export"


def package(name="git", **desired):
    return {"id": name, "kind": "package", "identity": {"name": name}, "desired": desired}


def service():
    return {"id": "ssh", "kind": "service",
            "identity": {"manager": "system", "unit": "sshd.service"}}


def service_bytes(**changes):
    fields = dict(LoadState="loaded", ActiveState="active", SubState="running",
                  UnitFileState="enabled", Type="simple", MainPID="142",
                  InvocationID="1234567890abcdef1234567890abcdef",
                  ActiveEnterTimestampMonotonic="100000")
    fields.update(changes)
    return "".join(f"{key}={value}\n" for key, value in fields.items()).encode()


class Queries:
    def __init__(self, versions=b"git 2.51.0-1\npython 3.12.16-1\n", explicit=b"git\n",
                 services=None, results=None):
        self.versions, self.explicit = versions, explicit
        self.services = services or [service_bytes(), service_bytes()]
        self.results = iter(results) if results is not None else None
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if self.results is not None:
            return next(self.results)
        if argv == PACKAGE_VERSIONS:
            return QueryResult("ok", self.versions, 0)
        if argv == PACKAGE_EXPLICIT:
            return QueryResult("ok", self.explicit, 0)
        if argv == SERVICE_QUERY + ("sshd.service",):
            return QueryResult("ok", self.services.pop(0), 0)
        raise AssertionError("Unexpected query")


def facts(batch, resource_id):
    return {fact.property: fact for fact in batch.for_resource(resource_id)}


class ObservationTests(unittest.TestCase):
    def observe(self, resources, runner):
        return observe_resources(resources, host_id=HOST, runner=runner, observed_at=WHEN)

    def test_records_are_immutable_and_projection_does_not_mutate_them(self):
        identity = {"name": "git"}
        fact = Observation(HOST, "git", "package", identity, "present", "known", True,
                           WHEN, "fixture")
        identity["name"] = "changed"
        self.assertEqual(fact.identity["name"], "git")
        with self.assertRaises(TypeError):
            fact.identity["name"] = "changed"
        with self.assertRaises(FrozenInstanceError):
            fact.value = False
        batch = ObservationBatch(HOST, WHEN, [fact], ["git"])
        projected = batch.as_dict()
        projected["facts"][0]["identity"]["name"] = "changed"
        self.assertEqual(batch.facts[0].identity["name"], "git")
        json.dumps(batch.as_dict())
        for coverage in ([{"mutable": True}], ["git", "git"], []):
            with self.subTest(coverage=coverage), self.assertRaises(ValueError):
                ObservationBatch(HOST, WHEN, [fact], coverage)
        with self.assertRaises(ValueError):
            ObservationBatch(HOST, WHEN, [fact, fact], ["git"])

    def test_unknown_values_and_invalid_context_are_rejected(self):
        for kwargs in [dict(state="unknown", value=True, limitations=("missing",)),
                       dict(state="unknown", value=None),
                       dict(state="unexpected", value=None),
                       dict(state="known", value={"mutable": True})]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Observation(HOST, "git", "package", {"name": "git"}, "present",
                            observed_at=WHEN, evidence_source="fixture", **kwargs)
        for host, when in [("invalid", WHEN), (HOST, "2026-11-01"),
                           (HOST, "2026-11-01T23:00:00+01:00")]:
            runner = Queries()
            with self.assertRaises(ValueError):
                observe_resources([], host_id=host, observed_at=when, runner=runner)
            self.assertEqual(runner.calls, [])

    def test_direct_presence_version_and_reason_do_not_infer_request_resolution(self):
        runner = Queries()
        batch = self.observe([package("git", version={"policy": "any"}),
                              package("python"), package("virtual")], runner)
        self.assertEqual(runner.calls, [PACKAGE_VERSIONS, PACKAGE_EXPLICIT] * 2)
        git = facts(batch, "git")
        self.assertIs(git["present"].value, True)
        self.assertEqual(git["version"].value, "2.51.0-1")
        self.assertEqual(git["install_reason"].value, "explicit")
        self.assertEqual(facts(batch, "python")["install_reason"].value, "dependency")
        self.assertIs(facts(batch, "virtual")["present"].value, False)
        self.assertEqual(facts(batch, "virtual")["version"].state, "absent")
        self.assertEqual(git["source"].state, "unknown")
        self.assertEqual(git["provider"].state, "unknown")
        self.assertIn("direct_installed_names_not_package_request_satisfaction", batch.limitations)
        self.assertEqual(batch.coverage, ("git", "python", "virtual"))

    def test_package_version_and_reason_races_are_unknown(self):
        for version, explicit in [(b"git 3-1\n", b"git\n"), (b"git 2-1\n", b"")]:
            with self.subTest(version=version, explicit=explicit):
                sequence = [b"git 2-1\n", b"git\n", version, explicit]
                batch = self.observe([package()], Queries(results=[QueryResult("ok", raw) for raw in sequence]))
                self.assertTrue(all(f.state == "unknown" for f in batch.facts))
                self.assertEqual(batch.facts[0].limitations, ("package_inventory_changed",))

    def test_malformed_package_evidence_is_not_exported(self):
        cases = [(b"git 2-1\ngit 3-1\n", b"git\n"),
                 (b"git 2-1\n", b"git\ngit\n"),
                 (b"git 2-1\n", b"not-installed\n"),
                 ((SECRET + " invalid value\n").encode(), b""),
                 (b"git \xff\n", b"")]
        for versions, explicit in cases:
            with self.subTest(versions=versions):
                batch = self.observe([package()], Queries(versions, explicit))
                self.assertTrue(all(f.state == "unknown" for f in batch.facts))
                self.assertNotIn(SECRET, json.dumps(batch.as_dict()))

    def test_query_failure_does_not_claim_package_absence(self):
        for code in ("tool_unavailable", "permission_denied", "command_failed", "timeout", "output_limit"):
            with self.subTest(code=code):
                runner = Queries(results=[QueryResult(code), QueryResult("ok", b"")])
                batch = self.observe([package()], runner)
                self.assertEqual(facts(batch, "git")["present"].state, "unknown")
                self.assertEqual(batch.facts[0].limitations, (code,))

    def test_known_service_state_is_not_health_and_does_not_invoke_other_tools(self):
        runner = Queries()
        batch = self.observe([service()], runner)
        found = facts(batch, "ssh")
        self.assertEqual(runner.calls, [SERVICE_QUERY + ("sshd.service",)] * 2)
        self.assertIs(found["running"].value, True)
        self.assertIs(found["enabled"].value, True)
        self.assertEqual(found["main_pid"].value, 142)
        self.assertEqual(found["service_type"].value, "simple")
        self.assertIn("service_state_not_functional_health", batch.limitations)

    def test_service_facts_keep_prequery_identity_label_and_kind(self):
        mutations = {
            "nested_identity": lambda item: item["identity"].update(unit="unobserved.service"),
            "identity_replacement": lambda item: item.update(
                identity={"manager": "system", "unit": "unobserved.service"}),
            "label": lambda item: item.update(id="unobserved"),
            "kind": lambda item: item.update(kind="package"),
            "removed_fields": lambda item: item.clear(),
        }
        expected = self.observe([service()], Queries()).as_dict()
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                resource, queries = service(), Queries()

                def runner(argv):
                    if not queries.calls:
                        mutate(resource)
                    return queries(argv)

                self.assertEqual(self.observe([resource], runner).as_dict(), expected)
                self.assertEqual(queries.calls, [SERVICE_QUERY + ("sshd.service",)] * 2)

    def test_changed_service_identity_cannot_claim_agreement_for_unqueried_unit(self):
        def declaration(unit):
            return load_declaration(f'''schema = 1
components = []
[[resources]]
id = "ssh"
kind = "service"
identity = {{manager = "system", unit = "{unit}"}}
manage = ["running"]
desired = {{running = true}}
'''.encode())

        observed, unobserved = declaration("sshd.service"), declaration("unobserved.service")
        resources, queries = observed.model["resources"], Queries()

        def runner(argv):
            resources[0]["identity"]["unit"] = "unobserved.service"
            return queries(argv)

        batch = self.observe(resources, runner)
        self.assertEqual(queries.calls, [SERVICE_QUERY + ("sshd.service",)] * 2)
        for intent, comparison in ((observed, "agreement"), (unobserved, "unknown")):
            report = build_report(intent, None, batch.as_dict(), host_id=HOST,
                                  now=datetime.fromisoformat(WHEN)).as_dict()
            running = report["resources"][0]["properties"][0]
            self.assertEqual(running["property"], "running")
            self.assertEqual(running["comparison"], comparison)
            if comparison == "unknown":
                self.assertEqual(running["limitations"], ["observation_identity_mismatch"])

    def test_package_queries_cannot_change_later_resources_or_batch_coverage(self):
        resources = [package(), service(),
                     {"id": "data", "kind": "directory", "identity": {"path": "/srv/data"},
                      "desired": {"mode": 0o750}}]
        expected = self.observe(resources, Queries()).as_dict()
        queries = Queries()

        def runner(argv):
            if not queries.calls:
                resources[0]["identity"]["name"] = "python"
                resources[0]["id"] = "changed-package"
                resources[0]["kind"] = "directory"
                resources[1]["identity"]["unit"] = "unobserved.service"
                resources[1]["id"] = "changed-service"
                resources[1]["kind"] = "package"
                resources[2]["identity"]["path"] = "/unobserved"
                resources[2]["id"] = "changed-directory"
                resources[2]["kind"] = "service"
                resources[2]["desired"].clear()
                resources[2]["desired"][SECRET] = True
                resources.append(package("late"))
                resources.reverse()
            return queries(argv)

        self.assertEqual(self.observe(resources, runner).as_dict(), expected)
        self.assertEqual(queries.calls, [PACKAGE_VERSIONS, PACKAGE_EXPLICIT] * 2
                         + [SERVICE_QUERY + ("sshd.service",)] * 2)

    def test_unknown_facts_keep_original_targets_after_query_failure(self):
        resources = [package(), service()]
        queries = Queries(results=[QueryResult("permission_denied"),
                                   QueryResult("ok", b""), QueryResult("timeout")])

        def runner(argv):
            if not queries.calls:
                resources[0]["identity"]["name"] = "unobserved"
                resources[1]["identity"]["unit"] = "unobserved.service"
            return queries(argv)

        batch = self.observe(resources, runner)
        self.assertTrue(all(fact.state == "unknown" for fact in batch.facts))
        self.assertEqual(facts(batch, "git")["present"].identity, {"name": "git"})
        self.assertEqual(facts(batch, "ssh")["running"].identity, service()["identity"])
        self.assertEqual(queries.calls, [PACKAGE_VERSIONS, PACKAGE_EXPLICIT,
                                         SERVICE_QUERY + ("sshd.service",)])

    def test_stopped_service_and_unsupported_state_semantics(self):
        cases = [({"ActiveState": "inactive", "SubState": "dead", "MainPID": "0",
                   "UnitFileState": "disabled"}, False, False),
                 ({"Type": "oneshot", "SubState": "exited", "MainPID": "0"}, None, True),
                 ({"ActiveState": "activating", "SubState": "start"}, None, True),
                 ({"UnitFileState": "enabled-runtime"}, True, None),
                 ({"UnitFileState": "static"}, True, None),
                 ({"UnitFileState": "masked"}, True, None)]
        for changes, running, enabled in cases:
            with self.subTest(changes=changes):
                raw = service_bytes(**changes)
                found = facts(self.observe([service()], Queries(services=[raw, raw])), "ssh")
                for prop, expected in (("running", running), ("enabled", enabled)):
                    self.assertEqual(found[prop].value, expected)
                    self.assertEqual(found[prop].state, "unknown" if expected is None else "known")

    def test_absent_service_is_reported_only_with_successful_positive_evidence(self):
        raw = service_bytes(LoadState="not-found", ActiveState="inactive", SubState="dead",
                            MainPID="0", UnitFileState="", Type="", InvocationID="",
                            ActiveEnterTimestampMonotonic="0")
        found = facts(self.observe([service()], Queries(services=[raw, raw])), "ssh")
        self.assertIs(found["present"].value, False)
        failed = self.observe([service()], Queries(results=[QueryResult("command_failed")]))
        self.assertEqual(facts(failed, "ssh")["present"].state, "unknown")

    def test_changed_missing_malformed_and_unknown_service_fields_are_unknown(self):
        valid = service_bytes()
        variants = [valid.replace(b"MainPID=142\n", b""), valid + b"MainPID=142\n",
                    valid.replace(b"Type=simple", b"Type=unsupported"),
                    valid.replace(b"MainPID=142", ("MainPID=" + SECRET).encode()),
                    valid + ("Secret=" + SECRET + "\n").encode()]
        for raw in variants:
            with self.subTest(raw=raw):
                batch = self.observe([service()], Queries(services=[raw, raw]))
                self.assertTrue(all(f.state == "unknown" for f in batch.facts))
                self.assertNotIn(SECRET, json.dumps(batch.as_dict()))
        batch = self.observe([service()], Queries(services=[valid, service_bytes(MainPID="143")]))
        self.assertTrue(all(f.state == "unknown" for f in batch.facts))
        self.assertEqual(batch.facts[0].limitations, ("service_state_changed",))

    def test_unsupported_resources_remain_unknown_without_commands(self):
        runner = Queries()
        resource = {"id": "data", "kind": "directory", "identity": {"path": "/srv/data"},
                    "desired": {"mode": 0o750}}
        batch = self.observe([resource], runner)
        self.assertEqual(runner.calls, [])
        self.assertEqual({f.property for f in batch.facts}, {"present", "mode"})
        self.assertTrue(all(f.state == "unknown" for f in batch.facts))

    def test_all_valid_unsupported_kinds_preserve_declared_property_coverage(self):
        cases = [
            ("compose", '{engine="local", project="app"}', '{running=true, services=["web"]}'),
            ("volume", '{engine="local", name="data"}', '{present=true}'),
            ("network", '{engine="local", name="app"}', '{present=true}'),
            ("user", '{name="app"}', '{groups=["media"]}'),
            ("group", '{name="media"}', '{members=["app"]}'),
            ("file", '{path="/srv/config"}', '{content="private contents"}'),
            ("directory", '{path="/srv/data"}', '{mode=488}'),
            ("symlink", '{path="/srv/current"}', '{target="data"}'),
            ("sonarr_xml", '{path="/srv/config.xml"}', '{port=8989}'),
        ]
        for kind, identity, desired in cases:
            with self.subTest(kind=kind):
                declaration = load_declaration(f'''schema = 1
components = []
[[resources]]
id = "resource"
kind = "{kind}"
identity = {identity}
desired = {desired}
'''.encode())
                resource = declaration.model["resources"][0]
                queries = Queries()
                batch = self.observe([resource], queries)
                self.assertEqual(queries.calls, [])
                self.assertEqual({fact.property for fact in batch.facts},
                                 {"present", *resource["desired"]})
                self.assertTrue(all(fact.state == "unknown" and fact.kind == kind
                                    and fact.identity == resource["identity"]
                                    and fact.evidence_source == "unsupported_adapter"
                                    and fact.limitations == ("resource_kind_not_observed",)
                                    for fact in batch.facts))

    def test_contextual_desired_values_are_not_needed_or_exported(self):
        declaration = load_declaration(b'''schema = 1
components = []
[[inputs]]
id = "configuration"
base_directory = "/srv"
files = [{path="config", classification="nonsecret"}]
[[resources]]
id = "config"
kind = "file"
identity = {path="/srv/config"}
desired = {content_input="configuration"}
''')
        queries = Queries()
        batch = self.observe(declaration.model["resources"], queries)
        self.assertEqual(queries.calls, [])
        self.assertEqual({fact.property for fact in batch.facts}, {"present", "content_input"})
        self.assertTrue(all(fact.state == "unknown" for fact in batch.facts))
        self.assertNotIn("configuration", json.dumps(batch.as_dict()))

    def test_normalized_unsupported_unit_types_remain_unknown_without_commands(self):
        for unit in ("example.socket", "example.timer", "example"):
            with self.subTest(unit=unit):
                declaration = load_declaration(f'''schema = 1
components = []
[[resources]]
id = "example"
kind = "service"
identity = {{manager = "system", unit = "{unit}"}}
manage = ["running", "enabled"]
desired = {{running = true, enabled = true}}
'''.encode())
                runner = Queries()
                batch = self.observe(declaration.model["resources"], runner)
                self.assertEqual(runner.calls, [])
                self.assertEqual(batch.coverage, ("example",))
                self.assertTrue({"present", "running", "enabled"} <=
                                {fact.property for fact in batch.facts})
                self.assertTrue(all(fact.state == "unknown" for fact in batch.facts))
                self.assertTrue(all(fact.limitations == ("service_unit_type_unsupported",)
                                    for fact in batch.facts))

    def test_bad_identity_and_duplicate_resource_never_execute(self):
        for resources in [[package(), package()], [package("--root")],
                          [service() | {"identity": {"manager": "user", "unit": "sshd.service"}}]]:
            runner = Queries()
            with self.subTest(resources=resources), self.assertRaises(ValueError):
                self.observe(resources, runner)
            self.assertEqual(runner.calls, [])

    def test_invalid_targets_and_used_property_keys_fail_before_any_query(self):
        directory = {"id": "data", "kind": "directory", "identity": {"path": "/srv/data"}}
        invalid = [None, [], {}, service() | {"id": ""}, service() | {"id": SECRET + "\n"},
                   service() | {"kind": SECRET}, service() | {"kind": ["service"]},
                   directory | {"identity": {"path": 42}},
                   directory | {"identity": {"path": "/srv/data", SECRET: "private"}},
                   directory | {"desired": ["mode"]}, directory | {"desired": None}]
        invalid.extend(directory | {"desired": {key: SECRET}}
                       for key in (1, ("mode",), "", "x" * 129, SECRET + "\n"))
        for resource in invalid:
            with self.subTest(resource=resource):
                runner = Queries()
                with self.assertRaises(ValueError) as raised:
                    self.observe([package(), resource], runner)
                self.assertEqual(str(raised.exception), "invalid_observation_resource")
                self.assertEqual(runner.calls, [])


class BoundedQueryTests(unittest.TestCase):
    def child(self, code, **bounds):
        real_popen = subprocess.Popen
        seen = []

        def launch(argv, **kwargs):
            seen.append((argv, kwargs))
            return real_popen([sys.executable, "-c", code], **kwargs)

        with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch):
            result = run_readonly(PACKAGE_VERSIONS, **bounds)
        self.assertEqual(seen[0][0], PACKAGE_VERSIONS)
        self.assertEqual(seen[0][1]["env"], ENVIRONMENT)
        self.assertEqual(seen[0][1]["stdin"], subprocess.DEVNULL)
        self.assertTrue(seen[0][1]["start_new_session"])
        self.assertNotIn("shell", seen[0][1])
        return result

    def test_query_allowlist_refuses_mutations_and_injected_programs(self):
        cases = [("/usr/bin/pacman", "-S", "git"), ("/usr/bin/pacman", "-Sy"),
                 ("/usr/bin/systemctl", "restart", "sshd.service"),
                 ("/usr/bin/sudo", "pacman", "-Q"), ("pacman", "-Q"),
                 SERVICE_QUERY + ("--user",), SERVICE_QUERY + ("bad\n.service",),
                 SERVICE_QUERY + ("example.socket",)]
        with patch("mpkg_manager.query_process.subprocess.Popen") as spawn:
            for argv in cases:
                self.assertEqual(run_readonly(argv).code, "invalid_query")
            spawn.assert_not_called()

    def test_success_uses_minimal_environment_and_hides_private_output_in_repr(self):
        with patch.dict(os.environ, {"MANAGER_SECRET": SECRET, "LD_PRELOAD": SECRET,
                                     "DBUS_SYSTEM_BUS_ADDRESS": SECRET}):
            result = self.child("import os; print(','.join(sorted(os.environ)))")
        self.assertEqual(result.code, "ok")
        self.assertNotIn(SECRET.encode(), result.output)
        self.assertNotIn(b"MANAGER_SECRET", result.output)
        self.assertNotIn(b"DBUS_SYSTEM_BUS_ADDRESS", result.output)
        self.assertNotIn("PATH", repr(result))

    def test_nonzero_and_spawn_errors_never_expose_child_errors(self):
        result = self.child(f"import sys; print({SECRET!r}); print({SECRET!r}, file=sys.stderr); sys.exit(7)")
        self.assertEqual(result.code, "command_failed")
        self.assertEqual(result.output, b"")
        self.assertEqual(result.returncode, 7)
        self.assertNotIn(SECRET, repr(result))
        for error, code in [(FileNotFoundError(SECRET), "tool_unavailable"),
                            (PermissionError(SECRET), "permission_denied"),
                            (OSError(SECRET), "start_failed")]:
            with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=error):
                result = run_readonly(PACKAGE_VERSIONS)
            self.assertEqual(result.code, code)
            self.assertNotIn(SECRET, repr(result))

    def test_output_bound_counts_both_streams_and_discards_partial_output(self):
        for descriptor in (1, 2):
            with self.subTest(descriptor=descriptor):
                result = self.child(f"import os; os.write({descriptor}, b'x' * 50000)", max_output=1024)
                self.assertEqual(result.code, "output_limit")
                self.assertEqual(result.output, b"")
        result = self.child("import os; os.write(1,b'x'*700); os.write(2,b'y'*700)", max_output=1024)
        self.assertEqual(result.code, "output_limit")

    def test_nonzero_exit_stops_descendant_after_output_pipes_close(self):
        real_popen = subprocess.Popen
        processes = []
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-appear"
            code = f"""
import os, time
ready_read, ready_write = os.pipe()
child = os.fork()
if child:
    os.close(ready_write)
    assert os.read(ready_read, 1) == b'x'
    os._exit(7)
os.close(ready_read)
os.close(1)
os.close(2)
os.write(ready_write, b'x')
os.close(ready_write)
time.sleep(1)
open({str(marker)!r}, 'w').write('effect')
os._exit(0)
"""

            def launch(argv, **kwargs):
                process = real_popen([sys.executable, "-c", code], **kwargs)
                processes.append(process)
                return process

            try:
                started = time.monotonic()
                with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch):
                    result = run_readonly(PACKAGE_VERSIONS, timeout=2)
                self.assertEqual(result.code, "command_failed")
                self.assertEqual(result.returncode, 7)
                self.assertEqual(result.output, b"")
                self.assertLess(time.monotonic() - started, 1)
                self.assertTrue(processes[0].stdout.closed)
                self.assertTrue(processes[0].stderr.closed)
                time.sleep(1.05)
                self.assertFalse(marker.exists())
            finally:
                # Also contain the fixture when this regression fails against
                # an implementation which leaves the child alive.
                for process in processes:
                    try:
                        os.killpg(process.pid, 9)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1)

    def test_deadline_kills_inherited_pipe_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-appear"
            code = ("import os,time; child=os.fork(); "
                    f"time.sleep(1) if child==0 else None; "
                    f"open({str(marker)!r},'w').write('effect') if child==0 else None; "
                    "os._exit(0)")
            started = time.monotonic()
            result = self.child(code, timeout=0.15)
            self.assertEqual(result.code, "timeout")
            self.assertLess(time.monotonic() - started, 1)
            time.sleep(1.05)
            self.assertFalse(marker.exists())

    def test_completion_at_or_after_deadline_discards_output(self):
        real_popen, real_clock, real_killpg = subprocess.Popen, time.monotonic, os.killpg
        cases = [(0.5, 0, "ok"), (0.5, 7, "command_failed"),
                 (1.0, 0, "timeout"), (1.25, 0, "timeout"), (1.25, 7, "timeout")]
        for completed_after, exit_code, expected in cases:
            with self.subTest(completed_after=completed_after, exit_code=exit_code):
                started, completed, processes = [None], [False], []

                def clock():
                    current = real_clock()
                    if started[0] is None:
                        started[0] = current
                    return started[0] + completed_after if completed[0] else current

                def launch(argv, **kwargs):
                    code = f"import sys; print({SECRET!r}); sys.exit({exit_code})"
                    process = real_popen([sys.executable, "-c", code], **kwargs)
                    processes.append(process)
                    real_wait = process.wait

                    def wait(*args, **wait_kwargs):
                        result = real_wait(*args, **wait_kwargs)
                        completed[0] = True
                        return result

                    process.wait = wait
                    return process

                with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch), \
                        patch("mpkg_manager.query_process.time.monotonic", side_effect=clock), \
                        patch("mpkg_manager.query_process.os.killpg", wraps=real_killpg) as kill:
                    result = run_readonly(PACKAGE_VERSIONS, timeout=1)
                self.assertEqual(result.code, expected)
                self.assertEqual(result.returncode, exit_code)
                self.assertEqual(result.output, (SECRET + "\n").encode() if expected == "ok" else b"")
                self.assertNotIn(SECRET, repr(result))
                self.assertTrue(processes[0].stdout.closed)
                self.assertTrue(processes[0].stderr.closed)
                if expected == "ok":
                    kill.assert_not_called()
                else:
                    kill.assert_called_once_with(processes[0].pid, 9)

    def test_late_reaped_leader_stops_closed_pipe_descendant(self):
        real_popen, real_clock = subprocess.Popen, time.monotonic
        started, completed, processes = [None], [False], []
        release_read, release_write = os.pipe()
        done_read, done_write = os.pipe()
        owned = {release_read, release_write, done_read, done_write}

        def close(fd):
            os.close(fd)
            owned.remove(fd)

        def clock():
            current = real_clock()
            if started[0] is None:
                started[0] = current
            return started[0] + 1.25 if completed[0] else current

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-appear"
            code = f"""
import os
ready_read, ready_write = os.pipe()
child = os.fork()
if child:
    os.close(ready_write)
    os.close({release_read})
    os.close({done_write})
    assert os.read(ready_read, 1) == b'x'
    os.write(1, b'private-late-output')
    os._exit(0)
os.close(ready_read)
os.close(1)
os.close(2)
os.write(ready_write, b'x')
os.close(ready_write)
if os.read({release_read}, 1) == b'x':
    open({str(marker)!r}, 'w').write('effect')
    os.write({done_write}, b'x')
os._exit(0)
"""

            def launch(argv, **kwargs):
                process = real_popen([sys.executable, "-c", code],
                                    pass_fds=(release_read, done_write), **kwargs)
                processes.append(process)
                close(release_read)
                close(done_write)
                real_wait = process.wait

                def wait(*args, **wait_kwargs):
                    result = real_wait(*args, **wait_kwargs)
                    completed[0] = True
                    return result

                process.wait = wait
                return process

            try:
                with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch), \
                        patch("mpkg_manager.query_process.time.monotonic", side_effect=clock):
                    result = run_readonly(PACKAGE_VERSIONS, timeout=1)
                # An unfixed runner leaves this child alive. Release it only
                # after the runner returns, then await effect or EOF directly.
                try:
                    os.write(release_write, b'x')
                except BrokenPipeError:
                    pass
                close(release_write)
                with selectors.DefaultSelector() as selector:
                    selector.register(done_read, selectors.EVENT_READ)
                    self.assertTrue(selector.select(1), "fixture descendant did not settle")
                    acknowledgement = os.read(done_read, 1)
                self.assertEqual(result.code, "timeout")
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.output, b"")
                self.assertEqual(acknowledgement, b"")
                self.assertFalse(marker.exists())
                self.assertTrue(processes[0].stdout.closed)
                self.assertTrue(processes[0].stderr.closed)
            finally:
                for process in processes:
                    try:
                        os.killpg(process.pid, 9)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1)
                for fd in owned:
                    os.close(fd)

    def test_cancellation_stops_group_and_preserves_exception(self):
        real_popen = subprocess.Popen
        real_selector = selectors.DefaultSelector
        for boundary in ("select", "wait"):
            for exception_type in (KeyboardInterrupt, SystemExit):
                with self.subTest(boundary=boundary, exception=exception_type), \
                        tempfile.TemporaryDirectory() as directory:
                    marker = Path(directory) / "must-not-appear"
                    original = exception_type("cancel observation")
                    leader_exits = exception_type is SystemExit
                    code = f"""
import os, time
child = os.fork()
if child:
    if {leader_exits!r}:
        os._exit(0)
    os.close(1)
    os.close(2)
    time.sleep(5)
else:
    if {boundary!r} == 'select':
        os.write(1, b'ready')
    else:
        os.close(1)
        os.close(2)
    time.sleep(0.6)
    open({str(marker)!r}, 'w').write('effect')
"""
                    processes = []

                    def launch(argv, **kwargs):
                        process = real_popen([sys.executable, "-c", code], **kwargs)
                        processes.append(process)
                        if boundary == "wait":
                            real_wait = process.wait
                            interrupted = False

                            def wait(*args, **wait_kwargs):
                                nonlocal interrupted
                                if not interrupted:
                                    interrupted = True
                                    raise original
                                return real_wait(*args, **wait_kwargs)

                            process.wait = wait
                        return process

                    def selector_factory():
                        selector = real_selector()
                        if boundary == "select":
                            real_select = selector.select

                            def select(timeout=None):
                                events = real_select(timeout)
                                if events:
                                    if leader_exits:
                                        processes[0].wait(timeout=1)
                                    raise original
                                return events

                            selector.select = select
                        return selector

                    started = time.monotonic()
                    with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch), \
                            patch("mpkg_manager.query_process.selectors.DefaultSelector",
                                  side_effect=selector_factory), \
                            self.assertRaises(exception_type) as caught:
                        run_readonly(PACKAGE_VERSIONS, timeout=0.1)
                    self.assertIs(caught.exception, original)
                    self.assertLess(time.monotonic() - started, 0.5)
                    self.assertIsNotNone(processes[0].returncode)
                    self.assertTrue(processes[0].stdout.closed)
                    self.assertTrue(processes[0].stderr.closed)
                    time.sleep(0.65)
                    self.assertFalse(marker.exists())

    def test_query_bounds_cannot_disable_limits(self):
        with patch("mpkg_manager.query_process.subprocess.Popen") as spawn:
            for bounds in ({"timeout": 0}, {"timeout": float("inf")}, {"timeout": True},
                           {"max_output": 0}, {"max_output": 2**30}):
                with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                    run_readonly(PACKAGE_VERSIONS, **bounds)
            spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
