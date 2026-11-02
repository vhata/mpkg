import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager import runtime_endpoint as runtime
from mpkg_manager._endpoint_process import ProbeResult
from mpkg_manager._runtime_proc import ProcReader, ProcUnavailable, covering_listeners
from mpkg_manager.query_process import QueryResult


HOST = "62b87faa-bd2c-415a-9211-adfb233a8b58"
WHEN = "2026-11-02T12:00:00Z"
CONTAINER = "a" * 64


def native():
    return {"id": "web", "kind": "service", "identity": {"manager": "system", "unit": "web.service"}}


def compose():
    return {"id": "web", "kind": "compose", "identity": {"engine": "local", "project": "example"},
            "desired": {"services": ["web"]}}


def check(port=18080):
    return {"id": "ping", "kind": "endpoint", "resource": "web", "timeout_seconds": 2,
            "url": f"http://127.0.0.1:{port}/private-route", "expected_status": 200}


def service(pid=123, group="/system.slice/web.service"):
    return {"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "Type": "exec",
            "MainPID": str(pid), "InvocationID": "b" * 32, "ControlGroup": group, "TriggeredBy": ""}


def container(pid=123):
    return {"id": CONTAINER, "pid": pid, "running": True, "status": "running",
            "started_at": "2026-11-02T11:00:00.000000001Z", "network_mode": "host",
            "project": "example", "service": "web", "oneoff": "False"}


class Replies:
    def __init__(self):
        self.service = service()
        self.container = container()
        self.engine = "engine-1"
        self.ids = CONTAINER + "\n"
        self.pids = "PID\n123\n"
        self.calls = []
        self.before = None

    def __call__(self, argv, *, timeout, max_output):
        self.calls.append(argv)
        if self.before:
            self.before(len(self.calls), argv)
        if not runtime._allowed_query(argv):
            raise AssertionError("non-allowlisted query")
        if argv[:len(runtime.SERVICE_QUERY)] == runtime.SERVICE_QUERY:
            raw = "\n".join(key + "=" + value for key, value in self.service.items()).encode() + b"\n"
        elif argv == runtime.ENGINE_QUERY:
            raw = json.dumps(self.engine).encode()
        elif argv[:len(runtime.LIST_QUERY)] == runtime.LIST_QUERY:
            raw = self.ids.encode()
        elif argv[:len(runtime.INSPECT_QUERY)] == runtime.INSPECT_QUERY:
            raw = json.dumps(self.container).encode()
        elif argv[:len(runtime.TOP_QUERY)] == runtime.TOP_QUERY:
            raw = self.pids.encode()
        else:
            raise AssertionError("unknown query")
        return QueryResult("ok", raw)


class FakeProc:
    def __init__(self):
        self.calls = []
        self.group = b"0::/system.slice/web.service\n"
        self.token = "stable"
        self.fail = None

    def capture(self, pids, port, guard):
        guard()
        self.calls.append((pids, port))
        if self.fail:
            raise ProcUnavailable(self.fail)
        return (((self.token, self.group), (987,)),), (987,), ((1, 2), (1, 3))


class RuntimeEndpointTests(unittest.TestCase):
    def setUp(self):
        self.replies = Replies()
        self.proc = FakeProc()
        self.probes = []

    def observe(self, resource=None, definition=None, **overrides):
        def probe(url, seconds):
            self.probes.append((url, seconds))
            return ProbeResult("ok", 200)
        arguments = {"host_id": HOST, "engine_aliases": {"local": "engine-1"}, "observed_at": WHEN,
                     "query_runner": self.replies, "proc_reader": self.proc, "probe_runner": probe}
        arguments.update(overrides)
        return runtime.observe_attributed_endpoint(check() if definition is None else definition,
                                                   native() if resource is None else resource, **arguments)

    def test_native_main_process_status_is_attributed_but_not_functional_health(self):
        result = self.observe()
        self.assertEqual((result.attribution, result.route_result), ("verified", "match"))
        self.assertEqual(result.as_dict()["functional_result"], "unverified")
        self.assertEqual(len(self.replies.calls), 4)
        self.assertEqual(len(self.proc.calls), 2)
        self.assertTrue(result.matches_context(check(), native(), host_id=HOST))
        text = repr(result) + json.dumps(result.as_dict())
        for private in ("private-route", "web.service", "system.slice", "MainPID", "987", "18080"):
            self.assertNotIn(private, text)
        projection = result.as_dict()
        projection["limitations"].clear()
        self.assertTrue(result.as_dict()["limitations"])

    def test_compose_selected_service_binds_actual_engine_and_container_membership(self):
        result = self.observe(compose())
        self.assertEqual(result.route_result, "match")
        self.assertEqual(len(self.replies.calls), 16)
        self.assertEqual(self.proc.calls, [((123,), 18080), ((123,), 18080)])
        self.assertTrue(result.matches_context(check(), compose(), host_id=HOST,
                                               engine_aliases={"local": "engine-1"}))

    def test_selected_scope_and_predicate_are_part_of_private_binding(self):
        result = self.observe(compose())
        changed = compose()
        changed["desired"]["services"] = ["other"]
        self.assertFalse(result.matches_context(check(), changed, host_id=HOST,
                                                engine_aliases={"local": "engine-1"}))
        altered = check()
        altered["expected_status"] = 204
        self.assertFalse(result.matches_context(altered, compose(), host_id=HOST,
                                                engine_aliases={"local": "engine-1"}))
        self.assertFalse(result.matches_context(check(), compose(), host_id=HOST,
                                                engine_aliases={"local": "other-engine"}))

    def test_caller_mutation_cannot_relabel_queries_or_evidence(self):
        definition, resource, aliases = check(), compose(), {"local": "engine-1"}
        original_check, original_resource = copy.deepcopy(definition), copy.deepcopy(resource)
        def mutate(count, argv):
            if count == 1:
                definition["url"] = "http://127.0.0.1:19999/replacement"
                resource["identity"]["project"] = "replacement"
                resource["desired"]["services"] = ["replacement"]
                aliases["local"] = "replacement"
        self.replies.before = mutate
        result = self.observe(resource, definition, engine_aliases=aliases)
        self.assertEqual(result.route_result, "match")
        self.assertEqual(self.probes[0][0], original_check["url"])
        self.assertTrue(result.matches_context(original_check, original_resource, host_id=HOST,
                                               engine_aliases={"local": "engine-1"}))
        self.assertNotIn("replacement", repr(self.replies.calls))

    def test_unsupported_address_and_compose_scope_do_not_query_or_probe(self):
        ipv6 = check()
        ipv6["url"] = "http://[::1]:18080/private"
        for resource, definition in ((native(), ipv6), ({**compose(), "desired": {}}, check()),
                                     ({**compose(), "desired": {"services": ["web", "worker"]}}, check())):
            self.assertEqual(self.observe(resource, definition).reason, "runtime_scope_unsupported")
        self.assertEqual(self.replies.calls, [])
        self.assertEqual(self.probes, [])

    def test_invalid_context_rejects_before_queries(self):
        for overrides in ({"budget_seconds": True}, {"budget_seconds": 0}, {"query_runner": 3},
                          {"host_id": "bad"}, {"observed_at": "bad"}, {"proc_reader": object()}):
            with self.subTest(overrides=overrides), self.assertRaises(runtime.RuntimeEndpointError):
                self.observe(**overrides)
        bad = check()
        bad["command"] = "sentinel"
        with self.assertRaises(runtime.RuntimeEndpointError):
            self.observe(definition=bad)
        self.assertEqual(self.replies.calls, [])

    def test_native_socket_activation_inactive_and_cgroup_mismatch_do_not_probe(self):
        for field, value, reason in (("TriggeredBy", "web.socket", "runtime_socket_activation_unsupported"),
                                     ("ActiveState", "inactive", "runtime_service_unavailable"),
                                     ("ControlGroup", "/other.service", "runtime_process_unavailable")):
            with self.subTest(field=field):
                self.replies.service = service()
                self.replies.service[field] = value
                self.assertEqual(self.observe().reason, reason)
        self.assertEqual(self.probes, [])

    def test_compose_ambiguity_engine_network_and_membership_fail_closed(self):
        cases = [("engine", "wrong", "runtime_engine_mismatch"),
                 ("ids", "", "runtime_container_ambiguous"),
                 ("ids", CONTAINER + "\n" + "c" * 64 + "\n", "runtime_container_ambiguous"),
                 ("pids", "PID\n999\n", "runtime_query_malformed")]
        for name, value, reason in cases:
            with self.subTest(name=name):
                self.replies = Replies()
                setattr(self.replies, name, value)
                self.assertEqual(self.observe(compose()).reason, reason)
        for key, value, reason in (("network_mode", "bridge", "runtime_network_unsupported"),
                                  ("running", False, "runtime_container_unavailable"),
                                  ("oneoff", "True", "runtime_query_malformed"),
                                  ("project", "other", "runtime_query_malformed")):
            with self.subTest(key=key):
                self.replies = Replies()
                self.replies.container[key] = value
                self.assertEqual(self.observe(compose()).reason, reason)
        self.assertEqual(self.probes, [])

    def test_initial_runtime_change_prevents_probe(self):
        def change(count, argv):
            if count == 2:
                self.replies.service["InvocationID"] = "c" * 32
        self.replies.before = change
        result = self.observe()
        self.assertEqual((result.route_result, result.reason), ("not_observed", "runtime_changed"))
        self.assertEqual(self.probes, [])

    def test_post_probe_runtime_and_process_changes_discard_success(self):
        for mode in ("manager", "process"):
            with self.subTest(mode=mode):
                self.replies, self.proc = Replies(), FakeProc()
                def probe(url, timeout):
                    if mode == "manager":
                        self.replies.service["InvocationID"] = "c" * 32
                    else:
                        self.proc.token = "replaced"
                    return ProbeResult("ok", 200)
                result = self.observe(probe_runner=probe)
                self.assertEqual((result.attribution, result.route_result, result.reason),
                                 ("unavailable", "unavailable", "runtime_changed"))

    def test_missing_or_unattributed_process_evidence_prevents_probe(self):
        for code in ("runtime_process_unavailable", "runtime_listener_unattributed",
                     "runtime_namespace_unsupported", "runtime_listener_table_malformed"):
            with self.subTest(code=code):
                self.proc.fail = code
                self.assertEqual(self.observe().reason, code)
        self.assertEqual(self.probes, [])

    def test_probe_status_and_failure_remain_separate_from_verified_ownership(self):
        for reply, state, reason in ((ProbeResult("ok", 503), "mismatch", "status_differs"),
                                      (ProbeResult("timeout"), "unavailable", "timeout"),
                                      ({"raw": "PRIVATE"}, "unavailable", "runtime_probe_failed")):
            result = self.observe(probe_runner=lambda url, timeout: reply)
            self.assertEqual((result.attribution, result.route_result, result.reason),
                             ("verified", state, reason))

    def test_query_failures_limits_and_raw_errors_are_redacted(self):
        for response, reason in ((QueryResult("io_error"), "runtime_query_unavailable"),
                                 (QueryResult("ok", b"PRIVATE"), "runtime_query_malformed"),
                                 (QueryResult("ok", b"x" * (runtime.MAX_OUTPUT + 1)), "runtime_inspection_limit"),
                                 ({"secret": "PRIVATE"}, "runtime_query_unavailable")):
            result = self.observe(query_runner=lambda *args, **kwargs: response)
            self.assertEqual(result.reason, reason)
            self.assertNotIn("PRIVATE", repr(result) + json.dumps(result.as_dict()))
        def fails(*args, **kwargs):
            raise OSError("PRIVATE process path")
        self.assertEqual(self.observe(query_runner=fails).reason, "runtime_unavailable")
        self.assertEqual(self.probes, [])

    def test_duplicate_manager_or_json_fields_are_rejected(self):
        good = self.replies(runtime.SERVICE_QUERY + ("web.service",), timeout=1, max_output=1000).output
        result = self.observe(query_runner=lambda *args, **kwargs: QueryResult("ok", good + b"MainPID=123\n"))
        self.assertEqual(result.reason, "runtime_query_malformed")
        original = self.replies
        def duplicate(argv, **kwargs):
            if argv[:len(runtime.INSPECT_QUERY)] == runtime.INSPECT_QUERY:
                return QueryResult("ok", b'{"id":"PRIVATE","id":"duplicate"}')
            return original(argv, **kwargs)
        self.assertEqual(self.observe(compose(), query_runner=duplicate).reason, "runtime_query_malformed")

    def test_out_of_range_service_pid_is_rejected_before_process_reads(self):
        self.replies.service["MainPID"] = str(2**31)
        self.assertEqual(self.observe().reason, "runtime_query_malformed")
        self.assertEqual(self.proc.calls, [])

    def test_late_query_and_probe_results_never_become_matches(self):
        clock = [0.0]
        def query(*args, **kwargs):
            value = self.replies(*args, **kwargs)
            clock[0] += 6
            return value
        with patch.object(runtime.time, "monotonic", side_effect=lambda: clock[0]):
            self.assertEqual(self.observe(query_runner=query).reason, "runtime_query_timeout")
        clock[0] = 0
        def probe(url, timeout):
            clock[0] += timeout
            return ProbeResult("ok", 200)
        with patch.object(runtime.time, "monotonic", side_effect=lambda: clock[0]):
            result = self.observe(probe_runner=probe)
        self.assertEqual((result.attribution, result.route_result, result.reason),
                         ("verified", "unavailable", "timeout"))

    def test_budget_query_count_and_cancellation_are_explicit(self):
        self.assertEqual(self.observe(budget_seconds=1).reason, "runtime_budget_exhausted")
        with patch.object(runtime, "MAX_QUERIES", 1):
            self.assertEqual(self.observe().reason, "runtime_inspection_limit")
        def cancel(url, timeout):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.observe(probe_runner=cancel)

    def test_default_query_adapter_rejects_arbitrary_commands_before_process_creation(self):
        with patch.object(runtime, "run_bounded", side_effect=AssertionError("unexpected execution")):
            for argv in (("/bin/sh", "-c", "PRIVATE"), runtime.TOP_QUERY + ("-bad", "-eo", "pid"),
                         runtime.SERVICE_QUERY + ("--bad.service",), ["/usr/bin/systemctl"]):
                self.assertEqual(runtime.run_readonly(argv, timeout=1).code, "invalid_query")


def table(*rows, ipv6=False):
    header = "  sl local_address " + ("remote_address" if ipv6 else "rem_address") + " st tx_queue rx_queue\n"
    return (header + "".join(rows)).encode()


def row(index=0, inode=987, address="0100007F", port=18080, state="0A"):
    remote = "0" * len(address)
    return (f" {index}: {address}:{port:04X} {remote}:0000 {state} 00000000:00000000 "
            f"00:00000000 00000000 1000 0 {inode} 1 0000000000000000\n")


class ListenerTableTests(unittest.TestCase):
    def test_wildcard_and_all_reuseport_sockets_are_included(self):
        self.assertEqual(covering_listeners(table(row(), row(1, 988, "00000000"), row(2, 989)),
                                           table(ipv6=True), 18080), (987, 988, 989))

    def test_noncovering_address_and_established_connections_do_not_establish_listener(self):
        for source in (table(row(address="0200007F")), table(row(state="01")), table()):
            with self.subTest(source=source), self.assertRaisesRegex(ProcUnavailable, "runtime_listener_unavailable"):
                covering_listeners(source, table(ipv6=True), 18080)

    def test_any_ipv6_listener_on_target_port_is_unsupported(self):
        for address in ("0" * 32, "0" * 24 + "01000000", "1" * 32):
            with self.subTest(address=address), self.assertRaisesRegex(ProcUnavailable, "runtime_ipv6_listener_unsupported"):
                covering_listeners(table(row()), table(row(address=address), ipv6=True), 18080)

    def test_malformed_truncated_and_oversized_tables_cannot_prove_absent_sockets(self):
        for source in (b"", table(row())[:-1], b"PRIVATE\n", table(row()).replace(b"0A", b"XX"),
                       table(row(), row()), b"x" * (1024 * 1024 + 1)):
            with self.subTest(size=len(source)), self.assertRaises(ProcUnavailable):
                covering_listeners(source, table(ipv6=True), 18080)
        with self.assertRaises(ProcUnavailable):
            covering_listeners(table(row()), b"PRIVATE malformed ipv6\n", 18080)


class ProcFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.process = self.root / "123"
        self.own = self.root / str(os.getpid())
        self.namespace_files = self.root / "namespace-files"
        self.namespace_files.mkdir()
        for name in ("net", "user", "mnt"):
            (self.namespace_files / name).touch()
        for directory in (self.process, self.own):
            (directory / "ns").mkdir(parents=True)
            for name in ("net", "user", "mnt"):
                (directory / "ns" / name).symlink_to(self.namespace_files / name)
        (self.own / "net").mkdir()
        (self.own / "net/tcp").write_bytes(table(row()))
        (self.own / "net/tcp6").write_bytes(table(ipv6=True))
        (self.process / "fd").mkdir()
        (self.process / "fd/3").symlink_to("socket:[987]")
        self.executable = self.root / "private-executable"
        self.executable.touch()
        (self.process / "exe").symlink_to(self.executable)
        self.metadata()

    def metadata(self):
        (self.process / "stat").write_bytes(b"123 (private ) command) S " + b"0 " * 18 + b"456\n")
        (self.process / "status").write_text("Pid:\t123\nTgid:\t123\nUid:\t1000 1000 1000 1000\n"
            "Gid:\t1000 1000 1000 1000\nGroups:\t1000 1001\n"
            "CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n")
        for name in ("uid_map", "gid_map"):
            (self.process / name).write_text("0 0 4294967295\n")
        (self.process / "cgroup").write_text("0::/system.slice/web.service\n")


class ProcSnapshotTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.fixture = ProcFixture(directory.name)
        self.reader = ProcReader(directory.name)

    def collect(self):
        return self.reader.capture((123,), 18080, lambda: None)

    def test_complete_descriptor_fixture_binds_identity_and_only_covering_sockets(self):
        (self.fixture.process / "fd/4").symlink_to("socket:[999]")
        snapshot = self.collect()
        identity, owned = snapshot[0][0]
        self.assertEqual(identity[:2], (123, 456))
        self.assertEqual(identity[2][0], (1000, 1000, 1000, 1000))
        self.assertEqual(owned, (987,))
        self.assertEqual(snapshot[1], (987,))

    def test_malformed_metadata_never_becomes_process_identity(self):
        for name, raw in (("stat", b"123 (broken\n"), ("stat", b"123 (zombie) Z " + b"0 " * 20),
                          ("status", b"Pid: 123\nUid: 0 0 0\n"), ("uid_map", b"PRIVATE\n"),
                          ("gid_map", b"0 0 4294967296\n"), ("cgroup", b"0::relative\n")):
            with self.subTest(name=name):
                self.fixture.metadata()
                (self.fixture.process / name).write_bytes(raw)
                with self.assertRaises(ProcUnavailable):
                    self.collect()

    def test_missing_credential_fields_prevent_attribution_and_probe(self):
        for field in ("Uid", "Gid", "Groups"):
            with self.subTest(field=field):
                self.fixture.metadata()
                path = self.fixture.process / "status"
                path.write_text("".join(line for line in path.read_text().splitlines(keepends=True)
                                        if not line.startswith(field + ":")))
                with patch.object(runtime, "run_probe") as probe:
                    result = runtime.observe_attributed_endpoint(check(), native(), host_id=HOST,
                        observed_at=WHEN, query_runner=Replies(), proc_reader=self.reader)
                self.assertEqual((result.attribution, result.route_result, result.reason),
                                 ("unavailable", "not_observed", "runtime_process_malformed"))
                probe.assert_not_called()

    def test_explicit_empty_supplementary_groups_remain_observed(self):
        path = self.fixture.process / "status"
        path.write_text(path.read_text().replace("Groups:\t1000 1001\n", "Groups:\n"))
        self.assertEqual(self.collect()[0][0][0][2][2], ())
        with patch.object(runtime, "run_probe", return_value=ProbeResult("ok", 200)) as probe:
            result = runtime.observe_attributed_endpoint(check(), native(), host_id=HOST,
                observed_at=WHEN, query_runner=Replies(), proc_reader=self.reader)
        self.assertEqual((result.attribution, result.route_result), ("verified", "match"))
        probe.assert_called_once_with(check()["url"], check()["timeout_seconds"])

    def test_user_or_network_namespace_mismatch_is_unsupported(self):
        other = self.fixture.root / "other-namespace"
        other.touch()
        for name in ("net", "user"):
            path = self.fixture.process / "ns" / name
            path.unlink()
            path.symlink_to(other)
            with self.subTest(name=name), self.assertRaisesRegex(ProcUnavailable, "runtime_namespace_unsupported"):
                self.collect()
            path.unlink()
            path.symlink_to(self.fixture.namespace_files / name)

    def test_different_mount_namespace_is_supported_when_stable(self):
        other = self.fixture.root / "other-mount"
        other.touch()
        path = self.fixture.process / "ns/mnt"
        path.unlink()
        path.symlink_to(other)
        self.assertEqual(self.collect()[1], (987,))

    def test_metadata_changes_during_snapshot_are_discarded(self):
        for name, old, new in (("stat", b"456", b"789"),
                               ("status", b"1000 1000 1000 1000", b"1001 1001 1001 1001"),
                               ("uid_map", b"0 0 4294967295", b"0 100000 65536"),
                               ("cgroup", b"/system.slice/web.service", b"/other.service")):
            with self.subTest(name=name):
                self.fixture.metadata()
                original = self.reader._identity
                calls = [0]
                def changing(parent, pid):
                    calls[0] += 1
                    if calls[0] == 2:
                        path = self.fixture.process / name
                        path.write_bytes(path.read_bytes().replace(old, new))
                    return original(parent, pid)
                with patch.object(self.reader, "_identity", side_effect=changing):
                    with self.assertRaisesRegex(ProcUnavailable, "runtime_changed"):
                        self.collect()

    def test_executable_and_listener_ownership_changes_are_discarded(self):
        original = self.reader._identity
        calls = [0]
        def executable_change(parent, pid):
            calls[0] += 1
            if calls[0] == 2:
                self.fixture.executable.rename(self.fixture.root / "old-executable")
                self.fixture.executable.touch()
            return original(parent, pid)
        with patch.object(self.reader, "_identity", side_effect=executable_change):
            with self.assertRaisesRegex(ProcUnavailable, "runtime_changed"):
                self.collect()
        original_owned = self.reader._owned
        calls[0] = 0
        def ownership_change(parent, listeners):
            calls[0] += 1
            if calls[0] == 2:
                (self.fixture.process / "fd/3").unlink()
            return original_owned(parent, listeners)
        with patch.object(self.reader, "_owned", side_effect=ownership_change):
            with self.assertRaisesRegex(ProcUnavailable, "runtime_changed"):
                self.collect()

    def test_new_covering_listener_after_ownership_scan_invalidates_snapshot(self):
        original = self.reader._read
        calls = [0]
        def changing(parent, name, limit):
            if name == "tcp":
                calls[0] += 1
                if calls[0] == 2:
                    (self.fixture.own / "net/tcp").write_bytes(table(row(), row(1, 988, "00000000")))
            return original(parent, name, limit)
        with patch.object(self.reader, "_read", side_effect=changing):
            with self.assertRaisesRegex(ProcUnavailable, "runtime_changed"):
                self.collect()

    def test_fd_limit_and_oversized_process_metadata_fail_closed(self):
        (self.fixture.process / "fd/4").symlink_to("socket:[999]")
        with patch("mpkg_manager._runtime_proc.MAX_FDS", 1):
            with self.assertRaisesRegex(ProcUnavailable, "runtime_inspection_limit"):
                self.collect()
        (self.fixture.process / "status").write_bytes(b"x" * 65537)
        with self.assertRaisesRegex(ProcUnavailable, "runtime_inspection_limit"):
            self.collect()

    def test_proc_deadline_and_cancellation_propagate_without_success(self):
        def expired():
            raise runtime._Unavailable("runtime_budget_exhausted")
        with self.assertRaisesRegex(runtime._Unavailable, "runtime_budget_exhausted"):
            self.reader.capture((123,), 18080, expired)
        def cancelled():
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.reader.capture((123,), 18080, cancelled)


_SERVER = """
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass
server = HTTPServer(('127.0.0.1', 0), Handler)
print(server.server_port, flush=True)
server.serve_forever()
"""


class OwnedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.child = subprocess.Popen([sys.executable, "-I", "-c", _SERVER], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(self.stop)
        self.port = int(self.child.stdout.readline())
        self.replies = Replies()
        self.replies.container = container(self.child.pid)
        self.replies.pids = "PID\n" + str(self.child.pid) + "\n"

    def stop(self):
        self.child.terminate()
        try:
            self.child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait(timeout=2)
        self.child.stdout.close()

    def test_actual_owned_process_listener_and_default_http_worker_compose(self):
        result = runtime.observe_attributed_endpoint(check(self.port), compose(), host_id=HOST,
            engine_aliases={"local": "engine-1"}, query_runner=self.replies)
        self.assertEqual((result.attribution, result.route_result, result.reason),
                         ("verified", "match", "status_matches"), result)

    def test_actual_proc_snapshot_rejects_listener_owned_by_different_process(self):
        with self.assertRaisesRegex(ProcUnavailable, "runtime_listener_unattributed"):
            ProcReader().capture((os.getpid(),), self.port, lambda: None)

    def test_actual_proc_snapshot_detects_dead_process_without_following_pid_reuse(self):
        pid = self.child.pid
        self.child.terminate()
        self.child.wait(timeout=2)
        with self.assertRaises(ProcUnavailable):
            ProcReader().capture((pid,), self.port, lambda: None)


if __name__ == "__main__":
    unittest.main()
