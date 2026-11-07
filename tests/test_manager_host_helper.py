"""Private real-store boundary checks; no installed/root helper is executed."""
import copy
import fcntl
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from mpkg_manager.host_helper import (BoundaryError, HostBoundary, encode_response, handle_request,
                                      read_request, write_response)
from mpkg_manager.host_protocol import RequestError, parse_request
from mpkg_manager.store import HostStore, StoreError


ROOT = Path(__file__).resolve().parents[1]
HOST = "12345678-1234-4234-8234-123456789abc"
EMPTY = 'schema=1\ncomponents=[]\nresources=[]\n'
FILE = '''schema=1
components=[]
[[resources]]
id="config"
kind="file"
identity={path="/PRIVATE_SOURCE_SENTINEL/config"}
manage=["present"]
desired={present=true}
'''


def request(verb, operation, **values):
    return {"version": 1, "verb": verb, "arguments": {"operation": operation, **values}}


def wire(value):
    return json.dumps(value, ensure_ascii=False).encode()


class ProtocolTests(unittest.TestCase):
    def assert_invalid(self, value, expected="invalid_request"):
        raw = value if isinstance(value, bytes) else wire(value)
        with self.assertRaises(RequestError) as result:
            parse_request(raw)
        self.assertEqual(result.exception.code, expected)
        self.assertNotIn("SENTINEL", str(result.exception))

    def test_valid_operations_preserve_exact_source_and_revision(self):
        for operation in ("initialize",):
            self.assertEqual(parse_request(wire(request("record", operation))).operation, operation)
        for operation in ("current", "history"):
            self.assertEqual(parse_request(wire(request("export", operation))).operation, operation)
        for operation in ("intent", "adopt"):
            source = EMPTY + '# Unicode source comment: å\n'
            value = request("record", operation, source=source, source_is_nonsecret=True, expected_revision=9)
            if operation == "adopt":
                value["arguments"]["resource_ids"] = ["one"]
            parsed = parse_request(wire(value))
            self.assertEqual(parsed.source, source.encode())
            self.assertEqual(parsed.expected_revision, 9)
            self.assertNotIn(source, repr(parsed))
        parsed = parse_request(wire(request("record", "relinquish", expected_revision=9,
                                            resource_ids=[HOST])))
        self.assertEqual(parsed.resource_ids, (HOST,))

    def test_duplicate_nested_keys_and_non_json_types_are_rejected(self):
        for raw in (b'{"version":1,"version":1,"verb":"export","arguments":{"operation":"history"}}',
                    b'{"version":1,"verb":"export","arguments":{"operation":"history","operation":"current"}}',
                    b'{"version":NaN,"verb":"export","arguments":{"operation":"history"}}',
                    b'{"version":1.0,"verb":"export","arguments":{"operation":"history"}}',
                    b'[]', b'null', b'"SENTINEL"', b'{} {}', b'\xff', b'[' * 3000):
            self.assert_invalid(raw)

    def test_wire_cannot_supply_boundary_or_execution_controls(self):
        valid = request("record", "initialize")
        for field in ("path", "store_directory", "policy_path", "owner_uid", "program", "argv", "env",
                      "module", "unit", "operator_uid", "boundary", "mutation_lock"):
            for container in ("outer", "arguments"):
                value = copy.deepcopy(valid)
                (value if container == "outer" else value["arguments"])[field] = "SENTINEL"
                self.assert_invalid(value)

    def test_unsupported_and_unknown_verbs_have_fixed_errors(self):
        for verb in ("observe", "prepare", "plan", "apply", "recover"):
            self.assert_invalid(request(verb, "SENTINEL"), "operation_unsupported")
        for verb in ("SENTINEL", [], None):
            self.assert_invalid(request(verb, "initialize"))
        for version in (True, None, "1", 0, 2):
            value = request("record", "initialize") | {"version": version}
            self.assert_invalid(value, "protocol_unsupported")

    def test_record_requires_explicit_nonsecret_classification_and_valid_declaration(self):
        valid = request("record", "intent", source=EMPTY, expected_revision=0, source_is_nonsecret=True)
        for value in (False, 1, "true", None):
            bad = copy.deepcopy(valid)
            bad["arguments"]["source_is_nonsecret"] = value
            self.assert_invalid(bad)
        for revision in (-1, 2**63 - 1, True, "0"):
            bad = copy.deepcopy(valid)
            bad["arguments"]["expected_revision"] = revision
            self.assert_invalid(bad)
        bad = copy.deepcopy(valid)
        bad["arguments"]["source"] = 'schema=1\nPRIVATE_SENTINEL=7\n'
        self.assert_invalid(bad, "invalid_declaration")
        bad["arguments"]["source"] = '\ud800'
        self.assert_invalid(json.dumps(bad).encode())

    def test_protected_declarations_require_explicit_preparation(self):
        source = EMPTY + f'''[[inputs]]
id="private"
base_directory="/PRIVATE_SENTINEL"
files=[{{path="secret.env",classification="protected",reference="{HOST}"}}]
'''
        self.assert_invalid(request("record", "intent", source=source, expected_revision=0,
                                    source_is_nonsecret=True), "protected_preparation_required")

    def test_selection_and_size_bounds_do_not_accept_coercion(self):
        for selection in ([], ["a", "a"], "a", [1], ["bad/path"], ["a"] * 4097):
            self.assert_invalid(request("record", "adopt", source=EMPTY, expected_revision=0,
                                        source_is_nonsecret=True, resource_ids=selection))
        self.assert_invalid(request("record", "relinquish", expected_revision=0, resource_ids=["logical-name"]))
        with patch("mpkg_manager.host_protocol.MAX_REQUEST_BYTES", 10):
            self.assert_invalid(request("export", "history"), "request_size_limit")
        with patch("mpkg_manager.host_protocol.MAX_DECLARATION_BYTES", 10):
            self.assert_invalid(request("record", "intent", source=EMPTY, expected_revision=0,
                                        source_is_nonsecret=True), "request_size_limit")


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy_dir = self.root / "policy"
        self.policy_dir.mkdir(mode=0o700)
        self.policy = self.policy_dir / "host-policy.toml"
        self.policy.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                               f'allowed_input_roots={json.dumps([str(self.root)])}\n')
        self.policy.chmod(0o600)
        self.runtime = self.root / "run"
        self.runtime.mkdir(mode=0o700)
        self.lock = self.runtime / "apply.lock"
        self.lock.touch(mode=0o600)
        self.store = self.root / "store"
        self.boundary = HostBoundary(policy_path=self.policy, store_directory=self.store,
                                     mutation_lock=self.lock, owner_uid=os.geteuid())

    def call(self, verb, operation, **values):
        return json.loads(handle_request(wire(request(verb, operation, **values)), boundary=self.boundary))

    def initialize(self):
        result = self.call("record", "initialize")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"], {"host_id": HOST, "revision": 0, "initialized": True})

    def record(self, operation="intent", source=FILE, revision=0, **values):
        return self.call("record", operation, source=source, source_is_nonsecret=True,
                         expected_revision=revision, **values)

    def assert_code(self, response, code):
        self.assertEqual(response, {"version": 1, "ok": False, "error": {"code": code}})

    def inventory(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_mtime_ns,
                                                   stat.S_IMODE(path.stat().st_mode))
                for path in self.root.rglob("*") if path.is_file()}

    def test_initialize_is_explicit_refuses_existing_and_missing_reads_change_nothing(self):
        before = self.inventory()
        self.assert_code(self.call("export", "current"), "store_missing")
        self.assert_code(self.record(), "store_missing")
        self.assertEqual(self.inventory(), before)
        self.initialize()
        before = self.inventory()
        self.assert_code(self.call("record", "initialize"), "store_exists")
        self.assertEqual(self.inventory(), before)

    def test_initialize_failure_before_commit_preserves_partial_state_and_reports_unknown(self):
        with patch.object(HostStore, "_commit", side_effect=OSError("PRIVATE_IO_SENTINEL")):
            self.assert_code(self.call("record", "initialize"), "record_outcome_unknown")
        self.assertTrue(self.store.is_dir())
        self.assertTrue((self.store / "state.sqlite3").is_file())
        before = self.inventory()
        self.assertFalse(self.call("export", "current")["ok"])
        self.assert_code(self.call("record", "initialize"), "store_exists")
        self.assertEqual(self.inventory(), before)

    def test_initialize_failure_after_commit_reports_unknown_and_can_be_inspected(self):
        original = HostStore._commit
        def committed_then_failed(store):
            original(store)
            raise OSError("PRIVATE_IO_SENTINEL")
        with patch.object(HostStore, "_commit", committed_then_failed):
            self.assert_code(self.call("record", "initialize"), "record_outcome_unknown")
        current = self.call("export", "current")
        self.assertTrue(current["ok"], current)
        self.assertEqual(current["result"]["host_id"], HOST)
        self.assertEqual(current["result"]["revision"], 0)
        before = self.inventory()
        self.assert_code(self.call("record", "initialize"), "store_exists")
        self.assertEqual(self.inventory(), before)

    def test_partial_store_is_not_repaired(self):
        self.store.mkdir(mode=0o700)
        (self.store / "sentinel").write_text("PRIVATE_SENTINEL")
        before = self.inventory()
        self.assert_code(self.call("record", "initialize"), "store_exists")
        self.assertEqual(self.inventory(), before)

    def test_actual_record_adopt_relinquish_and_redacted_exports(self):
        self.initialize()
        with patch("subprocess.Popen", side_effect=AssertionError("native operation")), \
                patch("socket.socket", side_effect=AssertionError("network operation")):
            adopted = self.record("adopt", resource_ids=["config"])
            self.assertTrue(adopted["ok"], adopted)
            current = self.call("export", "current")["result"]
            self.assertEqual(current["revision"], 1)
            row = current["resources"][0]
            self.assertEqual(row["management"], "accepted")
            self.assertEqual(row["observation"], {"state": "unknown", "reason": "not_observed"})
            self.assertEqual(row["managed_properties"], ["present"])
            serialized = json.dumps(current)
            for text in ("PRIVATE_SOURCE_SENTINEL", "physical_key", "definition", "desired", "reference", "identity"):
                self.assertNotIn(text, serialized)
            before = self.inventory()
            history = self.call("export", "history")
            self.assertEqual(self.inventory(), before)
            self.assertEqual(history["result"]["decisions"][0]["kind"], "adopt")
            retained = self.record(source=EMPTY, revision=1)
            self.assertTrue(retained["ok"], retained)
            self.assertTrue(self.call("export", "current")["result"]["resources"][0]["pending_disposition"])
            result = self.call("record", "relinquish", expected_revision=2, resource_ids=[row["stable_id"]])
            self.assertTrue(result["ok"], result)
            self.assertEqual(self.call("export", "current")["result"]["resources"][0]["management"], "relinquished")
        with HostStore.open_readonly(self.store, HOST, owner_uid=os.geteuid()) as store:
            snapshot = store.snapshot(adopted["result"]["snapshot_id"])
            self.assertEqual(snapshot.source_bytes, FILE.encode())

    def test_stale_revision_and_invalid_requests_do_not_change_store(self):
        self.initialize()
        self.assertTrue(self.record()["ok"])
        before = self.inventory()
        self.assert_code(self.record(revision=0), "revision_conflict")
        self.assert_code(self.call("record", "intent", expected_revision=1, source=FILE,
                                   source_is_nonsecret=False), "invalid_request")
        self.assertEqual(self.inventory(), before)

    def test_changed_policy_host_and_aliases_fail_without_writes(self):
        self.initialize()
        original = self.policy.read_text()
        self.policy.write_text(original.replace("engine_aliases={}", 'engine_aliases={local="changed"}'))
        before = self.inventory()
        self.assert_code(self.record(), "host_binding_conflict")
        self.assert_code(self.call("export", "current"), "host_binding_conflict")
        self.assertEqual(self.inventory(), before)
        self.policy.write_text(original.replace(HOST, "22345678-1234-4234-8234-123456789abc"))
        self.assertFalse(self.record()["ok"])

    def test_fixture_owner_must_match_effective_identity(self):
        before = self.inventory()
        with patch("mpkg_manager.host_helper.os.geteuid", return_value=os.geteuid() + 1):
            self.assert_code(self.call("record", "initialize"), "host_owner_required")
        self.assertEqual(self.inventory(), before)
        self.assertFalse(self.store.exists())

    def test_unsafe_policy_and_store_paths_are_not_followed(self):
        for mode in (0o644, 0o666):
            self.policy.chmod(mode)
            self.assert_code(self.call("record", "initialize"), "policy_unavailable")
            self.assertFalse(self.store.exists())
        self.policy.chmod(0o600)
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        self.store.symlink_to(outside, target_is_directory=True)
        before = self.inventory()
        self.assertFalse(self.record()["ok"])
        self.assertEqual(self.inventory(), before)

    def test_no_wire_field_can_activate_fixture_overrides(self):
        self.initialize()
        with patch("mpkg_manager.host_helper.HostBoundary") as factory:
            for field in ("owner_uid", "policy_path", "store_directory", "mutation_lock"):
                result = json.loads(handle_request(wire(request("record", "initialize", **{field: str(self.root)}))))
                self.assert_code(result, "invalid_request")
            factory.assert_not_called()

    def test_busy_host_lock_blocks_record_but_not_readonly_export(self):
        self.initialize()
        fd = os.open(self.lock, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = self.inventory()
        self.assert_code(self.record(), "mutation_busy")
        self.assertTrue(self.call("export", "history")["ok"])
        self.assertEqual(self.inventory(), before)

    def test_missing_symlinked_hardlinked_and_permissive_locks_are_refused(self):
        self.initialize()
        self.lock.unlink()
        self.assert_code(self.record(), "mutation_lock_unavailable")
        self.assertFalse(self.lock.exists())
        outside = self.root / "outside-lock"
        outside.touch(mode=0o600)
        self.lock.symlink_to(outside)
        self.assert_code(self.record(), "mutation_lock_unavailable")
        self.lock.unlink()
        os.link(outside, self.lock)
        self.assert_code(self.record(), "mutation_lock_unavailable")
        self.lock.unlink()
        self.lock.touch(mode=0o644)
        self.assert_code(self.record(), "mutation_lock_unavailable")

    def test_policy_change_after_commit_reports_uncertainty(self):
        self.initialize()
        original = HostStore.record_intent
        def record_and_change(store, *args, **kwargs):
            result = original(store, *args, **kwargs)
            self.policy.write_text(self.policy.read_text() + "# changed\n")
            return result
        with patch.object(HostStore, "record_intent", record_and_change):
            self.assert_code(self.record(), "record_outcome_unknown")
        self.assertEqual(self.call("export", "current")["result"]["revision"], 1)

    def test_commit_unknown_and_arbitrary_exceptions_are_sanitized(self):
        self.initialize()
        for error, code in ((StoreError("commit_outcome_unknown"), "commit_outcome_unknown"),
                            (RuntimeError("PRIVATE_EXCEPTION_SENTINEL"), "record_outcome_unknown"),
                            (OSError("PRIVATE_EXCEPTION_SENTINEL"), "record_outcome_unknown"),
                            (StoreError("PRIVATE_EXCEPTION_SENTINEL"), "record_rejected")):
            with patch.object(HostStore, "record_intent", side_effect=error):
                self.assert_code(self.record(), code)
        with patch.object(HostStore, "history", side_effect=RuntimeError("PRIVATE_EXCEPTION_SENTINEL")):
            self.assert_code(self.call("export", "history"), "internal_error")
        self.assertEqual(self.call("export", "current")["result"]["revision"], 0)

    def test_response_size_limit_is_explicit_and_does_not_leak_values(self):
        self.initialize()
        with patch("mpkg_manager.host_helper.MAX_RESPONSE_BYTES", 100):
            response = self.call("export", "current")
        self.assert_code(response, "response_size_limit")


class TransportTests(unittest.TestCase):
    def test_command_exit_status_tracks_protocol_failure_and_transport_failure(self):
        from mpkg_manager.host_helper import main
        with patch("sys.argv", ["host-helper"]), \
                patch("mpkg_manager.host_helper.read_request", return_value=b"not JSON"), \
                patch("mpkg_manager.host_helper.write_response", return_value=True) as output:
            self.assertEqual(main(), 2)
            self.assertEqual(json.loads(output.call_args.args[1])["error"]["code"], "invalid_request")
            output.return_value = False
            self.assertEqual(main(), 1)
        with patch("sys.argv", ["host-helper", "--path", "PRIVATE_SENTINEL"]), \
                patch("mpkg_manager.host_helper.read_request") as reader, \
                patch("mpkg_manager.host_helper.write_response", return_value=True) as output:
            self.assertEqual(main(), 2)
            reader.assert_not_called()
            self.assertNotIn(b"PRIVATE_SENTINEL", output.call_args.args[1])

    def test_input_transport_failures_have_transport_exit_and_fixed_diagnostics(self):
        from mpkg_manager.host_helper import main
        cases = ((BoundaryError("request_timeout"), "request_timeout", 1),
                 (OSError("PRIVATE_TRANSPORT_SENTINEL"), "transport_unavailable", 1),
                 (BoundaryError("request_size_limit"), "request_size_limit", 2))
        for failure, code, status in cases:
            with self.subTest(code=code), patch("sys.argv", ["host-helper"]), \
                    patch("mpkg_manager.host_helper.read_request", side_effect=failure), \
                    patch("mpkg_manager.host_helper.write_response", return_value=True) as output:
                self.assertEqual(main(), status)
                raw = output.call_args.args[1]
                self.assertEqual(json.loads(raw), {"version": 1, "ok": False, "error": {"code": code}})
                self.assertNotIn(b"PRIVATE_TRANSPORT_SENTINEL", raw)

    def pipe(self):
        reader, writer = os.pipe()
        self.addCleanup(os.close, reader)
        self.addCleanup(os.close, writer)
        return reader, writer

    def test_request_requires_eof_and_has_deadline(self):
        reader, writer = self.pipe()
        os.write(writer, wire(request("export", "history")))
        started = time.monotonic()
        with self.assertRaises(BoundaryError) as result:
            read_request(reader, timeout=0.03)
        self.assertEqual(result.exception.code, "request_timeout")
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(os.get_blocking(reader))

    def test_regular_file_and_pipe_request_bounds(self):
        with tempfile.TemporaryFile() as stream:
            raw = wire(request("export", "history"))
            stream.write(raw)
            stream.seek(0)
            self.assertEqual(read_request(stream.fileno()), raw)
            stream.seek(0)
            with patch("mpkg_manager.host_helper.MAX_REQUEST_BYTES", 10):
                with self.assertRaises(BoundaryError) as result:
                    read_request(stream.fileno())
            self.assertEqual(result.exception.code, "request_size_limit")
        reader, writer = os.pipe()
        try:
            os.write(writer, raw)
            os.close(writer)
            writer = None
            self.assertEqual(read_request(reader), raw)
        finally:
            os.close(reader)
            if writer is not None:
                os.close(writer)

    def test_late_eof_is_not_accepted_as_timely_request(self):
        with tempfile.TemporaryFile() as stream:
            with patch("mpkg_manager.host_helper.time.monotonic", side_effect=[0.0, 0.0, 1.0]):
                with self.assertRaises(BoundaryError) as result:
                    read_request(stream.fileno(), timeout=1.0)
        self.assertEqual(result.exception.code, "request_timeout")

    def test_late_final_write_is_not_reported_as_timely_delivery(self):
        with tempfile.TemporaryFile() as stream:
            with patch("mpkg_manager.host_helper.time.monotonic", side_effect=[0.0, 0.0, 1.0]):
                self.assertFalse(write_response(stream.fileno(), b"response", timeout=1.0))

    def test_unresponsive_output_is_bounded_and_restores_fd_flags(self):
        reader, writer = self.pipe()
        started = time.monotonic()
        self.assertFalse(write_response(writer, b"x" * (1024 * 1024), timeout=0.03))
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(os.get_blocking(writer))


class InstalledPayloadTests(unittest.TestCase):
    def stage(self):
        # Ancestors have ordinary owner-only write permissions, unlike /tmp;
        # the production bootstrap deliberately refuses writable ancestors.
        cache = ROOT / ".docket"
        cache.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=cache)
        self.addCleanup(temporary.cleanup)
        target = Path(temporary.name)
        subprocess.run(["bash", str(ROOT / "packages/mpkg-manager/stage.sh"), str(target)], check=True)
        return target, target / "usr/lib/mpkg"

    def checker(self):
        return runpy.run_path(str(ROOT / "packages/mpkg-manager/host-helper.py"))["_verified_installation"]

    def test_staged_tree_has_fixed_entrypoint_sources_and_lock_rule(self):
        target, installed = self.stage()
        self.checker()(str(installed), owner_uid=os.geteuid())
        self.assertEqual({path.name for path in (installed / "mpkg_manager").iterdir()},
                         {path.name for path in (ROOT / "mpkg_manager").glob("*.py")})
        self.assertEqual(stat.S_IMODE((installed / "host-helper.py").stat().st_mode), 0o755)
        self.assertTrue((installed / "host-helper.py").read_text().startswith("#!/usr/bin/python3.12 -I\n"))
        self.assertEqual((installed / "attempt-worker.py").read_bytes(), (installed / "host-helper.py").read_bytes())
        self.assertEqual(stat.S_IMODE((installed / "attempt-worker.py").stat().st_mode), 0o755)
        self.assertEqual((target / "usr/lib/tmpfiles.d/mpkg.conf").read_bytes(),
                         (ROOT / "packages/mpkg-manager/mpkg.conf").read_bytes())
        self.assertFalse((target / "etc").exists())
        self.assertFalse((target / "var").exists())
        self.assertFalse((target / "run").exists())

    def test_install_check_refuses_unsafe_code_and_ancestors(self):
        target, installed = self.stage()
        check = self.checker()
        module = installed / "mpkg_manager/host_protocol.py"
        original = module.read_bytes()
        module.chmod(0o666)
        with self.assertRaises(ValueError):
            check(str(installed), owner_uid=os.geteuid())
        module.chmod(0o644)
        module.unlink()
        module.symlink_to(ROOT / "mpkg_manager/host_protocol.py")
        with self.assertRaises(ValueError):
            check(str(installed), owner_uid=os.geteuid())
        module.unlink()
        module.write_bytes(original)
        os.link(module, installed / "mpkg_manager/other.py")
        with self.assertRaises(ValueError):
            check(str(installed), owner_uid=os.geteuid())
        (installed / "mpkg_manager/other.py").unlink()
        installed.chmod(0o777)
        with self.assertRaises(ValueError):
            check(str(installed), owner_uid=os.geteuid())

    def test_wrong_location_refuses_before_importing_product_or_cwd_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in ("json.py", "sitecustomize.py", "host_helper.py"):
                (target / name).write_text('raise Exception("IMPORT_SENTINEL")\n')
            (target / "mpkg_manager").mkdir()
            (target / "mpkg_manager/__init__.py").write_text('raise Exception("IMPORT_SENTINEL")\n')
            result = subprocess.run([sys.executable, "-I", str(ROOT / "packages/mpkg-manager/host-helper.py")],
                                    cwd=target, env={**os.environ, "PYTHONPATH": str(target)},
                                    input=b"PRIVATE_INPUT_SENTINEL", capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "installed_helper_unavailable")
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"SENTINEL", result.stdout)

    def test_stager_refuses_nonempty_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            sentinel = target / "unrelated"
            sentinel.write_text("keep")
            result = subprocess.run(["bash", str(ROOT / "packages/mpkg-manager/stage.sh"), str(target)],
                                    capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(target.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_text(), "keep")

    def test_worker_entrypoint_is_required_and_checked_before_module_import(self):
        _, installed = self.stage()
        entrypoint = installed / "attempt-worker.py"
        raw = entrypoint.read_bytes()
        entrypoint.chmod(0o777)
        with self.assertRaises(ValueError):
            self.checker()(str(installed), owner_uid=os.geteuid())
        entrypoint.unlink()
        with self.assertRaises(FileNotFoundError):
            self.checker()(str(installed), owner_uid=os.geteuid())
        entrypoint.write_bytes(raw)
        entrypoint.chmod(0o755)
        self.checker()(str(installed), owner_uid=os.geteuid())

    def test_staged_worker_refuses_wrong_location_and_additional_arguments(self):
        _, installed = self.stage()
        for arguments in ([HOST], [HOST, "PRIVATE_ARGUMENT_SENTINEL"]):
            result = subprocess.run([sys.executable, "-I", str(installed / "attempt-worker.py"), *arguments],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["error"]["code"], "installed_helper_unavailable")
            self.assertEqual(result.stderr, b"")
            self.assertNotIn(b"SENTINEL", result.stdout)


if __name__ == "__main__":
    unittest.main()
