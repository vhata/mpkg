"""Owned workers, fake service transport and temporary stores; no systemd runs."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager import attempt_supervisor as supervisor
from mpkg_manager import attempt_worker as worker
from mpkg_manager.attempt_journal import (_FixtureJournal, _fixture_plan, JournalError,
                                         WorkerIdentity, read_attempt)
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_client import HostClientError, _Reply, request_host
from mpkg_manager.host_helper import BoundaryError, HostBoundary, handle_request
from mpkg_manager.query_process import QueryResult, run_bounded
from mpkg_manager.store import HostStore, StoreError


HOST = "12345678-1234-4234-8234-123456789abc"
BOOT = "22345678-1234-4234-8234-123456789abc"
SECRET = "PRIVATE_WORKER_OUTPUT_SENTINEL"
PACKAGES = load_declaration(b'''schema=1
components=[]
[[resources]]
id="one"
kind="package"
identity={name="git"}
manage=["present"]
desired={present=true}
[[resources]]
id="two"
kind="package"
identity={name="bash"}
manage=["present"]
desired={present=true}
''')


class FakeTransport:
    def __init__(self, outcome="accepted", callback=None):
        self.calls = []
        self.outcome, self.callback = outcome, callback

    def launch(self, spec):
        self.calls.append(spec)
        if self.callback:
            return self.callback(spec)
        return supervisor.LaunchResult(self.outcome)


def _owned_worker(arguments, attempt_id, dispatched, started, release, results):
    try:
        if not dispatched.wait(5):
            raise RuntimeError("fixture dispatch absent")
        def child():
            started.set()
            if not release.wait(5):
                return worker.ChildOutcome("unknown")
            return worker._run_inert_child()
        result = worker.AttemptWorker(**arguments, _runner=child).run(attempt_id)
        results.put(("completed", result["state"]))
    except BaseException:
        results.put(("failed", "fixed_fixture_error"))


def _disconnected_caller(arguments, attempt_id, dispatched):
    class Manager:
        def launch(self, spec):
            dispatched.set()
            # The fake service manager owns the sibling worker. The calling
            # client exits before receiving an acknowledgement.
            raise SystemExit(0)
    supervisor.AttemptSupervisor(**arguments, _transport=Manager()).dispatch(attempt_id)


class SupervisionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "store"
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.lock = self.runtime / "apply.lock"
        self.lock.touch(mode=0o600)
        self.policy = self.root / "policy.toml"
        self.policy.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                               f'allowed_input_roots={json.dumps([str(self.root)])}\n')
        self.policy.chmod(0o600)
        self.store = HostStore.create(self.directory, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.store.adopt(PACKAGES, 0, ["one", "two"])
        self.arguments = {"policy_path": self.policy, "store_directory": self.directory,
                          "mutation_lock": self.lock, "owner_uid": os.geteuid(),
                          "_fixture": True, "_fixture_boot": BOOT}
        self.boundary = HostBoundary(policy_path=self.policy, store_directory=self.directory,
                                     mutation_lock=self.lock, owner_uid=os.geteuid())
        self.transport = FakeTransport()

    def create(self, *, boot=BOOT):
        selected = [record["stable_id"] for record in self.store.current()["resources"]]
        plan = _fixture_plan(self.store, expected_revision=1, stable_resource_ids=selected)
        return _FixtureJournal(self.store).create(plan,
            WorkerIdentity(os.geteuid(), os.geteuid(), boot, str(uuid.uuid4())),
            stable_resource_ids=selected).as_dict()

    def dispatch(self, attempt, transport=None):
        return supervisor.AttemptSupervisor(**self.arguments,
            _transport=self.transport if transport is None else transport).dispatch(attempt["attempt_id"])

    def run_worker(self, attempt, runner=None, **changes):
        return worker.AttemptWorker(**(self.arguments | changes), _runner=runner).run(attempt["attempt_id"])

    def read(self, attempt):
        return read_attempt(self.store, attempt["attempt_id"]).as_dict()

    def record_wire(self):
        return json.dumps({"version": 1, "verb": "record", "arguments": {"operation": "intent",
            "source": PACKAGES.source_bytes.decode(), "source_is_nonsecret": True,
            "expected_revision": 1}}).encode()

    def assert_error(self, code, callback):
        with self.assertRaises((supervisor.SupervisionError, StoreError, JournalError, BoundaryError)) as error:
            callback()
        self.assertEqual(error.exception.code, code)
        self.assertNotIn(SECRET, str(error.exception))

    def test_inactive_fixture_attempt_does_not_block_recording(self):
        self.create()
        self.assertEqual(self.store.record_intent(PACKAGES, 1)["revision"], 2)

    def test_reservation_precedes_dispatch_and_blocks_recording_during_handoff(self):
        attempt = self.create()
        def launch(spec):
            self.assertEqual(spec.attempt_id, attempt["attempt_id"])
            current = self.read(attempt)
            self.assertTrue(current["supervision"]["reserved"])
            self.assertEqual(current["supervision"]["worker"], "not_started")
            # A worker can take the host lock now, but recording cannot cross
            # the durable reservation even in this handoff interval.
            with supervisor._mutation_lock(self.lock, os.geteuid()):
                pass
            self.assert_error("attempt_recovery_required", lambda: self.store.record_intent(PACKAGES, 1))
            response = json.loads(handle_request(self.record_wire(), boundary=self.boundary))
            self.assertEqual(response["error"]["code"], "attempt_recovery_required")
            with sqlite3.connect(self.directory / "state.sqlite3", timeout=0) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("ROLLBACK")
            return supervisor.LaunchResult("accepted")
        result = self.dispatch(attempt, FakeTransport(callback=launch))
        self.assertEqual(result["launch"], "accepted")
        self.assertFalse(result["executable"])

    def test_all_authority_writes_and_new_attempts_refuse_reservation(self):
        attempt = self.create()
        self.dispatch(attempt)
        stable = self.store.current()["resources"][0]["stable_id"]
        for callback in (lambda: self.store.record_intent(PACKAGES, 1),
                         lambda: self.store.adopt(PACKAGES, 1, ["one"]),
                         lambda: self.store.relinquish([stable], 1), self.create):
            self.assert_error("attempt_recovery_required", callback)
        self.assertEqual(self.store.current()["revision"], 1)

    def test_host_client_preserves_fixed_recovery_required_diagnostic(self):
        attempt = self.create()
        self.dispatch(attempt)
        def send(raw):
            response = handle_request(raw, boundary=self.boundary)
            return _Reply(response, 2)
        with self.assertRaises(HostClientError) as error:
            request_host(self.record_wire(), _sender=send)
        self.assertEqual((error.exception.code, error.exception.exit_status), ("attempt_recovery_required", 6))

    def test_competing_launch_and_duplicate_dispatch_never_redispatch(self):
        first, second = self.create(), self.create()
        self.dispatch(first)
        self.assert_error("attempt_already_dispatched", lambda: self.dispatch(first))
        self.assert_error("attempt_recovery_required", lambda: self.dispatch(second))
        self.assertEqual(len(self.transport.calls), 1)

    def test_start_commit_failure_never_calls_system_manager(self):
        attempt = self.create()
        with patch.object(HostStore, "_commit", side_effect=OSError(SECRET)):
            self.assert_error("commit_outcome_unknown", lambda: self.dispatch(attempt))
        self.assertEqual(self.transport.calls, [])
        self.assertFalse(self.read(attempt)["supervision"]["reserved"])

    def test_persisted_reservation_with_lost_response_never_redispatches(self):
        attempt = self.create()
        commit = HostStore._commit
        def lost(store):
            commit(store)
            raise OSError(SECRET)
        with patch.object(HostStore, "_commit", lost):
            self.assert_error("commit_outcome_unknown", lambda: self.dispatch(attempt))
        self.assertEqual(self.transport.calls, [])
        self.assertTrue(self.read(attempt)["supervision"]["reserved"])
        self.assert_error("attempt_already_dispatched", lambda: self.dispatch(attempt))

    def test_handoff_cleanup_failure_keeps_reservation_and_invokes_no_transport(self):
        attempt = self.create()
        original = supervisor._mutation_lock
        @contextmanager
        def interrupted(*args):
            with original(*args):
                yield
            raise OSError(SECRET)
        with patch.object(supervisor, "_mutation_lock", interrupted):
            with self.assertRaises(OSError):
                self.dispatch(attempt)
        self.assertEqual(self.transport.calls, [])
        self.assertTrue(self.read(attempt)["supervision"]["reserved"])
        self.assert_error("attempt_recovery_required", lambda: self.store.record_intent(PACKAGES, 1))

    def test_rejected_and_ambiguous_launches_preserve_durable_reservation(self):
        attempt = self.create()
        result = self.dispatch(attempt, FakeTransport("rejected"))
        self.assertEqual(result["launch"], "rejected")
        self.assert_error("worker_claim_refused", lambda: self.run_worker(attempt))
        self.assert_error("attempt_recovery_required", lambda: self.store.record_intent(PACKAGES, 1))

    def test_secret_bearing_transport_exception_is_unknown_without_leakage(self):
        attempt = self.create()
        def fail(spec):
            raise RuntimeError(SECRET)
        result = self.dispatch(attempt, FakeTransport(callback=fail))
        self.assertEqual(result["launch"], "unknown")
        self.assertNotIn(SECRET, json.dumps(result) + json.dumps(self.read(attempt)))
        self.assertNotIn(SECRET.encode(), (self.directory / "state.sqlite3").read_bytes())
        self.assert_error("attempt_already_dispatched", lambda: self.dispatch(attempt))

    def test_worker_without_reservation_and_wrong_boot_are_refused(self):
        attempt = self.create()
        self.assert_error("worker_claim_refused", lambda: self.run_worker(attempt))
        self.dispatch(attempt)
        self.assert_error("worker_identity_mismatch", lambda: self.run_worker(attempt, _fixture_boot=str(uuid.uuid4())))
        self.assertEqual(self.read(attempt)["supervision"]["worker"], "not_started")

    def test_production_boundary_cannot_run_or_dispatch_fixture_authority(self):
        attempt = self.create()
        with patch.object(supervisor, "_boot_id", return_value=BOOT):
            arguments = self.arguments | {"_fixture": False}
            self.assert_error("execution_unavailable", lambda: supervisor.AttemptSupervisor(
                **arguments, _transport=self.transport).dispatch(attempt["attempt_id"]))
        with patch.object(worker, "_boot_id", return_value=BOOT):
            self.assert_error("execution_unavailable", lambda: self.run_worker(attempt, _fixture=False))
        self.assertEqual(self.transport.calls, [])

    def test_worker_holds_host_lock_but_releases_database_locks_during_child(self):
        attempt = self.create()
        self.dispatch(attempt)
        calls = []
        def child():
            self.assert_error("mutation_busy", lambda: self.boundary.dispatch(
                __import__('mpkg_manager.host_protocol', fromlist=['parse_request']).parse_request(self.record_wire())))
            with sqlite3.connect(self.directory / "state.sqlite3", timeout=0) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("ROLLBACK")
            # Status/export reads do not wait for the host application lock.
            raw = json.dumps({"version": 1, "verb": "export", "arguments": {"operation": "current"}}).encode()
            self.assertTrue(json.loads(handle_request(raw, boundary=self.boundary))["ok"])
            self.assertEqual(self.read(attempt)["supervision"]["worker"], "owned")
            calls.append("child")
            return worker._run_inert_child()
        result = self.run_worker(attempt, child)
        self.assertEqual(calls, ["child", "child"])
        self.assertTrue(result["supervision"]["released"])
        self.assertEqual(result["state"], "observed-complete")
        self.assertEqual(self.store.record_intent(PACKAGES, 1)["revision"], 2)

    def test_duplicate_worker_cannot_replay_finished_attempt(self):
        attempt = self.create()
        self.dispatch(attempt)
        self.run_worker(attempt)
        self.assert_error("worker_claim_refused", lambda: self.run_worker(attempt))
        self.assert_error("attempt_already_dispatched", lambda: self.dispatch(attempt))

    def test_worker_can_complete_before_launch_acknowledgement(self):
        attempt = self.create()
        def launch(spec):
            result = self.run_worker(attempt)
            self.assertTrue(result["finished"])
            return supervisor.LaunchResult("accepted")
        self.dispatch(attempt, FakeTransport(callback=launch))
        current = self.read(attempt)
        self.assertEqual(current["supervision"]["dispatch"], "accepted")
        self.assertTrue(current["supervision"]["released"])
        self.assertEqual(current["events"][-1]["kind"], "launch_result")

    def test_worker_start_commit_failure_invokes_no_child(self):
        attempt = self.create()
        self.dispatch(attempt)
        calls = []
        with patch.object(HostStore, "_commit", side_effect=OSError(SECRET)):
            self.assert_error("commit_outcome_unknown", lambda: self.run_worker(attempt,
                lambda: calls.append("child")))
        self.assertEqual(calls, [])
        self.assertEqual(self.read(attempt)["supervision"]["worker"], "not_started")

    def test_timeout_keeps_unknown_work_and_blocks_retry_after_worker_exit(self):
        attempt = self.create()
        self.dispatch(attempt)
        def child():
            result = run_bounded((sys.executable, "-I", "-c", "import time; time.sleep(2)"),
                environment=supervisor._ENVIRONMENT, timeout=0.02, max_output=1024)
            self.assertEqual(result.code, "timeout")
            return worker._child_outcome(result)
        result = self.run_worker(attempt, child)
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["finished"])
        self.assertEqual(result["supervision"]["worker"], "unresolved")
        self.assertFalse(result["supervision"]["released"])
        self.assertEqual(result["actions"][1]["state"], "planned")
        with supervisor._mutation_lock(self.lock, os.geteuid()):
            pass  # A free lock does not resolve unknown quiescence.
        self.assert_error("attempt_recovery_required", lambda: self.store.record_intent(PACKAGES, 1))
        self.assert_error("worker_claim_refused", lambda: self.run_worker(attempt))

    def test_child_errors_and_bounded_output_never_enter_history(self):
        attempt = self.create()
        self.dispatch(attempt)
        def child():
            result = run_bounded((sys.executable, "-I", "-c",
                f'import sys; print("{SECRET}" * 1000); print("{SECRET}",file=sys.stderr)'),
                environment=supervisor._ENVIRONMENT, timeout=1, max_output=64)
            self.assertEqual(result.code, "output_limit")
            return worker._child_outcome(result)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = self.run_worker(attempt, child)
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(SECRET.encode(), (self.directory / "state.sqlite3").read_bytes())
        self.assertFalse(result["supervision"]["released"])

    def test_caller_disconnect_does_not_end_independently_owned_worker(self):
        attempt = self.create()
        context = multiprocessing.get_context("fork")
        dispatched, started, release = context.Event(), context.Event(), context.Event()
        results = context.Queue()
        owned = context.Process(target=_owned_worker,
            args=(self.arguments, attempt["attempt_id"], dispatched, started, release, results))
        caller = context.Process(target=_disconnected_caller,
            args=(self.arguments, attempt["attempt_id"], dispatched))
        owned.start()
        caller.start()
        try:
            caller.join(5)
            self.assertEqual(caller.exitcode, 0)
            self.assertTrue(started.wait(5))
            self.assertTrue(owned.is_alive())
            self.assert_error("mutation_busy", lambda: self.dispatch(attempt))
            self.assertEqual(self.read(attempt)["supervision"]["dispatch"], "not_recorded")
            release.set()
            owned.join(5)
            self.assertEqual(owned.exitcode, 0)
            self.assertEqual(results.get(timeout=1), ("completed", "observed-complete"))
            self.assertTrue(self.read(attempt)["supervision"]["released"])
        finally:
            release.set()
            for process in (caller, owned):
                if process.is_alive():
                    process.terminate()
                process.join(5)
                process.close()
            results.close()
            results.join_thread()

    def test_invalid_owned_result_keeps_gate_and_never_runs_next_action(self):
        attempt = self.create()
        self.dispatch(attempt)
        calls = []
        result = self.run_worker(attempt, lambda: calls.append(SECRET))
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["supervision"]["released"])


class TransportTests(unittest.TestCase):
    def test_closed_service_spec_and_fixed_private_client_invocation(self):
        spec = supervisor.LaunchSpec(HOST)
        with patch.object(supervisor, "run_bounded", return_value=QueryResult("ok", SECRET.encode())) as run:
            result = supervisor.SystemdTransport().launch(spec)
        self.assertEqual(result.outcome, "accepted")
        args, options = run.call_args
        self.assertEqual(args, (spec.argv(),))
        self.assertEqual(spec.argv()[-3:], ("--", "/usr/lib/mpkg/attempt-worker.py", HOST))
        for prop in ("Type=exec", "ExitType=cgroup", "KillMode=control-group", "Restart=no",
                     "RemainAfterExit=yes", "StandardOutput=null", "StandardError=null", "LimitCORE=0"):
            self.assertIn("--property=" + prop, spec.argv())
        for forbidden in ("--scope", "--wait", "--pipe", "--pty", "--collect"):
            self.assertNotIn(forbidden, spec.argv())
        self.assertEqual(options["environment"], supervisor._ENVIRONMENT)
        self.assertEqual((options["timeout"], options["max_output"]), (10, 65536))
        self.assertNotIn(SECRET, repr(result))

    def test_launch_result_never_infers_failure_from_ambiguous_client_exit(self):
        for code in ("timeout", "command_failed", "output_limit", "io_error"):
            with self.subTest(code=code), patch.object(supervisor, "run_bounded", return_value=QueryResult(code)):
                self.assertEqual(supervisor.SystemdTransport().launch(supervisor.LaunchSpec(HOST)).outcome, "unknown")
        for code in ("tool_unavailable", "permission_denied", "start_failed"):
            with self.subTest(code=code), patch.object(supervisor, "run_bounded", return_value=QueryResult(code)):
                self.assertEqual(supervisor.SystemdTransport().launch(supervisor.LaunchSpec(HOST)).outcome, "rejected")

    def test_invalid_uuid_or_caller_control_never_reaches_transport(self):
        with patch.object(supervisor, "run_bounded", side_effect=AssertionError("must not run")):
            for value in ("../worker", HOST + " --unit=bad", SECRET, None, 1):
                with self.assertRaises(supervisor.SupervisionError):
                    supervisor.LaunchSpec(value)
            with self.assertRaises(TypeError):
                supervisor.LaunchSpec(HOST, argv=["bad"])
            with self.assertRaises(supervisor.SupervisionError):
                supervisor.SystemdTransport().launch({"attempt_id": HOST})

    def test_installed_worker_main_never_emits_exception_text(self):
        output, error = io.StringIO(), io.StringIO()
        with patch.object(worker.AttemptWorker, "run", side_effect=RuntimeError(SECRET)), \
                redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(worker.main(HOST), 1)
        self.assertEqual(output.getvalue() + error.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
