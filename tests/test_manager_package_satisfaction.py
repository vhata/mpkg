"""Package satisfaction uses synthetic native replies and private child processes."""
from dataclasses import FrozenInstanceError
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

from mpkg_manager.observe_packages import (
    ENVIRONMENT, MAX_OUTPUT, QUERY, SOURCE, observe_package_requests, run_readonly,
)
from mpkg_manager.query_process import QueryResult, run_bounded


HOST = "98d1f834-494b-4a5e-bad0-ab8fb03fecb2"
WHEN = "2026-11-02T23:00:00Z"
SECRET = "private-diagnostic-not-public"


def package(name="git", resource_id=None):
    return {"id": resource_id or name, "kind": "package", "identity": {"name": name}}


class Replies:
    def __init__(self, *replies):
        self.replies = iter(replies)
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        return next(self.replies)


class PackageSatisfactionTests(unittest.TestCase):
    def observe(self, resources, runner, **kwargs):
        return observe_package_requests(resources, host_id=HOST, observed_at=WHEN,
                                        runner=runner, **kwargs)

    def test_positive_satisfaction_without_direct_inventory_or_provider_claim(self):
        runner = Replies(QueryResult("ok", b"", 0), QueryResult("ok", b"", 0))
        batch = self.observe([package("virtual"), package("git")], runner)
        self.assertEqual(runner.calls, [QUERY + ("git", "virtual")] * 2)
        self.assertEqual(batch.coverage, ("virtual", "git"))
        self.assertEqual({fact.property for fact in batch.facts}, {"present"})
        for fact in batch.facts:
            self.assertEqual(fact.state, "known")
            self.assertIs(fact.value, True)
            self.assertEqual(fact.evidence_source, SOURCE)
            self.assertEqual(fact.host_id, HOST)
            self.assertEqual(fact.observed_at, WHEN)
        self.assertIn("provider_identity_version_reason_and_provenance_not_observed", batch.limitations)

    def test_unmet_is_unknown_even_when_other_requests_are_satisfied(self):
        runner = Replies(*[QueryResult("ok", b"missing\n", 127)] * 2)
        batch = self.observe([package("virtual"), package("missing")], runner)
        self.assertIs(batch.for_resource("virtual")[0].value, True)
        missing = batch.for_resource("missing")[0]
        self.assertEqual(missing.state, "unknown")
        self.assertIsNone(missing.value)
        self.assertEqual(missing.limitations, ("package_request_unsatisfied_or_database_unavailable",))
        self.assertIn("unmet_request_not_verified_absence", batch.limitations)

    def test_repeated_unmet_sets_ignore_native_line_order(self):
        runner = Replies(QueryResult("ok", b"git\nvirtual\n", 127),
                         QueryResult("ok", b"virtual\ngit\n", 127))
        batch = self.observe([package("git"), package("virtual")], runner)
        self.assertTrue(all(f.state == "unknown" for f in batch.facts))
        self.assertTrue(all(f.limitations == ("package_request_unsatisfied_or_database_unavailable",)
                            for f in batch.facts))

    def test_empty_selection_runs_no_queries(self):
        runner = Replies()
        batch = self.observe([], runner)
        self.assertEqual(runner.calls, [])
        self.assertEqual(batch.facts, ())
        self.assertEqual(batch.coverage, ())

    def test_aliases_deduplicate_physical_requests_without_dropping_coverage(self):
        resources = [package("git", "first"), package("git", "second")]
        runner = Replies(*[QueryResult("ok", b"", 0)] * 2)
        batch = self.observe(resources, runner)
        self.assertEqual(runner.calls, [QUERY + ("git",)] * 2)
        self.assertEqual(batch.coverage, ("first", "second"))
        self.assertEqual(len(batch.facts), 2)

    def test_boundaries_and_invalid_resources_fail_before_query(self):
        cases = [None, iter([package()]), [None], [package(), package()],
                 [package("--root")], [package("git>=1")], [package("git\n")],
                 [package("é")], [package("x" * 256)], [package("git", "x" * 129)],
                 [package() | {"kind": "service"}],
                 [package() | {"identity": {"name": "git", "root": "/tmp"}}],
                 [package("p" + str(i)) for i in range(257)]]
        for resources in cases:
            with self.subTest(resources=repr(resources)[:80]):
                runner = Replies()
                with self.assertRaisesRegex(ValueError, "^invalid_package_observation_request$"):
                    self.observe(resources, runner)
                self.assertEqual(runner.calls, [])
        with self.assertRaisesRegex(ValueError, "^invalid_package_observation_request$"):
            self.observe([package()], object())
        runner = Replies(*[QueryResult("ok", b"", 0)] * 2)
        batch = self.observe([package("p" + str(i)) for i in range(256)], runner)
        self.assertEqual(len(batch.facts), 256)
        self.assertEqual(len(runner.calls[0]), len(QUERY) + 256)

    def test_invalid_context_runs_no_queries(self):
        for host, when in (("bad", WHEN), (HOST, "bad"), (HOST, "")):
            runner = Replies()
            with self.assertRaisesRegex(ValueError, "^invalid_observation_context$"):
                observe_package_requests([package()], host_id=host, observed_at=when, runner=runner)
            self.assertEqual(runner.calls, [])

    def test_malformed_protocol_never_produces_positive_or_absent_facts(self):
        cases = [(0, b"git\n"), (0, b"\n"), (127, b""), (127, b"git"),
                 (127, b"git\r\n"), (127, b"git\n\n"), (127, b"git\ngit\n"),
                 (127, b" git\n"), (127, b"git \n"), (127, b"other\n"),
                 (127, b"\xff\n"), (127, b"git\x00\n"), (127, (SECRET + "\n").encode()),
                 (None, b""), (1, b""), (-9, b"")]
        for code, output in cases:
            with self.subTest(code=code, output=output):
                runner = Replies(QueryResult("ok", output, code))
                batch = self.observe([package()], runner)
                self.assertEqual(batch.facts[0].state, "unknown")
                self.assertEqual(batch.facts[0].limitations, ("malformed_package_satisfaction",))
                self.assertEqual(len(runner.calls), 1)
                self.assertNotIn(SECRET, json.dumps(batch.as_dict()))

    def test_changed_queries_invalidate_the_entire_sample(self):
        for outputs in ((b"", b"git\n"), (b"git\n", b"virtual\n"), (b"git\n", b"")):
            runner = Replies(*(QueryResult("ok", raw, 127 if raw else 0) for raw in outputs))
            batch = self.observe([package("git"), package("virtual")], runner)
            self.assertTrue(all(fact.state == "unknown" for fact in batch.facts))
            self.assertTrue(all(fact.limitations == ("package_satisfaction_changed",) for fact in batch.facts))

    def test_first_or_second_failure_invalidates_all_without_private_output(self):
        for failure in ("timeout", "output_limit", "permission_denied", "tool_unavailable", "command_failed"):
            for position in (0, 1):
                with self.subTest(failure=failure, position=position):
                    replies = [QueryResult("ok", b"", 0)] * position + [QueryResult(failure)]
                    runner = Replies(*replies)
                    batch = self.observe([package()], runner)
                    self.assertEqual(batch.facts[0].state, "unknown")
                    self.assertEqual(batch.facts[0].limitations, (failure,))
                    self.assertEqual(len(runner.calls), position + 1)
        for value, expected in ((None, "invalid_package_query_result"),
                                (QueryResult("ok", b"x" * (MAX_OUTPUT + 1), 0), "output_limit")):
            batch = self.observe([package()], Replies(value))
            self.assertEqual(batch.facts[0].limitations, (expected,))

    def test_runner_errors_are_fixed_diagnostics_and_cancellation_propagates(self):
        def failing(argv):
            raise RuntimeError(SECRET)
        batch = self.observe([package()], failing)
        self.assertEqual(batch.facts[0].limitations, ("package_query_unavailable",))
        self.assertNotIn(SECRET, json.dumps(batch.as_dict()))
        def cancelling(argv):
            raise KeyboardInterrupt(SECRET)
        with self.assertRaises(KeyboardInterrupt):
            self.observe([package()], cancelling)

    def test_request_copy_and_immutable_evidence_survive_caller_mutation(self):
        resources = [package()]
        calls = []
        def runner(argv):
            calls.append(argv)
            resources[0]["identity"]["name"] = SECRET
            return QueryResult("ok", b"", 0)
        batch = self.observe(resources, runner)
        self.assertEqual(calls, [QUERY + ("git",)] * 2)
        self.assertEqual(batch.facts[0].identity["name"], "git")
        with self.assertRaises(FrozenInstanceError):
            batch.facts[0].value = False
        with self.assertRaises(TypeError):
            batch.facts[0].identity["name"] = "changed"
        projected = batch.as_dict()
        projected["facts"][0]["identity"]["name"] = "changed"
        self.assertEqual(batch.facts[0].identity["name"], "git")


class CompletionPolicyTests(unittest.TestCase):
    def child(self, code, *, adapter=True, **kwargs):
        real_popen = subprocess.Popen
        seen = []
        def launch(argv, **settings):
            seen.append((argv, settings))
            return real_popen([sys.executable, "-c", code], **settings)
        with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch):
            if adapter:
                result = run_readonly(QUERY + ("git",))
            else:
                result = run_bounded((sys.executable,), environment=ENVIRONMENT, **kwargs)
        self.assertEqual(seen[0][1]["env"], ENVIRONMENT)
        self.assertEqual(seen[0][1]["stdin"], subprocess.DEVNULL)
        self.assertTrue(seen[0][1]["close_fds"])
        self.assertTrue(seen[0][1]["start_new_session"])
        self.assertNotIn("shell", seen[0][1])
        return result

    def test_only_closed_dependency_queries_can_launch(self):
        invalid = [QUERY, list(QUERY + ("git",)), ("pacman", "-T", "git"),
                   ("/usr/bin/pacman", "-S", "--", "git"),
                   ("/usr/bin/pacman", "-T", "--dbpath", "/tmp", "git"),
                   QUERY + ("--root",), QUERY + ("-",), QUERY + ("git>=1",),
                   QUERY + ("git", "git"), QUERY + ("git\n",), QUERY + (True,),
                   QUERY + ("git", 3), QUERY + tuple("p" + str(i) for i in range(257))]
        with patch("mpkg_manager.query_process.subprocess.Popen",
                   side_effect=AssertionError("invalid query reached process launch")) as spawn:
            for argv in invalid:
                with self.subTest(argv=repr(argv)[:60]):
                    self.assertEqual(run_readonly(argv).code, "invalid_query")
            spawn.assert_not_called()

    def test_adapter_uses_fixed_bounds_and_private_clean_environment(self):
        with patch("mpkg_manager.observe_packages.run_bounded", return_value=QueryResult("ok", b"", 0)) as run:
            run_readonly(QUERY + ("git",))
        run.assert_called_once_with(QUERY + ("git",), environment=ENVIRONMENT, timeout=10,
                                    max_output=MAX_OUTPUT, accepted_returncodes=(0, 127),
                                    require_empty_stderr=True)
        with patch.dict(os.environ, {"LD_PRELOAD": SECRET, "MANAGER_SECRET": SECRET}):
            result = self.child("import os; print(','.join(sorted(os.environ)))")
        self.assertEqual(result.code, "ok")
        self.assertNotIn(SECRET.encode(), result.output)
        self.assertNotIn(b"MANAGER_SECRET", result.output)

    def test_approved_nonzero_returns_private_stdout_but_default_still_fails(self):
        code = f"import sys; print({SECRET!r}); sys.exit(127)"
        allowed = self.child(code)
        self.assertEqual((allowed.code, allowed.returncode), ("ok", 127))
        self.assertEqual(allowed.output, (SECRET + "\n").encode())
        self.assertNotIn(SECRET, repr(allowed))
        default = self.child(code, adapter=False)
        self.assertEqual((default.code, default.returncode, default.output), ("command_failed", 127, b""))
        other = self.child("import sys; print('private'); sys.exit(7)")
        self.assertEqual((other.code, other.output), ("command_failed", b""))

    def test_stderr_is_rejected_only_under_explicit_policy(self):
        for code in (0, 127):
            script = f"import sys; print('git'); print({SECRET!r}, file=sys.stderr); sys.exit({code})"
            strict = self.child(script)
            self.assertEqual(strict.code, "command_failed")
            self.assertEqual(strict.output, b"")
            self.assertNotIn(SECRET, repr(strict))
        permissive = self.child(f"import sys; print('git'); print({SECRET!r}, file=sys.stderr)", adapter=False)
        self.assertEqual((permissive.code, permissive.output), ("ok", b"git\n"))

    def test_policy_validation_precedes_spawn_and_rejects_bool_integer_aliases(self):
        invalid = [dict(accepted_returncodes=value) for value in
                   (None, (), [0, 127], (False, 127), (0, True), (0, 0), (127,),
                    (0, -1), (0, 256), (0, 1.0), tuple(range(257)))]
        invalid += [dict(require_empty_stderr=value) for value in (0, 1, None, "yes")]
        with patch("mpkg_manager.query_process.subprocess.Popen",
                   side_effect=AssertionError("invalid policy reached process launch")) as spawn:
            for policy in invalid:
                with self.subTest(policy=policy), self.assertRaisesRegex(ValueError, "^invalid_query_completion_policy$"):
                    run_bounded((sys.executable,), environment=ENVIRONMENT, **policy)
            spawn.assert_not_called()

    def test_accepted_nonzero_does_not_bypass_output_or_time_bounds(self):
        limited = self.child("import sys; print('x' * 2000); sys.exit(127)", adapter=False,
                             max_output=50, accepted_returncodes=(0, 127))
        self.assertEqual((limited.code, limited.output), ("output_limit", b""))
        timed = self.child("import time; time.sleep(2)", adapter=False,
                           timeout=0.1, accepted_returncodes=(0, 127))
        self.assertEqual((timed.code, timed.output), ("timeout", b""))

    def test_late_accepted_completion_discards_stdout(self):
        real_popen, real_clock = subprocess.Popen, time.monotonic
        started, finished = [None], [False]
        def clock():
            current = real_clock()
            if started[0] is None:
                started[0] = current
            return started[0] + 1 if finished[0] else current
        def launch(argv, **settings):
            process = real_popen([sys.executable, "-c", "import sys; print('git'); sys.exit(127)"], **settings)
            real_wait = process.wait
            def wait(*args, **kwargs):
                result = real_wait(*args, **kwargs)
                finished[0] = True
                return result
            process.wait = wait
            return process
        with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch), \
                patch("mpkg_manager.query_process.time.monotonic", side_effect=clock):
            result = run_bounded((sys.executable,), environment=ENVIRONMENT, timeout=1,
                                 accepted_returncodes=(0, 127))
        self.assertEqual((result.code, result.output, result.returncode), ("timeout", b"", 127))

    def test_cancellation_during_accepted_cleanup_preserves_exception_and_closes_pipes(self):
        real_popen, real_kill = subprocess.Popen, os.killpg
        processes, calls = [], []
        interrupted = KeyboardInterrupt(SECRET)
        def launch(argv, **settings):
            process = real_popen([sys.executable, "-c", "import sys; print('git'); sys.exit(127)"], **settings)
            processes.append(process)
            return process
        def kill(group, signum):
            calls.append((group, signum))
            if len(calls) == 1:
                raise interrupted
            return real_kill(group, signum)
        with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch), \
                patch("mpkg_manager.query_process.os.killpg", side_effect=kill):
            with self.assertRaises(KeyboardInterrupt) as caught:
                run_readonly(QUERY + ("git",))
        self.assertIs(caught.exception, interrupted)
        self.assertEqual(calls, [(processes[0].pid, 9)] * 2)
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

    def test_accepted_nonzero_stops_descendants_with_closed_output_pipes(self):
        real_popen = subprocess.Popen
        processes = []
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-appear"
            settled_read, settled_write = os.pipe()
            code = f"""
import os, time
ready_read, ready_write = os.pipe()
child = os.fork()
if child:
    os.close(ready_write)
    assert os.read(ready_read, 1) == b'x'
    os.write(1, b'git\\n')
    os._exit(127)
os.close(ready_read)
os.close(1)
os.close(2)
os.write(ready_write, b'x')
os.close(ready_write)
time.sleep(0.4)
open({str(marker)!r}, 'w').write('effect')
os._exit(0)
"""
            def launch(argv, **settings):
                settings["pass_fds"] = (settled_write,)
                process = real_popen([sys.executable, "-c", code], **settings)
                processes.append(process)
                return process
            try:
                with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch):
                    result = run_readonly(QUERY + ("git",))
                os.close(settled_write)
                settled_write = None
                self.assertEqual((result.code, result.output, result.returncode), ("ok", b"git\n", 127))
                with selectors.DefaultSelector() as selector:
                    selector.register(settled_read, selectors.EVENT_READ)
                    self.assertTrue(selector.select(1), "fixture descendants failed to settle")
                self.assertEqual(os.read(settled_read, 1), b"")
                self.assertFalse(marker.exists())
            finally:
                os.close(settled_read)
                if settled_write is not None:
                    os.close(settled_write)
                for process in processes:
                    try:
                        os.killpg(process.pid, 9)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1)


if __name__ == "__main__":
    unittest.main()
