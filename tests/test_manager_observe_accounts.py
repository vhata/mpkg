"""Exact local/NSS protocol stubs and owned Python children only."""
from dataclasses import FrozenInstanceError
import json
import sys
import unittest
from unittest.mock import patch

from mpkg_manager.observe_accounts import (COLLECTION_SECONDS, ENVIRONMENT, MAX_OUTPUT,
    MAX_RESOURCES, QUERY_SECONDS, observe_accounts, run_readonly)
from mpkg_manager.query_process import QueryResult, run_bounded


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T12:00:00Z"
SECRET = "SECRET_HASH_OR_GECOS_SENTINEL"
USER = f"worker:{SECRET}:1201:1202:{SECRET}:/srv/worker:/usr/bin/nologin\n".encode()
GROUP = f"workers:{SECRET}:1202:ignored_member\n".encode()


def resource(kind="user", name="worker", identity=None):
    return {"id": name, "kind": kind, "identity": {"name": name if identity is None else identity}}


class Queries:
    def __init__(self):
        self.calls = []
        self.override = None

    def __call__(self, argv, *, timeout):
        self.calls.append((argv, timeout))
        if self.override:
            result = self.override(argv, len(self.calls))
            if result is not None:
                return result
        database, key = argv[-2:]
        if database == "passwd" and key in ("worker", "1201"):
            return QueryResult("ok", USER, 0)
        if database == "group" and key in ("workers", "1202"):
            return QueryResult("ok", GROUP, 0)
        raise AssertionError("Unexpected fixture query")


def facts(batch, name="worker"):
    return {fact.property: fact for fact in batch.for_resource(name)}


class AccountObservationTests(unittest.TestCase):
    def observe(self, resources=None, runner=None, **kwargs):
        return observe_accounts([resource()] if resources is None else resources,
            **({"host_id": HOST, "observed_at": WHEN, "runner": Queries() if runner is None else runner} | kwargs))

    def test_positive_user_and_group_require_local_default_name_numeric_and_repeat(self):
        queries = Queries()
        batch = self.observe([resource(), resource("group", "workers")], queries)
        self.assertEqual(len(queries.calls), 24)
        first = queries.calls[:8]
        self.assertEqual(first, queries.calls[8:16])
        self.assertEqual([call[0] for call in first], [
            ("/usr/bin/getent", "--service=files", "--", "passwd", "worker"),
            ("/usr/bin/getent", "--", "passwd", "worker"),
            ("/usr/bin/getent", "--service=files", "--", "passwd", "1201"),
            ("/usr/bin/getent", "--", "passwd", "1201"),
            ("/usr/bin/getent", "--service=files", "--", "group", "1202"),
            ("/usr/bin/getent", "--", "group", "1202"),
            ("/usr/bin/getent", "--service=files", "--", "group", "workers"),
            ("/usr/bin/getent", "--", "group", "workers")])
        self.assertTrue(all(0 < timeout <= QUERY_SECONDS for _, timeout in queries.calls))
        observed = facts(batch)
        self.assertIs(observed["present"].value, True)
        self.assertEqual(observed["uid"].value, 1201)
        self.assertEqual(observed["gid"].value, 1202)
        self.assertEqual(observed["home"].value, "/srv/worker")
        self.assertEqual(observed["shell"].value, "/usr/bin/nologin")
        self.assertEqual(observed["primary_group"].value, "workers")
        self.assertEqual(observed["groups"].state, "unknown")
        self.assertIs(facts(batch, "workers")["present"].value, True)
        self.assertEqual(facts(batch, "workers")["members"].state, "unknown")
        self.assertNotIn(SECRET, json.dumps(batch.as_dict()))
        self.assertNotIn("ignored_member", json.dumps(batch.as_dict()))

    def test_local_and_default_name_or_reverse_conflicts_never_claim_presence(self):
        for position in (1, 2, 3, 4, 9, 10, 11, 12):
            with self.subTest(position=position):
                runner = Queries()
                runner.override = lambda argv, count: QueryResult("ok", USER.replace(b"1201", b"1301"), 0) if count == position else None
                observed = facts(self.observe(runner=runner))
                self.assertEqual(observed["present"].state, "unknown")
                self.assertIsNone(observed["present"].value)

    def test_primary_group_conflict_does_not_erase_other_stable_user_properties(self):
        runner = Queries()
        runner.override = lambda argv, count: QueryResult("ok", GROUP.replace(b"1202", b"1302"), 0) if count == 6 else None
        observed = facts(self.observe(runner=runner))
        self.assertIs(observed["present"].value, True)
        self.assertEqual(observed["home"].value, "/srv/worker")
        self.assertEqual(observed["primary_group"].state, "unknown")

    def test_primary_group_absence_is_unknown_and_never_synthesized_from_gid(self):
        runner = Queries()
        runner.override = lambda argv, count: QueryResult("ok", b"", 2) if argv[-2] == "group" else None
        observed = facts(self.observe(runner=runner))
        self.assertIs(observed["present"].value, True)
        self.assertEqual(observed["primary_group"].state, "unknown")
        self.assertEqual(observed["primary_group"].limitations, ("account_not_found_or_unavailable",))

    def test_missing_local_default_or_numeric_identity_stays_unknown_not_absent(self):
        for position in (1, 2, 3, 4):
            runner = Queries()
            runner.override = lambda argv, count: QueryResult("ok", b"", 2) if count == position else None
            observed = facts(self.observe(runner=runner))
            self.assertEqual(observed["present"].state, "unknown")
            self.assertIsNone(observed["present"].value)

    def test_property_change_between_complete_samples_invalidates_user(self):
        runner = Queries()
        runner.override = lambda argv, count: QueryResult("ok", USER.replace(b"/srv/worker", b"/srv/changed"), 0) if count > 8 and argv[-2] == "passwd" else None
        observed = facts(self.observe(runner=runner))
        self.assertEqual(observed["present"].limitations, ("account_properties_changed",))
        self.assertEqual(observed["home"].state, "unknown")

    def test_ignored_private_fields_and_additive_members_do_not_become_scalar_constraints(self):
        runner = Queries()
        def changed(argv, count):
            if count <= 8:
                return None
            raw = USER if argv[-2] == "passwd" else GROUP
            return QueryResult("ok", raw.replace(SECRET.encode(), b"OTHER_PRIVATE")
                               .replace(b"ignored_member", b"new_member,another"), 0)
        runner.override = changed
        batch = self.observe(runner=runner)
        self.assertIs(facts(batch)["present"].value, True)
        self.assertEqual(facts(batch)["primary_group"].value, "workers")
        self.assertEqual(facts(batch)["groups"].state, "unknown")
        self.assertNotIn("OTHER_PRIVATE", json.dumps(batch.as_dict()))
        self.assertNotIn("new_member", json.dumps(batch.as_dict()))

    def test_unsupported_paths_leave_only_those_properties_unknown(self):
        runner = Queries()
        runner.override = lambda argv, count: QueryResult("ok", USER.replace(b"/srv/worker", b"relative").replace(b"/usr/bin/nologin", b""), 0) if argv[-2] == "passwd" else None
        observed = facts(self.observe(runner=runner))
        self.assertIs(observed["present"].value, True)
        self.assertEqual(observed["home"].state, "unknown")
        self.assertEqual(observed["shell"].state, "unknown")
        self.assertEqual(observed["primary_group"].value, "workers")

    def test_strict_record_protocol_refuses_multiple_truncated_control_or_invalid_ids(self):
        malformed = [b"", USER + USER, USER[:-1], USER.replace(b"worker:", b"elsewhere:", 1),
                     USER.replace(b"1201", b"01201"), USER.replace(b"1201", b"4294967295"),
                     USER.replace(b"1202", b"-1"), USER.replace(b"/srv", b"\r/srv"),
                     USER.replace(b"/srv", b"\xff/srv"), b"x" * (MAX_OUTPUT + 1)]
        for raw in malformed:
            runner = lambda argv, timeout: QueryResult("ok", raw, 0)
            self.assertEqual(facts(self.observe(runner=runner))["present"].state, "unknown")
        for result in (QueryResult("ok", USER, 2), QueryResult("ok", USER, None), QueryResult("ok", USER, 3), object()):
            self.assertEqual(facts(self.observe(runner=lambda argv, timeout: result))["present"].state, "unknown")

    def test_failure_codes_and_arbitrary_runner_errors_are_private(self):
        for code in ("timeout", "output_limit", "command_failed", "permission_denied", "tool_unavailable"):
            batch = self.observe(runner=lambda argv, timeout: QueryResult(code))
            self.assertEqual(facts(batch)["present"].limitations, (code,))
        def failed(argv, *, timeout):
            raise RuntimeError(SECRET)
        batch = self.observe(runner=failed)
        self.assertEqual(facts(batch)["present"].limitations, ("account_query_unavailable",))
        self.assertNotIn(SECRET, json.dumps(batch.as_dict()))

    def test_numeric_names_are_explicitly_unknown_without_issuing_numeric_lookups(self):
        runner = Queries()
        batch = self.observe([resource(identity="123"), resource("group", "001")], runner)
        self.assertEqual(runner.calls, [])
        self.assertEqual(facts(batch)["present"].limitations, ("numeric_account_name_unsupported",))

    def test_validation_and_empty_batch_never_run_queries(self):
        runner = Queries()
        invalid = [[resource(), resource()], [resource(kind="service")],
                   [resource(identity="--help")], [{**resource(), "identity": {"wrong": "worker"}}],
                   [resource(name=str(index)) for index in range(MAX_RESOURCES + 1)]]
        for resources in invalid:
            with self.assertRaisesRegex(ValueError, "^invalid_account_observation_request$"):
                self.observe(resources, runner)
        self.assertEqual(self.observe([], runner).coverage, ())
        self.assertEqual(runner.calls, [])
        with self.assertRaisesRegex(ValueError, "^invalid_observation_context$"):
            self.observe(runner=runner, host_id="invalid")
        target = resource()
        target.update(checks=["outside-context"], consumers=["external"])
        self.assertIs(facts(self.observe([target], runner))["present"].value, True)

    def test_deadline_stops_further_scheduling_and_rejects_late_results(self):
        clock = [0.0]
        runner = Queries()
        def late(argv, *, timeout):
            result = runner(argv, timeout=timeout)
            clock[0] = COLLECTION_SECONDS
            return result
        with patch("mpkg_manager.observe_accounts.time.monotonic", side_effect=lambda: clock[0]):
            batch = self.observe([resource(), resource("group", "workers")], late)
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(facts(batch)["present"].limitations, ("account_collection_timeout",))
        self.assertEqual(facts(batch, "workers")["present"].limitations, ("account_collection_timeout",))

    def test_deadline_caps_final_query_allowance_and_cancellation_propagates(self):
        clock = [0.0]
        runner = Queries()
        def advance(argv, *, timeout):
            result = runner(argv, timeout=timeout)
            clock[0] += 29 if len(runner.calls) == 1 else 1
            return result
        with patch("mpkg_manager.observe_accounts.time.monotonic", side_effect=lambda: clock[0]):
            batch = self.observe(runner=advance)
        self.assertEqual([timeout for _, timeout in runner.calls], [2, 1])
        self.assertEqual(facts(batch)["present"].state, "unknown")
        def cancelled(argv, *, timeout):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.observe(runner=cancelled)

    def test_deadline_during_primary_group_probe_cannot_leave_partially_completed_user_known(self):
        for position in (5, 16):
            clock = [0.0]
            runner = Queries()
            def late(argv, *, timeout):
                result = runner(argv, timeout=timeout)
                if len(runner.calls) == position:
                    clock[0] = COLLECTION_SECONDS
                return result
            with patch("mpkg_manager.observe_accounts.time.monotonic", side_effect=lambda: clock[0]):
                batch = self.observe(runner=late)
            self.assertEqual(len(runner.calls), position)
            self.assertEqual(facts(batch)["present"].limitations, ("account_collection_timeout",))

    def test_evidence_is_immutable_and_uses_one_collection_start(self):
        with patch("mpkg_manager.observe_accounts.utc_now", return_value=WHEN) as clock:
            batch = self.observe(observed_at=None)
        clock.assert_called_once_with()
        self.assertEqual({fact.observed_at for fact in batch.facts}, {WHEN})
        batch.as_dict()["facts"].clear()
        self.assertTrue(batch.facts)
        with self.assertRaises(FrozenInstanceError):
            batch.coverage = ()

    def test_closed_query_policy_bounds_environment_and_stderr(self):
        valid = ("/usr/bin/getent", "--service=files", "--", "passwd", "worker")
        with patch("mpkg_manager.observe_accounts.run_bounded", return_value=QueryResult("ok", USER, 0)) as run:
            self.assertEqual(run_readonly(valid).code, "ok")
        self.assertEqual(run.call_args.kwargs, {"environment": ENVIRONMENT, "timeout": 2,
            "max_output": MAX_OUTPUT, "accepted_returncodes": (0, 2), "require_empty_stderr": True})
        invalid = [list(valid), ("/usr/bin/getent", "passwd"), valid + ("other",),
                   ("/usr/bin/getent", "--service=ldap", "--", "passwd", "worker"),
                   ("/usr/bin/getent", "--", "shadow", "worker"),
                   ("/usr/bin/sudo", *valid), (*valid[:-1], "--help"), (*valid[:-1], "4294967295")]
        with patch("mpkg_manager.observe_accounts.run_bounded", side_effect=AssertionError("Forbidden query")):
            for argv in invalid:
                self.assertEqual(run_readonly(argv).code, "invalid_query")
            for timeout in (0, 3, True, float("nan")):
                self.assertEqual(run_readonly(valid, timeout=timeout).code, "invalid_query")

    def test_owned_python_children_verify_stderr_failure_output_limit_and_timeout(self):
        # The transport executes only our Python children, never getent or NSS.
        def transport(argv, **kwargs):
            return run_bounded((sys.executable, "-c", source), **kwargs)
        for source, expected in (("import sys;print('PRIVATE',file=sys.stderr)", "command_failed"),
                                 ("print('x'*20000)", "output_limit"),
                                 ("import time;time.sleep(5)", "timeout")):
            with patch("mpkg_manager.observe_accounts.run_bounded", transport):
                result = run_readonly(("/usr/bin/getent", "--", "passwd", "worker"),
                                      timeout=0.1 if expected == "timeout" else 1)
            self.assertEqual(result.code, expected)
            self.assertEqual(result.output, b"")


if __name__ == "__main__":
    unittest.main()
