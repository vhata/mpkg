"""Fake recovery evidence and owned fixtures; no live system inspection."""
from dataclasses import replace
from contextlib import contextmanager
import json
import multiprocessing
import os
import sqlite3
import unittest
from unittest.mock import patch
import uuid

import test_manager_attempt_supervision as fixtures
from mpkg_manager import attempt_recovery as recovery
from mpkg_manager import attempt_supervisor as supervisor
from mpkg_manager import attempt_worker as worker
from mpkg_manager import attempt_journal as journal
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_helper import BoundaryError, HostBoundary, handle_request
from mpkg_manager.store import HostStore, StoreError, _TRIGGERS, _json


SECRET = "PRIVATE_RECOVERY_SENTINEL"
NEW_BOOT = "32345678-1234-4234-8234-123456789abc"


def quiet(request):
    return recovery.RecoveryEvidence(request, "settled", "inactive", "empty",
        "idle" if request.package_lock_required else "not_applicable",
        tuple((identity, "quiescent") for identity in request.engine_ids),
        tuple((identity, "quiescent") for identity in request.resource_ids))


def _owned_recovery(arguments, attempt_id, sequence, started, release, results):
    def collect(request):
        started.set()
        if not release.wait(5):
            raise RuntimeError("fixture collection interrupted")
        return quiet(request)
    try:
        result = recovery.AttemptRecovery(**arguments, _collector=collect).recover(
            attempt_id, expected_sequence=sequence)
        results.put(result["supervision"]["recovery"])
    except Exception as error:
        results.put(getattr(error, "code", "fixture_failure"))


class RecoveryTests(unittest.TestCase):
    setUp = fixtures.SupervisionTests.setUp
    create = fixtures.SupervisionTests.create
    dispatch = fixtures.SupervisionTests.dispatch
    read = fixtures.SupervisionTests.read
    record_wire = fixtures.SupervisionTests.record_wire
    run_worker = fixtures.SupervisionTests.run_worker

    def assert_error(self, code, callback):
        with self.assertRaises((recovery.RecoveryError, supervisor.SupervisionError,
                journal.JournalError, StoreError, BoundaryError)) as error:
            callback()
        self.assertEqual(error.exception.code, code)
        self.assertNotIn(SECRET, str(error.exception))

    def recover(self, attempt, collector=quiet, **changes):
        return recovery.AttemptRecovery(**(self.arguments | changes), _collector=collector).recover(
            attempt["attempt_id"], expected_sequence=self.read(attempt)["sequence"])

    def unknown(self):
        attempt = self.create()
        self.dispatch(attempt)
        supervisor._append(self.store, attempt["attempt_id"], "worker_started", "owned")
        supervisor._append(self.store, attempt["attempt_id"], "action_started", "started",
                           attempt["actions"][0]["action_id"])
        return attempt

    def blocked(self, attempt, collector):
        result = self.recover(attempt, collector)
        self.assertEqual(result["supervision"]["recovery"], "blocked")
        self.assertFalse(result["supervision"]["released"])
        self.assert_error("attempt_recovery_required", lambda: self.store.record_intent(fixtures.PACKAGES, 1))
        return result

    def test_quiescence_releases_ownership_without_finishing_unknown_effects(self):
        attempt = self.unknown()
        before = self.read(attempt)
        result = self.recover(attempt)
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["finished"])
        self.assertEqual(result["actions"], before["actions"])
        self.assertTrue(result["supervision"]["released"])
        self.assertEqual(result["events"][-1]["outcome"], "quiescent")
        self.store.record_intent(fixtures.PACKAGES, 1)
        retained = self.read(attempt)
        self.assertEqual(retained["state"], "unknown")
        self.assertEqual(retained["revision"], 1)
        self.assertEqual(retained["decision_state"], "superseded")

    def test_retry_requires_distinct_plan_and_attempt_and_retains_unknown_predecessor(self):
        attempt = self.unknown()
        self.recover(attempt)
        selected = [item["stable_resource_id"] for item in attempt["actions"]]
        new = journal._fixture_plan(self.store, expected_revision=1, stable_resource_ids=selected)
        identity = journal.WorkerIdentity(os.geteuid(), os.geteuid(), fixtures.BOOT, str(uuid.uuid4()))
        writer = journal._FixtureJournal(self.store)
        self.assert_error("attempt_plan_already_used", lambda: writer.create(
            replace(new, plan_id=attempt["plan_id"]), identity, stable_resource_ids=selected,
            predecessor=attempt["attempt_id"]))
        retry = writer.create(new, identity, stable_resource_ids=selected,
                              predecessor=attempt["attempt_id"]).as_dict()
        self.assertNotEqual(retry["attempt_id"], attempt["attempt_id"])
        self.assertEqual(retry["predecessor"], attempt["attempt_id"])
        self.assertEqual(retry["state"], "planned")
        self.assertEqual(self.read(attempt)["state"], "unknown")
        with HostStore.open_readonly(self.directory, fixtures.HOST, owner_uid=os.geteuid()) as reopened:
            self.assertEqual(journal.read_attempt(reopened, retry["attempt_id"]).as_dict(), retry)

    def test_failed_worker_result_is_preserved_after_recovery(self):
        attempt = self.create()
        self.dispatch(attempt)
        self.run_worker(attempt, runner=lambda: worker.ChildOutcome("failed"))
        before = self.read(attempt)
        result = self.recover(attempt)
        self.assertEqual(result["state"], "failed")
        self.assertTrue(result["finished"])
        self.assertEqual(result["actions"], before["actions"])
        self.assertTrue(result["supervision"]["released"])

    def test_launch_rejection_still_requires_evidence_and_does_not_invent_attempted_work(self):
        attempt = self.create()
        self.dispatch(attempt, fixtures.FakeTransport("rejected"))
        self.assert_error("attempt_recovery_required", lambda: self.store.record_intent(fixtures.PACKAGES, 1))
        result = self.recover(attempt, lambda request: replace(quiet(request), unit="absent"))
        self.assertEqual(result["state"], "planned")
        self.assertFalse(any(action["attempted"] for action in result["actions"]))

    def test_free_host_lock_and_dead_worker_do_not_override_active_child_or_native_lock(self):
        attempt = self.unknown()
        with supervisor._mutation_lock(self.lock, os.geteuid()):
            pass
        for field, state in (("unit", "active"), ("cgroup", "populated"),
                             ("package_lock", "held"), ("package_lock", "unavailable")):
            with self.subTest(field=field):
                self.blocked(attempt, lambda request: replace(quiet(request), **{field: state}))
        self.assertEqual(self.read(attempt)["state"], "unknown")

    def test_pending_dispatch_blocks_even_absent_unit_and_empty_cgroup(self):
        attempt = self.create()
        def pending(spec):
            self.blocked(attempt, lambda request: replace(quiet(request), unit="absent", dispatch="pending"))
            return supervisor.LaunchResult("unknown")
        self.dispatch(attempt, fixtures.FakeTransport(callback=pending))
        self.assertFalse(self.read(attempt)["supervision"]["released"])

    def test_reboot_is_not_quiescence_and_requires_all_current_evidence(self):
        attempt = self.unknown()
        result = self.recover(attempt, lambda request: replace(quiet(request), cgroup="unavailable"),
                              _fixture_boot=NEW_BOOT)
        self.assertEqual(result["supervision"]["recovery"], "blocked")
        result = self.recover(attempt, lambda request: replace(quiet(request), unit="absent"),
                              _fixture_boot=NEW_BOOT)
        self.assertEqual(result["state"], "unknown")
        raw = self.store._db.execute("SELECT outcome FROM attempt_events ORDER BY rowid DESC LIMIT 1").fetchone()[0]
        self.assertEqual(json.loads(raw)["original_boot_id"], fixtures.BOOT)
        self.assertEqual(json.loads(raw)["current_boot_id"], NEW_BOOT)

    def test_unavailable_or_slow_collector_records_only_sanitized_blocked_evidence(self):
        attempt = self.unknown()
        def unavailable(request):
            raise RuntimeError(SECRET)
        result = self.blocked(attempt, unavailable)
        with patch.object(recovery.time, "monotonic", side_effect=[0, recovery.EVIDENCE_SECONDS + 1]):
            self.blocked(attempt, quiet)
        self.assertNotIn(SECRET, json.dumps(result) + repr(result))
        self.assertNotIn(SECRET, str(self.store._db.execute("SELECT outcome FROM attempt_events").fetchall()))

    def test_evidence_must_be_fresh_complete_and_bound_to_exact_challenge(self):
        attempt = self.unknown()
        captures = []
        self.blocked(attempt, lambda request: captures.append(quiet(request)) or
                     replace(quiet(request), dispatch="pending"))
        self.assert_error("recovery_evidence_mismatch", lambda: self.recover(attempt, lambda request: captures[0]))
        for alter in (lambda value: replace(value, resources=()),
                      lambda value: replace(value, package_lock="not_applicable"),
                      lambda value: replace(value, request=replace(value.request, current_boot_id=NEW_BOOT)),
                      lambda value: replace(value, resources=((str(uuid.uuid4()), "quiescent"),))):
            with self.subTest(alter=alter), self.assertRaises(recovery.RecoveryError):
                self.recover(attempt, lambda request: alter(quiet(request)))
        self.assertFalse(self.read(attempt)["supervision"]["released"])

    def test_old_worker_and_late_launch_writes_are_sealed_after_quiescence(self):
        attempt = self.create()
        self.dispatch(attempt)
        self.recover(attempt)
        self.assert_error("attempt_recovered", lambda: self.run_worker(attempt))
        for kind, outcome in (("launch_result", "accepted"), ("worker_started", "owned")):
            self.assert_error("attempt_transition_invalid", lambda: supervisor._append(
                self.store, attempt["attempt_id"], kind, outcome))
        self.assert_error("recovery_not_required", lambda: self.recover(attempt))

    def test_recovery_holds_host_lock_but_never_a_database_transaction_during_collection(self):
        attempt = self.unknown()
        observed = []
        def inspect(request):
            self.assert_error("mutation_busy", lambda: self.recover(attempt))
            self.assert_error("attempt_recovery_required", lambda: self.store.relinquish(
                [attempt["actions"][0]["stable_resource_id"]], 1))
            with sqlite3.connect(self.directory / "state.sqlite3", timeout=0) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("ROLLBACK")
            with HostStore.open_readonly(self.directory, fixtures.HOST, owner_uid=os.geteuid()) as other:
                observed.append(journal.read_attempt(other, attempt["attempt_id"]).as_dict()["state"])
            return quiet(request)
        self.recover(attempt, inspect)
        self.assertEqual(observed, ["unknown"])

    def test_caller_death_does_not_allow_recovery_over_live_owned_worker(self):
        attempt = self.create()
        context = multiprocessing.get_context("fork")
        dispatched, started, release = context.Event(), context.Event(), context.Event()
        results = context.Queue()
        owned = context.Process(target=fixtures._owned_worker,
            args=(self.arguments, attempt["attempt_id"], dispatched, started, release, results))
        caller = context.Process(target=fixtures._disconnected_caller,
            args=(self.arguments, attempt["attempt_id"], dispatched))
        owned.start()
        caller.start()
        try:
            caller.join(5)
            self.assertEqual(caller.exitcode, 0)
            self.assertTrue(started.wait(5))
            self.assertTrue(owned.is_alive())
            collected = []
            self.assert_error("mutation_busy", lambda: self.recover(attempt,
                lambda request: collected.append(request) or quiet(request)))
            self.assertEqual(collected, [])
            self.assertEqual(self.read(attempt)["state"], "unknown")
            release.set()
            owned.join(5)
            self.assertEqual(owned.exitcode, 0)
            self.assertEqual(results.get(timeout=1), ("completed", "observed-complete"))
            self.assert_error("recovery_not_required", lambda: self.recover(attempt))
        finally:
            release.set()
            for process in (caller, owned):
                if process.is_alive():
                    process.terminate()
                process.join(5)
                process.close()
            results.close()
            results.join_thread()

    def test_concurrent_process_recovery_has_one_owner_and_one_disposition(self):
        attempt = self.unknown()
        sequence = self.read(attempt)["sequence"]
        context = multiprocessing.get_context("fork")
        started, release, results = context.Event(), context.Event(), context.Queue()
        owner = context.Process(target=_owned_recovery,
            args=(self.arguments, attempt["attempt_id"], sequence, started, release, results))
        owner.start()
        try:
            self.assertTrue(started.wait(5))
            self.assert_error("mutation_busy", lambda: self.recover(attempt))
            self.assertEqual(self.read(attempt)["sequence"], sequence)
            release.set()
            owner.join(5)
            self.assertEqual(owner.exitcode, 0)
            self.assertEqual(results.get(timeout=1), "quiescent")
            self.assertEqual(self.read(attempt)["sequence"], sequence + 1)
            self.assert_error("recovery_sequence_conflict", lambda: recovery.AttemptRecovery(
                **self.arguments, _collector=quiet).recover(attempt["attempt_id"], expected_sequence=sequence))
        finally:
            release.set()
            if owner.is_alive():
                owner.terminate()
            owner.join(5)
            owner.close()
            results.close()
            results.join_thread()

    def test_disposition_never_kills_deletes_locks_or_starts_a_process(self):
        attempt = self.unknown()
        inode = self.lock.stat().st_ino
        with patch("os.kill", side_effect=AssertionError("kill attempted")), \
                patch("os.unlink", side_effect=AssertionError("unlink attempted")), \
                patch("os.remove", side_effect=AssertionError("remove attempted")), \
                patch("subprocess.Popen", side_effect=AssertionError("process attempted")):
            result = self.recover(attempt)
        self.assertTrue(result["supervision"]["released"])
        self.assertEqual(self.lock.stat().st_ino, inode)

    def test_interruption_during_collection_leaves_original_gate_and_journal(self):
        attempt = self.unknown()
        before = self.read(attempt)
        def interrupted(request):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.recover(attempt, interrupted)
        self.assertEqual(self.read(attempt), before)
        self.assert_error("attempt_recovery_required", lambda: self.store.record_intent(fixtures.PACKAGES, 1))

    def test_recording_and_authority_remain_blocked_until_recovery_commit(self):
        attempt = self.unknown()
        before = (self.store.current(), self.store.history())
        def inspect(request):
            self.assert_error("attempt_recovery_required", lambda: self.store.record_intent(fixtures.PACKAGES, 1))
            self.assert_error("attempt_recovery_required", lambda: self.store.adopt(fixtures.PACKAGES, 1, ["one"]))
            response = json.loads(handle_request(self.record_wire(), boundary=self.boundary))
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], "mutation_busy")
            return quiet(request)
        self.recover(attempt, inspect)
        self.assertEqual((self.store.current(), self.store.history()), before)
        response = json.loads(handle_request(self.record_wire(), boundary=self.boundary))
        self.assertTrue(response["ok"])

    def test_journal_sequence_change_during_collection_invalidates_evidence(self):
        attempt = self.unknown()
        def inspect(request):
            supervisor._append(self.store, attempt["attempt_id"], "worker_completed", "unresolved")
            return quiet(request)
        self.assert_error("attempt_sequence_conflict", lambda: self.recover(attempt, inspect))
        self.assertFalse(self.read(attempt)["supervision"]["released"])

    def test_before_commit_failure_keeps_durable_gate_and_no_partial_evidence(self):
        attempt = self.unknown()
        sequence = self.read(attempt)["sequence"]
        with patch.object(HostStore, "_commit", side_effect=sqlite3.OperationalError(SECRET)):
            self.assert_error("recovery_outcome_unknown", lambda: self.recover(attempt))
        self.assertEqual(self.read(attempt)["sequence"], sequence)
        self.assertFalse(self.read(attempt)["supervision"]["released"])
        self.recover(attempt)

    def test_committed_disposition_survives_lost_response_without_replay(self):
        attempt = self.unknown()
        commit = HostStore._commit
        def lost(store):
            commit(store)
            raise OSError(SECRET)
        with patch.object(HostStore, "_commit", lost):
            self.assert_error("recovery_outcome_unknown", lambda: self.recover(attempt))
        result = self.read(attempt)
        self.assertTrue(result["supervision"]["released"])
        self.assertEqual(result["state"], "unknown")
        self.assert_error("recovery_not_required", lambda: self.recover(attempt))

    def test_post_commit_lock_policy_and_store_cleanup_failures_are_private_and_uncertain(self):
        for name in ("lock", "policy", "store"):
            with self.subTest(cleanup=name):
                attempt = self.unknown()
                if name == "store":
                    original = HostStore.__exit__
                    def failed_store_close(store, *arguments):
                        original(store, *arguments)
                        raise OSError(SECRET)
                    patched = patch.object(HostStore, "__exit__", failed_store_close)
                else:
                    attribute = "_mutation_lock" if name == "lock" else "load_host_policy"
                    original = getattr(recovery, attribute)
                    @contextmanager
                    def failed_close(*arguments, **keywords):
                        with original(*arguments, **keywords) as value:
                            yield value
                        raise OSError(SECRET)
                    patched = patch.object(recovery, attribute, failed_close)
                with patched:
                    self.assert_error("recovery_outcome_unknown", lambda: self.recover(attempt))
                with HostStore.open_readonly(self.directory, fixtures.HOST, owner_uid=os.geteuid()) as reopened:
                    result = journal.read_attempt(reopened, attempt["attempt_id"]).as_dict()
                self.assertTrue(result["supervision"]["released"])
                self.assertEqual(result["state"], "unknown")
                self.assertNotIn(SECRET, json.dumps(result))

    def test_precommit_untyped_failure_is_sanitized_without_releasing_ownership(self):
        attempt = self.unknown()
        before = self.read(attempt)
        with patch.object(recovery, "load_host_policy", side_effect=OSError(SECRET)):
            self.assert_error("recovery_failed", lambda: self.recover(attempt))
        self.assertEqual(self.read(attempt), before)

    def test_post_commit_interruption_stays_an_interrupt_with_durable_disposition(self):
        attempt = self.unknown()
        original = recovery._mutation_lock
        @contextmanager
        def interrupted_close(*arguments, **keywords):
            with original(*arguments, **keywords):
                yield
            raise KeyboardInterrupt()
        with patch.object(recovery, "_mutation_lock", interrupted_close):
            with self.assertRaises(KeyboardInterrupt):
                self.recover(attempt)
        self.assertTrue(self.read(attempt)["supervision"]["released"])

    def test_blocked_evidence_cannot_consume_final_quiescent_slot(self):
        attempt = self.unknown()
        with patch.object(recovery, "MAX_RECOVERY_OBSERVATIONS", 3):
            for _ in range(2):
                self.blocked(attempt, lambda request: replace(quiet(request), dispatch="pending"))
            self.assert_error("attempt_recovery_limit", lambda: self.recover(
                attempt, lambda request: replace(quiet(request), dispatch="pending")))
            self.assertTrue(self.recover(attempt)["supervision"]["released"])

    def test_generic_event_writer_cannot_claim_recovery_from_a_bare_outcome(self):
        attempt = self.unknown()
        self.assert_error("attempt_recovery_evidence_required", lambda: journal._FixtureJournal(self.store).append(
            attempt["attempt_id"], expected_sequence=self.read(attempt)["sequence"],
            action_id=None, kind="recovery_recorded", outcome="quiescent"))

    def test_another_inactive_fixture_cannot_start_effects_across_unresolved_ownership(self):
        inactive = self.create()
        attempt = self.unknown()
        effects = []
        self.assert_error("attempt_recovery_required", lambda: journal._FixtureJournal(self.store).run_inert(
            inactive["attempt_id"], inactive["actions"][0]["action_id"], expected_sequence=0,
            effect=lambda: effects.append("started"), observe=lambda: "satisfied"))
        self.assertEqual(effects, [])
        self.assertEqual(self.read(inactive)["state"], "planned")
        self.assertFalse(self.read(attempt)["supervision"]["released"])

    def test_production_boundary_and_inactive_attempt_refuse_before_collection(self):
        attempt = self.create()
        calls = []
        self.assert_error("recovery_unavailable", lambda: self.recover(attempt,
            lambda request: calls.append(request), _fixture=False))
        self.assert_error("recovery_not_required", lambda: self.recover(attempt,
            lambda request: calls.append(request)))
        self.assertEqual(calls, [])

    def test_missing_attempt_and_corrupt_action_history_do_not_guess_authority(self):
        self.assert_error("attempt_missing", lambda: recovery.AttemptRecovery(**self.arguments,
            _collector=quiet).recover(str(uuid.uuid4()), expected_sequence=1))
        attempt = self.unknown()
        with sqlite3.connect(self.directory / "state.sqlite3") as db:
            db.execute("DROP TRIGGER attempt_actions_delete")
            db.execute("DELETE FROM attempt_actions WHERE attempt_id=? AND ordinal=1", (attempt["attempt_id"],))
            db.execute(_TRIGGERS["attempt_actions_delete"])
        self.assert_error("store_corrupt", lambda: recovery.AttemptRecovery(**self.arguments,
            _collector=quiet).recover(attempt["attempt_id"], expected_sequence=4))

    def test_tampered_recovery_proof_fails_authentication(self):
        attempt = self.unknown()
        self.blocked(attempt, lambda request: replace(quiet(request), dispatch="pending"))
        with sqlite3.connect(self.directory / "state.sqlite3") as db:
            sequence, raw = db.execute("SELECT sequence,outcome FROM attempt_events WHERE kind='recovery_recorded'").fetchone()
            payload = json.loads(raw)
            payload["dispatch"], payload["disposition"] = "settled", "quiescent"
            db.execute("DROP TRIGGER attempt_events_update")
            db.execute("UPDATE attempt_events SET outcome=? WHERE attempt_id=? AND sequence=?",
                       (_json(payload).decode(), attempt["attempt_id"], sequence))
            db.execute(_TRIGGERS["attempt_events_update"])
        self.assert_error("store_corrupt", lambda: self.read(attempt))

    def test_authenticated_proof_still_requires_exact_scope_and_consistent_disposition(self):
        attempt = self.unknown()
        request = recovery._request(self.store, attempt["attempt_id"], self.read(attempt)["sequence"], fixtures.BOOT)
        original = json.loads(recovery._encode_evidence(quiet(request), request, os.geteuid()))
        wrong_ids = [str(uuid.uuid4()) for _ in request.resource_ids]
        changes = ({"original_boot_id": NEW_BOOT}, {"host_id": NEW_BOOT},
                   {"disposition": "blocked"}, {"sequence": request.sequence + 1},
                   {"resource_ids": wrong_ids, "resources": [[identity, "quiescent"] for identity in wrong_ids]})
        for change in changes:
            with self.subTest(change=change):
                self.assert_error("attempt_transition_invalid", lambda: journal._FixtureJournal(self.store)._append_recovery(
                    attempt["attempt_id"], expected_sequence=request.sequence,
                    outcome=_json(original | change).decode()))
        self.assertEqual(self.read(attempt)["sequence"], request.sequence)
        self.assertTrue(self.recover(attempt)["supervision"]["released"])

    def test_missing_store_is_not_recreated_or_reconstructed(self):
        missing = self.root / "missing-store"
        self.assert_error("store_missing", lambda: recovery.AttemptRecovery(**(
            self.arguments | {"store_directory": missing}), _collector=quiet).recover(
                str(uuid.uuid4()), expected_sequence=1))
        self.assertFalse(missing.exists())

    def test_private_context_reader_detaches_values_and_recovery_projection(self):
        attempt = self.unknown()
        self.recover(attempt)
        result = journal.read_attempt_context(self.store, attempt["attempt_id"])
        first = result.as_dict()
        self.assertEqual(first["context"]["worker"]["boot_id"], fixtures.BOOT)
        self.assertEqual(first["summary"], self.read(attempt))
        first["context"].clear()
        self.assertTrue(result.as_dict()["context"])
        public = json.dumps(first["summary"])
        for private in (fixtures.BOOT, "challenge_id", "operator_uid", "package_lock"):
            self.assertNotIn(private, public)


class EngineRecoveryTests(unittest.TestCase):
    # Separate fixture adds exact engine identity and daemon/resource evidence.
    create = RecoveryTests.create
    dispatch = RecoveryTests.dispatch
    read = RecoveryTests.read
    recover = RecoveryTests.recover
    unknown = RecoveryTests.unknown
    blocked = RecoveryTests.blocked
    assert_error = RecoveryTests.assert_error

    def setUp(self):
        fixtures.SupervisionTests.setUp(self)
        self.store.close()
        self.directory = self.root / "engine-store"
        self.policy.write_text(f'schema=1\nhost_id="{fixtures.HOST}"\nengine_aliases={{local="engine-one"}}\n'
                               f'allowed_input_roots={json.dumps([str(self.root)])}\n')
        self.store = HostStore.create(self.directory, fixtures.HOST,
            engine_aliases={"local": "engine-one"}, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        source = load_declaration(b'''schema=1
components=[]
[[resources]]
id="one"
kind="compose"
identity={engine="local",project="app"}
manage=["services"]
desired={services=["app"]}
[[resources]]
id="two"
kind="network"
identity={engine="local",name="app-network"}
manage=["present"]
desired={present=true}
''')
        self.store.adopt(source, 0, ["one", "two"])
        self.arguments["store_directory"] = self.directory
        self.boundary = HostBoundary(policy_path=self.policy, store_directory=self.directory,
                                    mutation_lock=self.lock, owner_uid=os.geteuid())

    def test_daemon_work_after_worker_death_requires_engine_and_resource_quiescence(self):
        attempt = self.unknown()
        self.blocked(attempt, lambda request: replace(quiet(request), engines=(("engine-one", "active"),)))
        self.blocked(attempt, lambda request: replace(quiet(request), resources=tuple(
            (identity, "active" if index == 0 else "quiescent") for index, identity in enumerate(request.resource_ids))))
        with self.assertRaises(recovery.RecoveryError):
            self.recover(attempt, lambda request: replace(quiet(request), engines=(("other-engine", "quiescent"),)))
        result = self.recover(attempt)
        self.assertTrue(result["supervision"]["released"])
        raw = self.store._db.execute("SELECT outcome FROM attempt_events WHERE kind='recovery_recorded' "
                                     "ORDER BY sequence DESC LIMIT 1").fetchone()[0]
        self.assertEqual(json.loads(raw)["package_lock"], "not_applicable")


if __name__ == "__main__":
    unittest.main()
