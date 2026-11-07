"""Durable attempt failures using owned temporary stores and inert effects."""
from dataclasses import FrozenInstanceError, replace
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager import attempt_journal as journal
from mpkg_manager import store_migration as migration
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.store import HostStore, ProtectedInput, StoreError, _TRIGGERS, _json


HOST = "12345678-1234-4234-8234-123456789abc"
PRIVATE = "PRIVATE_ATTEMPT_SENTINEL"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")
PACKAGES = load_declaration(b'''schema=1
components=[]
[[resources]]
id="first"
kind="package"
identity={name="git"}
manage=["present"]
desired={present=true}
[[resources]]
id="second"
kind="package"
identity={name="bash"}
manage=["present"]
desired={present=true}
''')


class JournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "store"
        self.store = HostStore.create(self.directory, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.store.adopt(PACKAGES, 0, ["first", "second"])
        self.selected = [record["stable_id"] for record in self.store.current()["resources"]]
        self.worker = journal.WorkerIdentity(os.geteuid(), os.geteuid(), str(uuid.uuid4()), str(uuid.uuid4()))
        self.writer = journal._FixtureJournal(self.store)

    def plan(self, revision=1):
        return journal._fixture_plan(self.store, expected_revision=revision, stable_resource_ids=self.selected)

    def create(self, *, plan=None, predecessor=None):
        return self.writer.create(self.plan() if plan is None else plan, self.worker,
                                  stable_resource_ids=self.selected, predecessor=predecessor).as_dict()

    def append(self, attempt, kind, outcome, index=0):
        return self.writer.append(attempt["attempt_id"], expected_sequence=attempt["sequence"],
            action_id=None if index is None else attempt["actions"][index]["action_id"],
            kind=kind, outcome=outcome).as_dict()

    def finish(self, attempt):
        return self.append(attempt, "attempt_finished", attempt["state"], None)

    def read(self, identity, store=None):
        return journal.read_attempt(self.store if store is None else store, identity).as_dict()

    def assert_error(self, code, callback):
        with self.assertRaises((StoreError, journal.JournalError, migration.MigrationError)) as error:
            callback()
        self.assertEqual(error.exception.code, code)
        self.assertNotIn(PRIVATE, str(error.exception))

    def corrupt(self, table, statement, args=()):
        with sqlite3.connect(self.directory / "state.sqlite3") as db:
            for action in ("update", "delete"):
                db.execute("DROP TRIGGER " + table + "_" + action)
            db.execute(statement, args)
            for action in ("update", "delete"):
                db.execute(_TRIGGERS[table + "_" + action])

    def test_target_and_worker_identity_survive_reopen_without_authority(self):
        attempt = self.create()
        self.assertEqual(attempt["state"], "planned")
        self.assertFalse(attempt["executable"])
        self.assertEqual(attempt["authority"], "fixture_only")
        self.assertEqual([row["attempted"] for row in attempt["actions"]], [False, False])
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as other:
            self.assertEqual(self.read(attempt["attempt_id"], other), attempt)
            context = json.loads(other._db.execute("SELECT context FROM attempts").fetchone()[0])
            self.assertEqual(context["worker"]["worker_id"], self.worker.worker_id)
            self.assertEqual(context["worker"]["boot_id"], self.worker.boot_id)
            self.assertEqual(context["target"]["revision"], 1)
            self.assertEqual(context["target"]["resources"][0]["definition"]["desired"], {"present": True})

    def test_plan_contract_is_closed_immutable_and_host_bound(self):
        plan = self.plan()
        with self.assertRaises(FrozenInstanceError):
            plan.plan_id = str(uuid.uuid4())
        for change in ({"contract_version": True}, {"contract_version": 2}, {"authority": "accepted"},
                       {"plan_id": "caller-plan"}, {"decision_revision": True}, {"target_digest": PRIVATE}):
            self.assert_error("invalid_attempt_request", lambda: replace(plan, **change))
        self.assert_error("invalid_attempt_request", lambda: self.create(
            plan=replace(plan, host_id=str(uuid.uuid4()))))
        self.assert_error("attempt_target_changed", lambda: self.create(plan=replace(plan, target_digest="0" * 64)))
        self.assertEqual(journal.list_attempts(self.store), [])

    def test_stale_plan_and_duplicate_plan_are_rejected(self):
        plan = self.plan()
        self.create(plan=plan)
        self.assert_error("attempt_plan_already_used", lambda: self.create(plan=plan))
        self.store.record_intent(EMPTY, 1)
        self.assert_error("revision_conflict", lambda: self.create(plan=plan))
        self.assert_error("attempt_revision_conflict", self.plan)

    def test_protected_binding_material_is_retained_privately_and_redacted(self):
        source = {"path": "/private/" + PRIVATE, "device": 1, "inode": 2, "size": len(PRIVATE),
                  "mtime_ns": 3, "uid": os.geteuid(), "gid": os.getegid(), "mode": 0o100600, "links": 1}
        self.store.record_intent(PACKAGES, 1,
            protected_inputs=[ProtectedInput("fixture", PRIVATE.encode(), source, "private configuration")])
        plan = self.plan(2)
        attempt = self.create(plan=plan)
        row = self.store._db.execute("SELECT context FROM attempts").fetchone()[0]
        context = json.loads(row)
        self.assertEqual(context["target"]["inputs"][0]["source_identity"]["path"], source["path"])
        self.assertNotIn(PRIVATE, json.dumps(attempt) + repr(journal.read_attempt(self.store, attempt["attempt_id"])))
        self.assertNotIn(context["target"]["inputs"][0]["token"], json.dumps(attempt))

    def test_start_commit_failure_invokes_no_effect(self):
        attempt = self.create()
        effects = []
        with patch.object(HostStore, "_commit", side_effect=sqlite3.OperationalError(PRIVATE)):
            self.assert_error("commit_outcome_unknown", lambda: self.writer.run_inert(
                attempt["attempt_id"], attempt["actions"][0]["action_id"], expected_sequence=0,
                effect=lambda: effects.append("effect"), observe=lambda: "satisfied"))
        self.assertEqual(effects, [])
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as other:
            self.assertEqual(self.read(attempt["attempt_id"], other)["state"], "planned")

    def test_record_then_adopt_binds_reused_protected_capture_to_original_origin(self):
        inputs = self.root / "inputs"
        inputs.mkdir(mode=0o700)
        (inputs / "private.env").write_text(PRIVATE)
        policy_path = self.root / "policy.toml"
        policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                               f'allowed_input_roots={json.dumps([str(inputs)])}\n')
        policy_path.chmod(0o600)
        with load_host_policy(path=policy_path, owner_uid=os.geteuid()) as policy:
            recorder = ProtectedRecorder(self.store, policy)
            prepared = recorder.prepare(expected_revision=1, input_id="input", base_directory=str(inputs),
                                         path="private.env")
            declaration = load_declaration(PACKAGES.source_bytes + f'''
[[inputs]]
id="input"
base_directory={json.dumps(str(inputs))}
files=[{{path="private.env",classification="protected",reference="{prepared.reference}"}}]
'''.encode())
            recorder.record_intent(declaration, 1, prepared_inputs=[prepared])
            recorder.adopt(declaration, 2, ["first", "second"])
        attempt = self.create(plan=self.plan(3))
        context = json.loads(self.store._db.execute("SELECT context FROM attempts").fetchone()[0])
        target = context["target"]
        self.assertEqual(len(target["inputs"]), 1)
        self.assertEqual(target["inputs"][0]["revision"], 2)
        self.assertEqual(target["inputs"][0]["capture_id"], prepared.reference)
        self.assertEqual(target["declared_inputs"][0]["state"], "bound")
        self.assertEqual(target["declared_inputs"][0]["origin_revision"], 2)
        self.store.record_intent(EMPTY, 3)
        self.assertEqual(self.read(attempt["attempt_id"])["decision_state"], "superseded")

    def test_committed_start_with_lost_response_still_invokes_no_effect(self):
        attempt = self.create()
        commit, effects = HostStore._commit, []
        def lost_response(store):
            commit(store)
            raise OSError(PRIVATE)
        with patch.object(HostStore, "_commit", lost_response):
            self.assert_error("commit_outcome_unknown", lambda: self.writer.run_inert(
                attempt["attempt_id"], attempt["actions"][0]["action_id"], expected_sequence=0,
                effect=lambda: effects.append("effect"), observe=lambda: "satisfied"))
        self.assertEqual(effects, [])
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as other:
            result = self.read(attempt["attempt_id"], other)
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(result["events"][0]["kind"], "action_started")

    def test_interrupt_after_effect_preserves_unknown_and_unattempted_work(self):
        attempt = self.create()
        effects = []
        def effect():
            effects.append("changed")
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.writer.run_inert(attempt["attempt_id"], attempt["actions"][0]["action_id"],
                                  expected_sequence=0, effect=effect, observe=lambda: "satisfied")
        self.assertEqual(effects, ["changed"])
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as other:
            result = self.read(attempt["attempt_id"], other)
            self.assertEqual([row["state"] for row in result["actions"]], ["unknown", "planned"])
            self.assert_error("attempt_transition_invalid", lambda: self.finish(result))

    def test_effect_runs_without_database_or_store_lock(self):
        attempt = self.create()
        def effect():
            self.assertFalse(self.store._db.in_transaction)
            with sqlite3.connect(self.directory / "state.sqlite3", timeout=0) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("ROLLBACK")
            with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as other:
                self.assertEqual(self.read(attempt["attempt_id"], other)["state"], "unknown")
        result = self.writer.run_inert(attempt["attempt_id"], attempt["actions"][0]["action_id"],
            expected_sequence=0, effect=effect, observe=lambda: "satisfied").as_dict()
        self.assertEqual(result["actions"][0]["state"], "observed-complete")
        self.assertEqual(result["actions"][1]["state"], "planned")

    def test_completion_commit_failure_retains_started_record(self):
        attempt = self.create()
        commit, effects = HostStore._commit, []
        count = 0
        def failure(store):
            nonlocal count
            count += 1
            if count == 2:
                raise sqlite3.OperationalError(PRIVATE)
            commit(store)
        with patch.object(HostStore, "_commit", failure):
            self.assert_error("commit_outcome_unknown", lambda: self.writer.run_inert(
                attempt["attempt_id"], attempt["actions"][0]["action_id"], expected_sequence=0,
                effect=lambda: effects.append("effect"), observe=lambda: "satisfied"))
        self.assertEqual(effects, ["effect"])
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as other:
            result = self.read(attempt["attempt_id"], other)
            self.assertEqual(result["sequence"], 1)
            self.assertEqual(result["actions"][0]["state"], "unknown")

    def test_unlock_failure_after_start_commit_does_not_advance_to_effect(self):
        attempt = self.create()
        flock, effects = fcntl.flock, []
        calls = 0
        def unlock(fd, operation):
            nonlocal calls
            if fd == self.store._lockfd and operation == fcntl.LOCK_UN:
                calls += 1
                if calls == 2:  # append's read transaction, then committed write
                    raise OSError(PRIVATE)
            return flock(fd, operation)
        with patch("mpkg_manager.store.fcntl.flock", unlock):
            self.assert_error("commit_outcome_unknown", lambda: self.writer.run_inert(
                attempt["attempt_id"], attempt["actions"][0]["action_id"], expected_sequence=0,
                effect=lambda: effects.append("effect"), observe=lambda: "satisfied"))
        self.assertEqual(effects, [])
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as other:
            self.assertEqual(self.read(attempt["attempt_id"], other)["state"], "unknown")

    def test_command_and_observation_outcomes_are_independent(self):
        attempt = self.create()
        attempt = self.append(attempt, "action_started", "started")
        attempt = self.append(attempt, "command_completed", "failed")
        attempt = self.append(attempt, "observation_completed", "satisfied")
        self.assertEqual(attempt["actions"][0]["command_outcome"], "failed")
        self.assertEqual(attempt["actions"][0]["observation_outcome"], "satisfied")
        self.assertEqual(attempt["actions"][0]["state"], "failed")
        self.assertTrue(self.finish(attempt)["finished"])

    def test_successful_command_without_check_remains_unverified(self):
        attempt = self.create()
        attempt = self.append(attempt, "action_started", "started")
        attempt = self.append(attempt, "command_completed", "succeeded")
        self.assertEqual(attempt["actions"][0]["state"], "unverified")
        self.assert_error("attempt_transition_invalid", lambda: self.append(attempt, "action_started", "started", 1))
        attempt = self.append(attempt, "observation_completed", "unavailable")
        self.assertTrue(self.finish(attempt)["finished"])

    def test_observation_never_resolves_unknown_command_without_recovery(self):
        for outcome in ("failed", "satisfied", "unavailable"):
            with self.subTest(outcome=outcome):
                attempt = self.create()
                attempt = self.append(attempt, "action_started", "started")
                attempt = self.append(attempt, "command_completed", "unknown")
                attempt = self.append(attempt, "observation_completed", outcome)
                self.assertEqual(attempt["state"], "unknown")
                self.assertEqual(attempt["actions"][0]["observation_outcome"], outcome)
                self.assert_error("attempt_transition_invalid", lambda: self.finish(attempt))
                self.assert_error("invalid_attempt_request", lambda: self.create(predecessor=attempt["attempt_id"]))

    def test_failed_check_stops_later_effects(self):
        attempt = self.create()
        attempt = self.append(attempt, "action_started", "started")
        attempt = self.append(attempt, "command_completed", "succeeded")
        attempt = self.append(attempt, "observation_completed", "failed")
        effects = []
        self.assert_error("attempt_transition_invalid", lambda: self.writer.run_inert(
            attempt["attempt_id"], attempt["actions"][1]["action_id"], expected_sequence=attempt["sequence"],
            effect=lambda: effects.append("forbidden"), observe=lambda: "satisfied"))
        self.assertEqual(effects, [])

    def test_complete_attempt_retains_every_event_and_rejects_replay(self):
        attempt = self.create()
        for index in range(2):
            attempt = self.append(attempt, "action_started", "started", index)
            attempt = self.append(attempt, "command_completed", "succeeded", index)
            attempt = self.append(attempt, "observation_completed", "satisfied", index)
        attempt = self.finish(attempt)
        self.assertEqual((attempt["state"], attempt["sequence"]), ("observed-complete", 7))
        self.assert_error("attempt_transition_invalid", lambda: self.finish(attempt))
        self.assert_error("attempt_transition_invalid", lambda: self.append(attempt, "action_started", "started"))
        self.assert_error("invalid_attempt_request", lambda: self.create(predecessor=attempt["attempt_id"]))

    def test_new_attempt_links_to_failed_predecessor_with_new_plan(self):
        attempt = self.create()
        attempt = self.append(attempt, "action_started", "started")
        self.assert_error("invalid_attempt_request", lambda: self.create(predecessor=attempt["attempt_id"]))
        attempt = self.append(attempt, "command_completed", "failed")
        attempt = self.finish(attempt)
        next_attempt = self.create(predecessor=attempt["attempt_id"])
        self.assertNotEqual(next_attempt["plan_id"], attempt["plan_id"])
        self.assertEqual(next_attempt["predecessor"], attempt["attempt_id"])
        self.assertEqual(next_attempt["state"], "planned")

    def test_new_intent_does_not_rewrite_original_targets_or_outcomes(self):
        attempt = self.create()
        attempt = self.append(attempt, "action_started", "started")
        raw = self.store._db.execute("SELECT context FROM attempts").fetchone()[0]
        self.store.record_intent(EMPTY, 1)
        self.assertEqual(self.store._db.execute("SELECT context FROM attempts").fetchone()[0], raw)
        attempt = self.append(attempt, "command_completed", "failed")
        self.assertEqual((attempt["revision"], attempt["decision_state"]), (1, "superseded"))
        self.assertEqual(self.store.current()["revision"], 2)
        self.assertEqual(attempt["actions"][1]["state"], "planned")

    def test_later_adoption_cannot_replace_original_required_check(self):
        raw = b'''schema=1
components=[]
[[resources]]
id="web"
kind="service"
identity={manager="system",unit="web.service"}
desired={running=true}
manage=["running"]
checks=["state"]
[[checks]]
id="state"
kind="service"
resource="web"
timeout_seconds=3
expected={running=true,enabled=true}
'''
        original = load_declaration(raw)
        self.store.adopt(original, 1, ["web"])
        self.selected = [record["stable_id"] for record in self.store.current()["resources"]
                         if record["logical_id"] == "web"]
        attempt = self.create(plan=self.plan(2))
        context = self.store._db.execute("SELECT context FROM attempts").fetchone()[0]
        self.store.adopt(load_declaration(raw.replace(b"running=true,enabled=true", b"running=true")), 2, ["web"])
        result = self.read(attempt["attempt_id"])
        self.assertEqual(result["actions"][0]["required_check_count"], 1)
        self.assertEqual(result["decision_state"], "superseded")
        self.assertEqual(self.store._db.execute("SELECT context FROM attempts").fetchone()[0], context)
        check = json.loads(context)["target"]["resources"][0]["checks"][0]
        self.assertEqual(check["expected"], {"running": True, "enabled": True})

    def test_sequence_compare_and_swap_prevents_duplicate_writer_events(self):
        attempt = self.create()
        advanced = self.append(attempt, "action_started", "started")
        self.assert_error("attempt_sequence_conflict", lambda: self.append(attempt, "action_started", "started"))
        self.assertEqual(self.read(attempt["attempt_id"]), advanced)

    def test_invalid_transition_and_unbounded_raw_outcome_leave_history_unchanged(self):
        attempt = self.create()
        for kind, outcome in (("command_completed", "succeeded"), ("observation_completed", "satisfied"),
                              ("action_started", PRIVATE), (PRIVATE, PRIVATE)):
            self.assert_error("attempt_transition_invalid", lambda: self.append(attempt, kind, outcome))
        self.assertEqual(self.read(attempt["attempt_id"]), attempt)
        self.assert_error("attempt_transition_invalid", lambda: self.append(attempt, "action_started", "started", 1))

    def test_callback_exceptions_and_unknown_observations_do_not_leak(self):
        attempt = self.create()
        def fail():
            raise RuntimeError(PRIVATE)
        result = self.writer.run_inert(attempt["attempt_id"], attempt["actions"][0]["action_id"],
            expected_sequence=0, effect=fail, observe=lambda: PRIVATE).as_dict()
        self.assertEqual((result["actions"][0]["command_outcome"], result["actions"][0]["observation_outcome"]),
                         ("failed", "unavailable"))
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertNotIn(PRIVATE.encode(), (self.directory / "state.sqlite3").read_bytes())

    def test_rows_are_immutable_through_sql(self):
        attempt = self.create()
        self.append(attempt, "action_started", "started")
        for table in ("attempts", "attempt_actions", "attempt_events"):
            with self.subTest(table=table), sqlite3.connect(self.directory / "state.sqlite3") as db:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable_record"):
                    db.execute("DELETE FROM " + table)
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable_record"):
                    db.execute("UPDATE " + table + " SET id=id")

    def test_tampered_target_worker_or_seal_is_refused(self):
        self.create()
        original = self.store._db.execute("SELECT context,seal FROM attempts").fetchone()
        context = json.loads(original[0])
        context["worker"]["operator_uid"] += 1
        self.corrupt("attempts", "UPDATE attempts SET context=?", (_json(context),))
        self.assert_error("store_corrupt", self.store.current)
        self.corrupt("attempts", "UPDATE attempts SET context=?,seal=?", original)
        self.corrupt("attempts", "UPDATE attempts SET seal=?", (b"x" * 32,))
        self.assert_error("store_corrupt", lambda: journal.list_attempts(self.store))

    def test_tampered_event_and_missing_action_are_refused(self):
        attempt = self.create()
        self.append(attempt, "action_started", "started")
        self.corrupt("attempt_events", "UPDATE attempt_events SET outcome='succeeded'")
        self.assert_error("store_corrupt", lambda: self.read(attempt["attempt_id"]))

    def test_missing_original_action_is_refused(self):
        self.create()
        self.corrupt("attempt_actions", "DELETE FROM attempt_actions WHERE ordinal=1")
        self.assert_error("store_corrupt", self.store.current)

    def test_semantically_invalid_resealed_event_is_refused(self):
        attempt = self.create()
        row, _, _ = journal._rows(self.store, attempt["attempt_id"])
        values = [attempt["attempt_id"], 1, str(uuid.uuid4()), attempt["actions"][0]["action_id"],
                  "command_completed", journal._now(), "succeeded"]
        seal = journal._seal(self.store, "event", values, row[7])
        with sqlite3.connect(self.directory / "state.sqlite3") as db:
            db.execute("INSERT INTO attempt_events VALUES(?,?,?,?,?,?,?,?)", (*values, seal))
        self.assert_error("store_corrupt", self.store.current)

    def test_readonly_listing_is_detached_paginated_and_nonmutating(self):
        created = {self.create()["attempt_id"] for _ in range(3)}
        before = (self.directory / "state.sqlite3").read_bytes()
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as other:
            first = journal.list_attempts(other, limit=2)
            final = journal.list_attempts(other, after_id=first[-1].as_dict()["attempt_id"])
            self.assertEqual({row.as_dict()["attempt_id"] for row in first + final}, created)
            value = first[0].as_dict()
            value["actions"].clear()
            self.assertEqual(len(first[0].as_dict()["actions"]), 2)
            for limit in (True, 0, 101):
                self.assert_error("invalid_attempt_request", lambda: journal.list_attempts(other, limit=limit))
            self.assert_error("store_readonly", lambda: journal._FixtureJournal(other).create(
                self.plan(), self.worker, stable_resource_ids=self.selected))
        self.assertEqual((self.directory / "state.sqlite3").read_bytes(), before)

    def test_private_backup_preserves_attempts_events_and_key(self):
        attempt = self.create()
        attempt = self.append(attempt, "action_started", "started")
        with self.store._locked(exclusive=True):
            self.store._db.execute("BEGIN IMMEDIATE")
            try:
                with migration._Backup(self.root / "backup", os.geteuid()) as backup:
                    backup.capture(self.store, 1)
            finally:
                self.store._db.execute("ROLLBACK")
        self.store.record_intent(EMPTY, 1)
        with HostStore.open_readonly(self.root / "backup", HOST, owner_uid=os.geteuid()) as backup:
            self.assertEqual(self.read(attempt["attempt_id"], backup), attempt)

    def test_pagination_does_not_skip_concurrent_appends_with_lower_uuids(self):
        self.selected = self.selected[:1]
        plan = self.plan()
        with patch.object(journal.uuid, "uuid4", return_value=uuid.UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")):
            first = self.create(plan=plan)
        page = journal.list_attempts(self.store, limit=1)
        plan = self.plan()
        with patch.object(journal.uuid, "uuid4", return_value=uuid.UUID("00000000-0000-4000-8000-000000000000")):
            second = self.create(plan=plan)
        rest = journal.list_attempts(self.store, after_id=page[-1].as_dict()["attempt_id"])
        self.assertLess(second["attempt_id"], first["attempt_id"])
        self.assertEqual([attempt.as_dict()["attempt_id"] for attempt in rest], [second["attempt_id"]])
        self.assertEqual([attempt.as_dict()["ordinal"] for attempt in page + rest], [1, 2])
        self.assert_error("attempt_cursor_missing", lambda: journal.list_attempts(self.store,
            after_id=str(uuid.uuid4())))


class JournalMigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "store"
        self.backup = self.root / "backup"
        with patch("mpkg_manager.store.SCHEMA_VERSION", 3):
            with HostStore.create(self.directory, HOST, owner_uid=os.geteuid()) as store:
                store.adopt(PACKAGES, 0, ["first", "second"])
                self.original = store.current()

    def migrate(self):
        return migration.migrate_store_to_v4(self.directory, HOST, expected_revision=1,
            backup_directory=self.backup, owner_uid=os.geteuid())

    def test_v3_is_readable_and_writes_and_journal_need_explicit_migration(self):
        before = (self.directory / "state.sqlite3").read_bytes()
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as old:
            self.assertEqual(old.current(), self.original)
            with self.assertRaisesRegex(journal.JournalError, "attempt_migration_required"):
                journal.list_attempts(old)
        with self.assertRaisesRegex(StoreError, "store_migration_required"):
            HostStore.open_existing(self.directory, HOST, owner_uid=os.geteuid())
        self.assertEqual((self.directory / "state.sqlite3").read_bytes(), before)
        self.assertFalse(self.backup.exists())

    def test_verified_v4_migration_preserves_old_history_and_readable_backup(self):
        receipt = self.migrate()
        self.assertEqual((receipt.from_version, receipt.to_version), (3, 4))
        with HostStore.open_existing(self.directory, HOST, owner_uid=os.geteuid()) as store:
            self.assertEqual(store.current(), self.original)
            self.assertEqual(journal.list_attempts(store), [])
            self.assertEqual(store.schema_history()["schema_version"], 4)
            self.assertEqual([row["to_version"] for row in store.schema_history()["receipts"]], [3, 4])
        with HostStore.open_readonly(self.backup, HOST, owner_uid=os.geteuid()) as backup:
            self.assertEqual(backup.current(), self.original)
            self.assertEqual(backup._schema_version, 3)

    def test_failed_backup_does_not_upgrade_and_keeps_artifacts(self):
        capture = migration._Backup.capture
        def fail(backup, store, revision):
            capture(backup, store, revision)
            raise migration.MigrationError("backup_verification_failed")
        with patch.object(migration._Backup, "capture", fail):
            with self.assertRaisesRegex(migration.MigrationError, "backup_verification_failed"):
                self.migrate()
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as store:
            self.assertEqual(store._schema_version, 3)
        self.assertTrue((self.backup / "state.sqlite3").is_file())
        with self.assertRaisesRegex(migration.MigrationError, "backup_destination_exists"):
            self.migrate()

    def test_migration_commit_response_loss_is_inspectable(self):
        commit = HostStore._commit
        def lost(store):
            commit(store)
            raise OSError(PRIVATE)
        with patch.object(HostStore, "_commit", lost):
            with self.assertRaisesRegex(migration.MigrationError, "migration_outcome_unknown"):
                self.migrate()
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as store:
            self.assertEqual(store._schema_version, 4)
            self.assertEqual(store.schema_history()["receipts"][-1]["from_version"], 3)
        with HostStore.open_readonly(self.backup, HOST, owner_uid=os.geteuid()) as backup:
            self.assertEqual(backup._schema_version, 3)


if __name__ == "__main__":
    unittest.main()
