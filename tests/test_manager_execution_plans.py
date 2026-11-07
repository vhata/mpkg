"""Accepted inert plans, owned temporary histories and no host operations."""
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager import execution_plans as plans
from mpkg_manager import attempt_journal as journal
from mpkg_manager import store_migration as migration
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.store import HostStore, StoreError, _TRIGGERS, _json

HOST = '12345678-1234-4234-8234-123456789abc'
PRIVATE = 'PRIVATE_EXECUTION_EVIDENCE_SENTINEL'
SOURCE = b'''schema=1
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
requires=["first"]
'''
DECLARATION = load_declaration(SOURCE)


class ExecutionPlanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / 'store'
        self.store = HostStore.create(self.directory, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.store.adopt(DECLARATION, 0, ['first', 'second'])
        self.policy_path = self.root / 'policy.toml'
        self.policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\nallowed_input_roots={json.dumps([str(self.root)])}\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.recorder = ProtectedRecorder(self.store, self.policy)
        self.adapter = plans._InertAdapter()
        self.ids = {row['logical_id']: row['stable_id'] for row in self.store.current()['resources']}
        for identity in self.ids.values():
            self.adapter.seed(identity, token=PRIVATE)
        self.planner = plans._FixturePlanner(self.recorder, self.adapter)
        self.worker = journal.WorkerIdentity(os.geteuid(), os.geteuid(), str(uuid.uuid4()), str(uuid.uuid4()))
        self.lock = self.root / 'apply.lock'
        self.lock.touch(mode=0o600)

    def prepare(self, revision=1):
        return self.planner.prepare(expected_revision=revision, stable_resource_ids=[self.ids['second']]).as_dict()

    def accept(self, plan=None):
        return self.planner.accept((self.prepare() if plan is None else plan)['plan_id'], operator_uid=os.geteuid())

    def run_plan(self, binding):
        return self.planner.run_inert(binding, self.worker, mutation_lock=self.lock).as_dict()

    def error(self, code, callback):
        with self.assertRaises((plans.ExecutionPlanError, StoreError, journal.JournalError)) as caught:
            callback()
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn(PRIVATE, str(caught.exception))

    def test_registered_derivation_closes_dependencies_and_preserves_private_bindings(self):
        plan = self.prepare()
        self.assertEqual([action['stable_resource_id'] for action in plan['actions']], [self.ids['first'], self.ids['second']])
        self.assertFalse(plan['executable'])
        self.assertFalse(plan['accepted'])
        self.assertNotIn(PRIVATE, json.dumps(plan))
        context = json.loads(self.store._db.execute('SELECT context FROM execution_plans').fetchone()[0])
        self.assertEqual(context['actions'][1]['dependencies'], [self.ids['first']])
        self.assertEqual(context['actions'][0]['interruption'], 'stop_and_require_recovery')
        self.assertEqual(context['actions'][0]['disposition'], 'retain')
        self.assertEqual(context['history']['target']['host_id'], HOST)

    def test_explicit_acceptance_reopens_and_runs_only_inert_effects(self):
        binding = self.accept()
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as other:
            result = plans.read_execution_plan(other, binding.plan_id).as_dict()
            self.assertEqual(result['acceptance_id'], binding.acceptance_id)
        result = self.run_plan(binding)
        self.assertEqual(result['state'], 'observed-complete')
        self.assertTrue(result['supervision']['released'])
        self.assertEqual(self.adapter.executions, [self.ids['first'], self.ids['second']])
        self.assertEqual(result['plan_id'], binding.plan_id)
        self.assertEqual(self.store.current()['revision'], 1)

    def test_production_and_unregistered_adapters_refuse(self):
        self.error('execution_adapter_unavailable', lambda: plans.ExecutionPlanner(self.recorder).prepare())
        self.error('execution_adapter_unavailable', lambda: plans._FixturePlanner(self.recorder, object()))

    def test_forged_binding_or_operator_never_creates_attempt(self):
        binding = self.accept()
        for changed in (replace(binding, host_id=str(uuid.uuid4())), replace(binding, descriptor_digest='0'*64),
                        replace(binding, authority='production'), replace(binding, operator_uid=binding.operator_uid+1)):
            self.error('plan_acceptance_mismatch', lambda: self.run_plan(changed))
        self.error('plan_operator_mismatch', lambda: self.planner.create_attempt(binding,
            replace(self.worker, operator_uid=self.worker.operator_uid+1)))
        self.assertEqual(journal.list_attempts(self.store), [])

    def test_before_evidence_change_requires_new_plan_and_acceptance(self):
        binding = self.accept()
        self.adapter.seed(self.ids['first'], token='changed')
        self.error('execution_plan_stale', lambda: self.run_plan(binding))
        fresh = self.accept()
        self.assertNotEqual(fresh.plan_id, binding.plan_id)
        self.assertEqual(self.run_plan(fresh)['state'], 'observed-complete')

    def test_noop_observes_without_calling_execute(self):
        for identity in self.ids.values():
            self.adapter.seed(identity, satisfied=True)
        binding = self.accept()
        with patch.object(self.adapter, 'execute', side_effect=AssertionError('must not mutate')):
            self.assertEqual(self.run_plan(binding)['state'], 'observed-complete')
        self.assertEqual(self.adapter.executions, [])

    def test_authority_change_invalidates_acceptance(self):
        binding = self.accept()
        self.store.record_intent(DECLARATION, 1)
        self.error('execution_plan_stale', lambda: self.run_plan(binding))
        self.assertEqual(journal.list_attempts(self.store), [])

    def test_acceptance_uses_normal_unresolved_attempt_gate(self):
        plan = self.prepare()
        fixture = journal._fixture_plan(self.store, expected_revision=1, stable_resource_ids=[self.ids['first']])
        attempt = journal._FixtureJournal(self.store).create(fixture, self.worker,
            stable_resource_ids=[self.ids['first']]).as_dict()
        journal._FixtureJournal(self.store).append(attempt['attempt_id'], expected_sequence=0,
            action_id=None, kind='launch_reserved', outcome='reserved')
        self.error('attempt_recovery_required', lambda: self.accept(plan))
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM plan_acceptances').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
