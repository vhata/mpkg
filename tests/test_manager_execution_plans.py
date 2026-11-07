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


    def test_artifact_substitution_invalidates_acceptance(self):
        binding = self.accept()
        self.adapter.facts[self.ids['second']]['artifact'] = b'substituted'
        self.error('execution_plan_stale', lambda: self.run_plan(binding))
        self.assertEqual(self.adapter.executions, [])

    def test_missing_before_evidence_blocks_preparation(self):
        del self.adapter.facts[self.ids['first']]
        self.error('plan_evidence_unavailable', self.prepare)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM execution_plans').fetchone()[0], 0)

    def test_no_current_authority_for_dependency_is_rejected(self):
        self.store.relinquish([self.ids['first']], 1)
        self.error('plan_authority_unavailable', lambda: self.prepare(2))

    def test_freshness_is_rechecked_between_actions(self):
        binding = self.accept()
        execute = self.adapter.execute
        def change_next(action):
            result = execute(action)
            self.adapter.facts[self.ids['second']]['token'] = 'concurrent change'
            return result
        with patch.object(self.adapter, 'execute', change_next):
            self.error('execution_plan_stale', lambda: self.run_plan(binding))
        attempt = journal.list_attempts(self.store)[0].as_dict()
        self.assertEqual(self.adapter.executions, [self.ids['first']])
        self.assertEqual([action['state'] for action in attempt['actions']], ['observed-complete', 'planned'])
        self.assertEqual(attempt['supervision']['worker'], 'unresolved')
        self.error('attempt_recovery_required', lambda: self.store.record_intent(DECLARATION, 1))

    def with_checks(self):
        checked = load_declaration(SOURCE.replace(b'desired={present=true}\n[[resources]]',
            b'desired={present=true}\nchecks=["installed"]\n[[resources]]') + b'''\n[[checks]]
 id="installed"
 kind="package"
 resource="first"
 timeout_seconds=2
 expected={present=true,reason="explicit"}
''')
        self.store.adopt(checked, 1, ['first', 'second'])
        return checked

    def test_failed_required_check_stops_later_effects(self):
        self.with_checks()
        self.adapter.facts[self.ids['first']]['checks'] = False
        binding = self.accept(self.prepare(2))
        result = self.run_plan(binding)
        self.assertEqual(self.adapter.executions, [self.ids['first']])
        self.assertEqual(result['state'], 'unverified')
        self.assertEqual(result['actions'][1]['state'], 'planned')
        self.assertFalse(result['supervision']['released'])

    def test_missing_required_check_cannot_be_claimed_as_success(self):
        self.with_checks()
        binding = self.accept(self.prepare(2))
        with patch.object(self.adapter, 'observe', return_value={'desired': 'satisfied', 'checks': []}):
            result = self.run_plan(binding)
        self.assertEqual(result['state'], 'unverified')
        self.assertEqual(self.adapter.executions, [self.ids['first']])

    def test_original_checks_survive_new_intent_with_weaker_current_check(self):
        checked = self.with_checks()
        self.store.record_intent(load_declaration(checked.source_bytes.replace(
            b'present=true,reason="explicit"', b'present=true')), 2)
        plan = self.prepare(3)
        context = json.loads(self.store._db.execute('SELECT context FROM execution_plans').fetchone()[0])
        roles = context['actions'][0]['checks']
        self.assertEqual(roles[0]['definitions'][0]['expected'], {'present': True})
        self.assertEqual(roles[1]['definitions'][0]['expected'], {'present': True, 'reason': 'explicit'})
        self.assertEqual(plan['actions'][0]['required_check_count'], 2)

    def test_noop_still_requires_checks(self):
        self.with_checks()
        for identity in self.ids.values():
            self.adapter.seed(identity, satisfied=True, checks=False)
        result = self.run_plan(self.accept(self.prepare(2)))
        self.assertEqual(result['state'], 'unverified')
        self.assertEqual(self.adapter.executions, [])

    def test_plan_and_acceptance_rows_are_immutable(self):
        binding = self.accept()
        for table in ('execution_plans', 'plan_acceptances'):
            for command in (f'UPDATE {table} SET id=id', f'DELETE FROM {table}'):
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable_record'):
                    self.store._db.execute(command)
        self.error('plan_already_accepted', lambda: self.planner.accept(binding.plan_id, operator_uid=os.geteuid()))

    def rewrite_plan(self, row):
        with sqlite3.connect(self.directory / 'state.sqlite3') as db:
            db.execute('DROP TRIGGER execution_plans_update')
            db.execute('UPDATE execution_plans SET context=?,seal=? WHERE id=?', (row[4], row[5], row[0]))
            db.execute(_TRIGGERS['execution_plans_update'])

    def test_authenticated_descriptor_still_requires_derived_order_checks_and_effects(self):
        self.with_checks()
        plan = self.prepare(2)
        original = self.store._db.execute('SELECT * FROM execution_plans').fetchone()
        mutations = [lambda value: value['actions'].reverse(),
            lambda value: value['actions'][0].update(checks=[]),
            lambda value: value['actions'][0].update(adapter='shell'),
            lambda value: value['actions'][1].update(dependencies=[])]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = json.loads(original[4])
                mutation(value)
                values = original[:4] + (_json(value),)
                changed = values + (plans._seal(self.store, 'plan', list(values)),)
                self.rewrite_plan(changed)
                self.error('store_corrupt', lambda: plans.read_execution_plan(self.store, plan['plan_id']))
                self.rewrite_plan(original)

    def test_canonical_evidence_tampering_requires_authentication(self):
        plan = self.prepare()
        original = self.store._db.execute('SELECT * FROM execution_plans').fetchone()
        value = json.loads(original[4])
        value['actions'][0]['prepared']['artifacts'][0]['digest'] = '0'*64
        self.rewrite_plan(original[:4] + (_json(value), original[5]))
        self.error('store_corrupt', lambda: plans.read_execution_plan(self.store, plan['plan_id']))

    def test_acceptance_operator_tampering_is_rejected(self):
        binding = self.accept()
        with sqlite3.connect(self.directory / 'state.sqlite3') as db:
            db.execute('DROP TRIGGER plan_acceptances_update')
            db.execute('UPDATE plan_acceptances SET operator_uid=operator_uid+1')
            db.execute(_TRIGGERS['plan_acceptances_update'])
        self.error('store_corrupt', lambda: self.planner.binding(binding.acceptance_id))

    def test_lost_acceptance_commit_is_durable_but_not_an_execution(self):
        plan = self.prepare()
        commit = HostStore._commit
        def lost(store):
            commit(store)
            raise OSError(PRIVATE)
        with patch.object(HostStore, '_commit', lost):
            self.error('commit_outcome_unknown', lambda: self.accept(plan))
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as reopened:
            result = plans.read_execution_plan(reopened, plan['plan_id']).as_dict()
            self.assertTrue(result['accepted'])
            self.assertEqual(journal.list_attempts(reopened), [])
        self.assertEqual(self.adapter.executions, [])

    def test_action_start_commit_failure_never_executes(self):
        binding = self.accept()
        commit = HostStore._commit
        def fail_start(store):
            last = store._db.execute('SELECT kind FROM attempt_events ORDER BY rowid DESC LIMIT 1').fetchone()
            if last == ('action_started',):
                raise OSError(PRIVATE)
            commit(store)
        with patch.object(HostStore, '_commit', fail_start):
            self.error('commit_outcome_unknown', lambda: self.run_plan(binding))
        self.assertEqual(self.adapter.executions, [])
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as reopened:
            attempt = journal.list_attempts(reopened)[0].as_dict()
            self.assertFalse(attempt['supervision']['released'])

    def test_source_bytes_identity_and_policy_are_bound(self):
        source = self.root / 'private.env'
        source.write_text(PRIVATE)
        prepared = self.recorder.prepare(expected_revision=1, input_id='input',
            base_directory=str(self.root), path='private.env')
        declaration = load_declaration(SOURCE + f'''\n[[inputs]]
 id="input"
 base_directory={json.dumps(str(self.root))}
 files=[{{path="private.env",classification="protected",reference="{prepared.reference}"}}]
'''.encode())
        self.recorder.record_intent(declaration, 1, prepared_inputs=[prepared])
        binding = self.accept(self.prepare(2))
        source.write_text('changed')
        self.error('execution_plan_stale', lambda: self.run_plan(binding))
        self.assertEqual(journal.list_attempts(self.store), [])

    def test_policy_replacement_invalidates_fresh_handle_too(self):
        binding = self.accept()
        replacement = self.root / 'replacement'
        replacement.write_bytes(self.policy_path.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(self.policy_path)
        with load_host_policy(path=self.policy_path, owner_uid=os.geteuid()) as policy:
            other = plans._FixturePlanner(ProtectedRecorder(self.store, policy), self.adapter)
            self.error('execution_plan_stale', lambda: other.validate(binding))



if __name__ == '__main__':
    unittest.main()
