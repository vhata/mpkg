"""Full client/protocol/helper/store boundary with trusted inert assembly."""
import json
import os
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager import host_client as client
from mpkg_manager import host_helper as helper
from mpkg_manager import execution_plans as plans
from mpkg_manager import attempt_journal as journal
from mpkg_manager.attempt_supervisor import LaunchResult
from mpkg_manager.attempt_recovery import AttemptRecovery, RecoveryEvidence
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.protected_bindings import ProtectedRecorder
from mpkg_manager.store import HostStore
from mpkg_manager.host_protocol import MAX_REQUEST_BYTES
import test_manager_execution_plans as fixtures
from test_manager_execution_plans import HOST, PRIVATE


class ExecutionRequests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ExecutionPlanTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.launches = []
        self.execute = False
        self.boot_id = self.f.worker.boot_id
        self.boundary = helper.HostBoundary(policy_path=self.f.policy_path,
            store_directory=self.f.directory, mutation_lock=self.f.lock,
            owner_uid=os.geteuid(), operator_uid=1234, _execution=self)

    def planner(self, recorder):
        return plans._FixturePlanner(recorder, self.f.adapter)

    def launch(self, spec):
        self.launches.append(spec)
        if self.execute:
            with load_host_policy(path=self.f.policy_path, owner_uid=os.geteuid()) as policy:
                with HostStore.open_existing(self.f.directory, HOST, owner_uid=os.geteuid()) as store:
                    attempt = journal.read_attempt(store, spec.attempt_id).as_dict()
                    plan = plans.read_execution_plan(store, attempt['plan_id']).as_dict()
                    planner = self.planner(ProtectedRecorder(store, policy))
                    binding = planner.binding(plan['acceptance_id'])
                    worker = journal.WorkerIdentity(operator_uid=1234, worker_uid=os.geteuid(), boot_id=self.boot_id, worker_id=str(uuid.uuid4()))
                    planner._run_inert(binding, worker, mutation_lock=self.f.lock, reserved_attempt=spec.attempt_id)
        return LaunchResult('accepted')

    def recover(self, identity, sequence, operator):
        def collect(request):
            return RecoveryEvidence(request, 'settled', 'absent', 'empty',
                'idle' if request.package_lock_required else 'not_applicable',
                tuple((x, 'quiescent') for x in request.engine_ids),
                tuple((x, 'quiescent') for x in request.resource_ids))
        return AttemptRecovery(policy_path=self.f.policy_path, store_directory=self.f.directory,
            mutation_lock=self.f.lock, owner_uid=os.geteuid(), _fixture=True,
            _fixture_boot=self.boot_id, _collector=collect).recover(identity,
                expected_sequence=sequence, operator_uid=operator)

    def raw(self, verb, **args):
        return json.dumps(dict(version=1, verb=verb, arguments=args)).encode()

    def sender(self, raw):
        reply = helper.handle_request(raw, boundary=self.boundary)
        self.assertNotIn(PRIVATE.encode(), reply)
        return client._Reply(reply, 0 if json.loads(reply)['ok'] else 2)

    def request(self, verb, **args):
        return client.request_host(self.raw(verb, **args), _sender=self.sender)

    def prepare(self):
        return self.request('prepare', operation='execution', expected_revision=1,
            resource_ids=[self.f.ids['second']], interruption='stop_and_require_recovery')

    def accepted(self):
        plan = self.prepare()
        return self.request('plan', operation='accept', plan_id=plan['plan_id'])

    def test_full_boundary_executes_and_repeats_return_same_attempt(self):
        plan = self.accepted()
        self.execute = True
        result = self.request('apply', operation='execution', plan_id=plan['plan_id'])
        repeat = self.request('apply', operation='execution', plan_id=plan['plan_id'])
        self.assertEqual(result['attempt_id'], repeat['attempt_id'])
        self.assertEqual(repeat['launch'], 'existing')
        self.assertEqual(len(self.launches), 1)
        attempt = journal.read_attempt(self.f.store, result['attempt_id']).as_dict()
        self.assertEqual(attempt['state'], 'observed-complete')
        self.assertEqual(self.f.adapter.executions, [self.f.ids['first'], self.f.ids['second']])

    def test_lost_reply_reconnect_and_recovery_preserve_identity(self):
        plan = self.accepted()
        raw = self.raw('apply', operation='execution', plan_id=plan['plan_id'])
        def lost(raw):
            self.sender(raw)
            raise client._TransportFailure('helper_timeout', dispatched=True)
        with self.assertRaises(client.HostClientError) as caught:
            client.request_host(raw, _sender=lost)
        self.assertEqual(caught.exception.category, 'uncertain')
        result = self.request('apply', operation='execution', plan_id=plan['plan_id'])
        attempt = journal.read_attempt(self.f.store, result['attempt_id']).as_dict()
        self.assertTrue(attempt['supervision']['reserved'])
        recovered = self.request('recover', operation='attempt', attempt_id=result['attempt_id'],
                                 expected_sequence=attempt['sequence'])
        self.assertEqual(recovered['disposition'], 'quiescent')
        self.assertEqual(len(self.launches), 1)
        self.assertEqual(self.f.adapter.executions, [])

    def test_record_is_blocked_during_dispatch_handoff(self):
        plan = self.accepted()
        def launch(spec):
            reply = json.loads(helper.handle_request(self.raw('record', operation='relinquish',
                expected_revision=1, resource_ids=[self.f.ids['first']]), boundary=self.boundary))
            self.assertEqual(reply['error']['code'], 'attempt_recovery_required')
            return LaunchResult('unknown')
        with patch.object(self, 'launch', side_effect=launch):
            self.request('apply', operation='execution', plan_id=plan['plan_id'])

    def test_forgery_malformed_oversize_and_production_refusal(self):
        for raw in (b'{', b'x'*(MAX_REQUEST_BYTES+1),
                    self.raw('apply', operation='execution', plan_id=str(uuid.uuid4()), operator_uid=0)):
            self.assertFalse(json.loads(helper.handle_request(raw, boundary=self.boundary))['ok'])
        self.boundary._execution = None
        with self.assertRaisesRegex(client.HostClientError, 'execution_adapter_unavailable'):
            self.prepare()
        self.assertEqual(self.launches, [])

    def test_wrong_operator_stale_plan_and_forged_plan_never_launch(self):
        plan = self.accepted()
        self.boundary._operator_uid = 5678
        with self.assertRaisesRegex(client.HostClientError, 'execution_request_rejected'):
            self.request('apply', operation='execution', plan_id=plan['plan_id'])
        self.boundary._operator_uid = 1234
        self.f.adapter.seed(self.f.ids['first'], token='changed')
        for identity in (plan['plan_id'], str(uuid.uuid4())):
            with self.assertRaises(client.HostClientError):
                self.request('apply', operation='execution', plan_id=identity)
        self.assertEqual(self.launches, [])

    def test_authorization_denial_never_dispatches(self):
        with patch.object(client, '_authorize', side_effect=client.HostClientError('authentication_failed', 'authentication', 4)), patch.object(client, '_exchange') as exchange:
            with self.assertRaises(client.HostClientError):
                client.request_host(self.raw('apply', operation='execution', plan_id=str(uuid.uuid4())))
            exchange.assert_not_called()

    def test_repeat_acceptance_and_lost_accept_response(self):
        plan = self.prepare()
        first = self.request('plan', operation='accept', plan_id=plan['plan_id'])
        second = self.request('plan', operation='accept', plan_id=plan['plan_id'])
        self.assertEqual(first, second)
        self.assertEqual(self.request('plan', operation='inspect', plan_id=plan['plan_id']), first)

    def test_lock_contention_prevents_apply_creation(self):
        plan = self.accepted()
        with helper._mutation_lock(self.f.lock, os.geteuid()):
            with self.assertRaisesRegex(client.HostClientError, 'mutation_busy'):
                self.request('apply', operation='execution', plan_id=plan['plan_id'])
        self.assertEqual(journal.list_attempts(self.f.store), [])

    def test_secret_launch_error_is_unknown_and_never_retried(self):
        plan = self.accepted()
        with patch.object(self, 'launch', side_effect=RuntimeError(PRIVATE)) as launch:
            result = self.request('apply', operation='execution', plan_id=plan['plan_id'])
            repeat = self.request('apply', operation='execution', plan_id=plan['plan_id'])
        self.assertEqual(result['launch'], 'unknown')
        self.assertEqual(repeat['attempt_id'], result['attempt_id'])
        launch.assert_called_once()

    def test_cli_uses_closed_transport(self):
        from mpkg_manager.cli import main
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with redirect_stdout(output):
            code = main(['prepare-execution', '--expected-revision', '1', '--resource',
                         self.f.ids['second'], '--interruption', 'stop_and_require_recovery', '--json'],
                        _sender=self.sender)
        self.assertEqual(code, 0)
        plan = json.loads(output.getvalue())['result']
        for command in ('accept-plan', 'inspect-plan', 'apply'):
            with redirect_stdout(StringIO()):
                self.assertEqual(main([command, plan['plan_id'], '--json'], _sender=self.sender), 0)

    def apply_plan(self, plan):
        return self.request('apply', operation='execution', plan_id=plan['plan_id'])

    def recover_attempt(self, result):
        attempt = journal.read_attempt(self.f.store, result['attempt_id']).as_dict()
        recovered = self.request('recover', operation='attempt', attempt_id=result['attempt_id'],
                                 expected_sequence=attempt['sequence'])
        self.assertEqual(recovered['disposition'], 'quiescent')

    def selected_plan(self, identities):
        revision = self.f.store.current()['revision']
        plan = self.request('prepare', operation='execution', expected_revision=revision,
            resource_ids=identities, interruption='stop_and_require_recovery')
        return self.request('plan', operation='accept', plan_id=plan['plan_id'])

    def test_preaccepted_spare_cannot_bypass_recovery_chronology(self):
        first, spare = self.accepted(), self.accepted()
        original = self.apply_plan(first)
        self.recover_attempt(original)
        self.execute = True
        before = len(journal.list_attempts(self.f.store))
        with self.assertRaisesRegex(client.HostClientError, 'execution_request_rejected'):
            self.apply_plan(spare)
        self.assertEqual(len(journal.list_attempts(self.f.store)), before)
        self.assertEqual(self.f.adapter.executions, [])
        self.assertEqual(len(self.launches), 1)
        repeat = self.apply_plan(first)
        self.assertEqual(repeat['attempt_id'], original['attempt_id'])
        self.assertEqual(repeat['launch'], 'existing')

    def test_accepting_an_old_proposal_after_recovery_is_insufficient(self):
        first = self.accepted()
        old = self.prepare()
        original = self.apply_plan(first)
        self.recover_attempt(original)
        accepted_later = self.request('plan', operation='accept', plan_id=old['plan_id'])
        with self.assertRaisesRegex(client.HostClientError, 'execution_request_rejected'):
            self.apply_plan(accepted_later)
        self.assertEqual(len(self.launches), 1)

    def test_fresh_retries_link_the_latest_single_lineage_and_execute(self):
        original = self.apply_plan(self.accepted())
        self.recover_attempt(original)
        second = self.apply_plan(self.accepted())
        self.assertEqual(journal.read_attempt(self.f.store, second['attempt_id']).as_dict()['predecessor'],
                         original['attempt_id'])
        self.recover_attempt(second)
        self.execute = True
        final_plan = self.accepted()
        final = self.apply_plan(final_plan)
        attempt = journal.read_attempt(self.f.store, final['attempt_id']).as_dict()
        self.assertEqual(attempt['predecessor'], second['attempt_id'])
        self.assertEqual(attempt['state'], 'observed-complete')
        self.assertEqual(self.f.adapter.executions, [self.f.ids['first'], self.f.ids['second']])
        self.assertEqual(self.apply_plan(final_plan)['attempt_id'], final['attempt_id'])
        # A verified descendant resolves its ancestors without preventing a
        # later fresh no-op plan from verifying the satisfied intent.
        after_success = self.apply_plan(self.accepted())
        latest = journal.read_attempt(self.f.store, after_success['attempt_id']).as_dict()
        self.assertEqual(latest['state'], 'observed-complete')
        self.assertIsNone(latest['predecessor'])
        self.assertEqual(len(self.f.adapter.executions), 2)

    def test_dependency_overlap_is_retry_scope_even_with_different_roots(self):
        original = self.apply_plan(self.selected_plan([self.f.ids['first']]))
        self.recover_attempt(original)
        fresh = self.selected_plan([self.f.ids['second']])
        retry = self.apply_plan(fresh)
        self.assertEqual(journal.read_attempt(self.f.store, retry['attempt_id']).as_dict()['predecessor'],
                         original['attempt_id'])

    def test_unrelated_overlapping_legacy_lineages_block_new_dispatch(self):
        # Assemble authenticated historical attempts as the old boundary did:
        # neither has a predecessor, although both affect the same resources.
        from dataclasses import replace
        from mpkg_manager.attempt_supervisor import _append
        first, second = self.accepted(), self.accepted()
        original = self.apply_plan(first)
        self.recover_attempt(original)
        binding = self.f.planner.binding(second['acceptance_id'])
        legacy = self.f.planner.create_attempt(binding, replace(self.f.worker, operator_uid=1234)).as_dict()
        _append(self.f.store, legacy['attempt_id'], 'launch_reserved', 'reserved')
        self.recover_attempt(legacy)
        with self.assertRaisesRegex(client.HostClientError, 'execution_request_rejected'):
            self.apply_plan(self.accepted())
        self.assertEqual(len(journal.list_attempts(self.f.store)), 2)
        self.assertEqual(len(self.launches), 1)
        self.assertEqual(self.f.adapter.executions, [])

    def test_disjoint_recovery_does_not_invent_retry_ancestry(self):
        from mpkg_manager.declarations import load_declaration
        declaration = load_declaration(fixtures.SOURCE.replace(b'requires=["first"]', b''))
        self.f.store.adopt(declaration, 1, ['first', 'second'])
        original = self.apply_plan(self.selected_plan([self.f.ids['first']]))
        self.recover_attempt(original)
        self.execute = True
        independent = self.apply_plan(self.selected_plan([self.f.ids['second']]))
        attempt = journal.read_attempt(self.f.store, independent['attempt_id']).as_dict()
        self.assertIsNone(attempt['predecessor'])
        self.assertEqual(attempt['state'], 'observed-complete')

    def test_partial_success_does_not_erase_unchecked_ancestor_scope(self):
        original = self.apply_plan(self.accepted())
        self.recover_attempt(original)
        self.execute = True
        partial = self.apply_plan(self.selected_plan([self.f.ids['first']]))
        self.assertEqual(journal.read_attempt(self.f.store, partial['attempt_id']).as_dict()['state'],
                         'observed-complete')
        complete = self.apply_plan(self.accepted())
        self.assertEqual(journal.read_attempt(self.f.store, complete['attempt_id']).as_dict()['predecessor'],
                         original['attempt_id'])
        self.assertEqual(self.f.adapter.executions, [self.f.ids['first'], self.f.ids['second']])

    def test_combined_scope_with_two_recovered_lineages_is_ambiguous(self):
        from mpkg_manager.declarations import load_declaration
        declaration = load_declaration(fixtures.SOURCE.replace(b'requires=["first"]', b''))
        self.f.store.adopt(declaration, 1, ['first', 'second'])
        for logical in ('first', 'second'):
            original = self.apply_plan(self.selected_plan([self.f.ids[logical]]))
            self.recover_attempt(original)
        combined = self.selected_plan(list(self.f.ids.values()))
        with self.assertRaisesRegex(client.HostClientError, 'execution_request_rejected'):
            self.apply_plan(combined)
        self.assertEqual(len(self.launches), 2)
        self.assertEqual(len(journal.list_attempts(self.f.store)), 2)

    def test_successful_noop_retry_does_not_revive_pre_recovery_acceptance(self):
        for identity in self.f.ids.values():
            self.f.adapter.seed(identity, satisfied=True)
        first, spare = self.accepted(), self.accepted()
        original = self.apply_plan(first)
        self.recover_attempt(original)
        self.execute = True
        fresh = self.apply_plan(self.accepted())
        self.assertEqual(journal.read_attempt(self.f.store, fresh['attempt_id']).as_dict()['state'],
                         'observed-complete')
        with self.assertRaisesRegex(client.HostClientError, 'execution_request_rejected'):
            self.apply_plan(spare)
        self.assertEqual(self.f.adapter.executions, [])
        self.assertEqual(len(self.launches), 2)

    def test_recovered_completion_still_requires_retry_ancestry(self):
        self.execute = True
        append = journal._FixtureJournal.append
        def lose_worker_completion(writer, identity, **arguments):
            if arguments['kind'] == 'worker_completed':
                return journal.read_attempt(writer.store, identity)
            return append(writer, identity, **arguments)
        with patch.object(journal._FixtureJournal, 'append', lose_worker_completion):
            original = self.apply_plan(self.accepted())
        before = journal.read_attempt(self.f.store, original['attempt_id']).as_dict()
        self.assertEqual(before['state'], 'observed-complete')
        self.assertFalse(before['supervision']['released'])
        self.recover_attempt(original)
        retry = self.apply_plan(self.accepted())
        attempt = journal.read_attempt(self.f.store, retry['attempt_id']).as_dict()
        self.assertEqual(attempt['predecessor'], original['attempt_id'])
        self.assertEqual(attempt['state'], 'observed-complete')
        self.assertEqual(len(self.f.adapter.executions), 2)
