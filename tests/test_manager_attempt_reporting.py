"""Historical reporting through owned stores; no recovery or host effects."""
from contextlib import redirect_stdout
from copy import deepcopy
import fcntl
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager import attempt_journal as journal, attempt_reporting as reporting, host_helper
from mpkg_manager.cli import main
from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_client import _Reply
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.host_protocol import parse_request, RequestError
from mpkg_manager.store import HostStore, _TRIGGERS

HOST = '12345678-1234-4234-8234-123456789abc'
SOURCE = '''schema=1
components=[]
[[resources]]
id="first"
kind="package"
identity={name="git"}
manage=["present", "version"]
desired={present=true, version={policy="exact", value="1.0"}}
checks=["original"]
[[resources]]
id="second"
kind="package"
identity={name="bash"}
manage=["present"]
desired={present=true}
[[resources]]
id="third"
kind="package"
identity={name="diffutils"}
manage=["present"]
desired={present=true}
[[checks]]
id="original"
kind="package"
resource="first"
timeout_seconds=3
expected={present=true, version="1.0"}
'''


class AttemptReportingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / 'store'
        self.policy = self.root / 'policy.toml'
        self.policy.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\nallowed_input_roots=[{json.dumps(str(self.root))}]\n')
        self.policy.chmod(0o600)
        self.store = HostStore.create(self.directory, HOST, owner_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.store.adopt(load_declaration(SOURCE.encode()), 0, ['first', 'second', 'third'])
        resources = {row['logical_id']: row['stable_id'] for row in self.store.current()['resources']}
        self.selected = [resources[name] for name in ('first', 'second', 'third')]
        self.worker = journal.WorkerIdentity(os.geteuid(), os.geteuid(), str(uuid.uuid4()), str(uuid.uuid4()))
        self.writer = journal._FixtureJournal(self.store)
        self.boundary = HostBoundary(policy_path=self.policy, store_directory=self.directory,
                                     mutation_lock=self.root / 'lock', owner_uid=os.geteuid())

    def create(self, predecessor=None):
        plan = journal._fixture_plan(self.store, expected_revision=self.store.current()['revision'],
                                     stable_resource_ids=self.selected)
        return self.writer.create(plan, self.worker, stable_resource_ids=self.selected,
                                  predecessor=predecessor).as_dict()

    def append(self, attempt, kind, outcome, index=0):
        return self.writer.append(attempt['attempt_id'], expected_sequence=attempt['sequence'],
            action_id=None if index is None else attempt['actions'][index]['action_id'],
            kind=kind, outcome=outcome).as_dict()

    def invoke(self, *args):
        output = io.StringIO()
        def sender(raw):
            reply = handle_request(raw, boundary=self.boundary)
            return _Reply(reply, 0 if json.loads(reply)['ok'] else 2)
        with redirect_stdout(output):
            status = main([*args, '--json'], _sender=sender)
        return status, json.loads(output.getvalue())

    def page(self, **kwargs):
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as reader:
            return reporting.attempt_page(reader, **kwargs)

    def detail(self, attempt, **kwargs):
        with HostStore.open_readonly(self.directory, HOST, owner_uid=os.geteuid()) as reader:
            return reporting.attempt_detail(reader, attempt['attempt_id'], **kwargs)

    def corrupt(self, table, statement):
        with sqlite3.connect(self.directory / 'state.sqlite3') as db:
            for event in ('update', 'delete'):
                db.execute('DROP TRIGGER ' + table + '_' + event)
            db.execute(statement)
            for event in ('update', 'delete'):
                db.execute(_TRIGGERS[table + '_' + event])

    def test_empty_history_is_complete_not_unavailable(self):
        result = self.page()
        self.assertEqual(result['attempts'], [])
        self.assertEqual(result['observed_through_ordinal'], 0)
        self.assertIsNone(result['next_after'])
        self.assertFalse(result['has_more'])
        self.assertEqual(self.invoke('attempts')[0], 0)

    def test_partial_effects_and_original_checks_survive_newer_intent(self):
        attempt = self.create()
        for kind, outcome in [('action_started', 'started'), ('command_completed', 'succeeded'),
                              ('observation_completed', 'satisfied')]:
            attempt = self.append(attempt, kind, outcome)
        attempt = self.append(attempt, 'action_started', 'started', 1)
        attempt = self.append(attempt, 'command_completed', 'unknown', 1)
        before = self.detail(attempt)['attempt']
        self.store.record_intent(load_declaration(SOURCE.replace('1.0', '2.0').encode()), 1)
        after = self.detail(attempt)['attempt']
        self.assertEqual(before | {'decision_state': 'superseded'}, after)
        self.assertEqual(after['revision'], 1)
        self.assertEqual([row['state'] for row in after['actions']], ['observed-complete', 'unknown', 'planned'])
        self.assertEqual([row['work'] for row in after['actions']], ['attempted', 'attempted', 'not_attempted'])
        check = after['actions'][0]['target']['required_checks'][0]
        self.assertEqual(check['predicates'][1]['value'], '1.0')
        self.assertEqual(check['result'], 'not_individually_recorded')
        self.assertEqual(check['revision'], 1)
        newer = self.create()
        report = self.detail(newer)['attempt']
        self.assertEqual(report['decision_checks'][0]['predicates'][1]['value'], '2.0')
        self.assertEqual(report['actions'][0]['decision_target']['desired'][1]['value'],
                         {'policy': 'exact', 'value': '2.0'})
        self.assertEqual(report['actions'][0]['target']['desired'][1]['value'],
                         {'policy': 'exact', 'value': '1.0'})
        self.assertEqual(report['actions'][0]['target']['required_checks'][0]['predicates'][1]['value'], '1.0')

    def test_failed_finished_attempt_retains_not_attempted_work_and_retry_link(self):
        attempt = self.append(self.create(), 'action_started', 'started')
        attempt = self.append(attempt, 'command_completed', 'failed')
        attempt = self.append(attempt, 'observation_completed', 'satisfied')
        attempt = self.append(attempt, 'attempt_finished', 'failed', None)
        retry = self.create(attempt['attempt_id'])
        self.assertEqual(self.detail(retry)['attempt']['predecessor'], attempt['attempt_id'])
        original = self.detail(attempt)['attempt']
        self.assertTrue(original['finished'])
        self.assertEqual(original['state'], 'failed')
        self.assertEqual(original['actions'][1]['work'], 'not_attempted')
        self.assertEqual(original['actions'][0]['observation_outcome'], 'satisfied')

    def test_append_order_and_new_attempts_continue_after_terminal_page(self):
        attempts = [self.create() for _ in range(3)]
        one = self.page(limit=1)
        self.assertTrue(one['has_more'])
        two = self.page(limit=2, after_id=one['next_after'])
        self.assertFalse(two['has_more'])
        self.assertEqual([row['attempt_id'] for row in one['attempts'] + two['attempts']],
                         [row['attempt_id'] for row in attempts])
        newer = self.create()
        three = self.page(limit=1, after_id=two['next_after'])
        self.assertEqual(three['attempts'][0]['attempt_id'], newer['attempt_id'])
        empty = self.page(after_id=three['next_after'])
        self.assertEqual(empty['attempts'], [])
        self.assertEqual(empty['next_after'], newer['attempt_id'])

    def test_complete_event_pages_and_later_append(self):
        attempt = self.append(self.create(), 'action_started', 'started')
        attempt = self.append(attempt, 'command_completed', 'succeeded')
        first = self.detail(attempt, event_limit=1)
        self.assertTrue(first['has_more'])
        second = self.detail(attempt, after_event=first['next_event'], event_limit=1)
        self.assertFalse(second['has_more'])
        self.assertEqual([event['sequence'] for event in first['events'] + second['events']], [1, 2])
        attempt = self.append(attempt, 'observation_completed', 'satisfied')
        third = self.detail(attempt, after_event=second['next_event'])
        self.assertEqual(third['events'][0]['sequence'], 3)
        self.assertEqual(third['attempt']['actions'][0]['state'], 'observed-complete')

    def test_byte_budget_pages_without_dropping_target_or_checks(self):
        first, second = self.create(), self.create()
        normal = self.page(limit=1)
        budget = reporting._size(normal) + 80
        with patch.object(reporting, 'MAX_PAGE_BYTES', budget):
            page = self.page(limit=100)
            self.assertEqual(page['attempts'], normal['attempts'])
            self.assertTrue(page['has_more'])
            self.assertEqual(page['next_after'], first['attempt_id'])
            following = self.page(after_id=page['next_after'])
            self.assertEqual(following['attempts'][0]['attempt_id'], second['attempt_id'])
        with patch.object(reporting, 'MAX_PAGE_BYTES', 100):
            status, error = self.invoke('attempts')
            self.assertNotEqual(status, 0)
            self.assertEqual(error['error']['code'], 'attempt_history_size_limit')

    def test_event_byte_budget_does_not_stall_or_drop_events(self):
        attempt = self.append(self.create(), 'action_started', 'started')
        attempt = self.append(attempt, 'command_completed', 'succeeded')
        normal = self.detail(attempt, event_limit=1)
        with patch.object(reporting, 'MAX_PAGE_BYTES', reporting._size(normal) + 8):
            page = self.detail(attempt, event_limit=100)
            self.assertEqual(len(page['events']), 1)
            self.assertTrue(page['has_more'])
            self.assertEqual(page['next_event'], 1)
        with patch.object(reporting, 'MAX_PAGE_BYTES', 100):
            with self.assertRaisesRegex(reporting.AttemptReportError, 'attempt_history_size_limit'):
                self.detail(attempt)

    def test_missing_attempt_and_cursors_are_fixed_errors(self):
        attempt = self.create()
        for args, code in [(('attempt', str(uuid.uuid4())), 'attempt_missing'),
                           (('attempts', '--after', str(uuid.uuid4())), 'attempt_cursor_missing'),
                           (('attempt', attempt['attempt_id'], '--after-event', '1'), 'attempt_event_cursor_missing')]:
            with self.subTest(args=args):
                status, result = self.invoke(*args)
                self.assertEqual(status, 6)
                self.assertEqual(result['error']['code'], code)

    def test_missing_store_and_corrupt_history_are_not_empty(self):
        self.create()
        self.corrupt('attempts', "UPDATE attempts SET context=x'00'")
        status, result = self.invoke('attempts')
        self.assertEqual(status, 6)
        self.assertEqual(result['error']['code'], 'store_corrupt')
        self.boundary._store_directory = self.root / 'missing'
        status, result = self.invoke('attempts')
        self.assertEqual(status, 6)
        self.assertEqual(result['error']['code'], 'store_missing')

    def test_reporting_neither_takes_application_lock_nor_recovers_or_captures(self):
        attempt = self.create()
        path = self.root / 'lock'
        path.touch(mode=0o600)
        before = (self.directory / 'state.sqlite3').read_bytes()
        with path.open('rb') as held, patch.object(host_helper, '_mutation_lock',
                side_effect=AssertionError('application lock requested')), \
                patch('mpkg_manager.attempt_supervisor.AttemptSupervisor.dispatch',
                      side_effect=AssertionError('recovery/dispatch requested')), \
                patch('mpkg_manager.protected_bindings.ProtectedRecorder._capture',
                      side_effect=AssertionError('capture requested')), \
                patch('subprocess.Popen', side_effect=AssertionError('child requested')):
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.invoke('attempts')[0], 0)
            self.assertEqual(self.invoke('attempt', attempt['attempt_id'])[0], 0)
        self.assertEqual((self.directory / 'state.sqlite3').read_bytes(), before)
        self.assertEqual(self.detail(attempt)['attempt']['sequence'], 0)

    def test_concurrent_append_keeps_each_page_transaction_consistent(self):
        attempt = self.create()
        started, stop = threading.Event(), threading.Event()
        failures = []
        def writer():
            try:
                with HostStore.open_existing(self.directory, HOST, owner_uid=os.geteuid()) as other:
                    started.set()
                    stop.wait(5)
                    journal._FixtureJournal(other).append(attempt['attempt_id'], expected_sequence=0,
                        action_id=attempt['actions'][0]['action_id'], kind='action_started', outcome='started')
            except BaseException as error:
                failures.append(error)
        thread = threading.Thread(target=writer)
        thread.start()
        self.assertTrue(started.wait(5))
        original = reporting._entry
        def during(*args):
            result = original(*args)
            stop.set()
            return result
        try:
            with patch.object(reporting, '_entry', side_effect=during):
                page = self.detail(attempt)
        finally:
            stop.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(page['observed_through_sequence'], 0)
        self.assertEqual(page['events'], [])
        self.assertEqual(self.detail(attempt)['observed_through_sequence'], 1)

    def test_protocol_rejects_unbounded_and_caller_selected_fields(self):
        valid = {'version': 1, 'verb': 'export', 'arguments': {'operation': 'attempts', 'limit': 20, 'after_id': None}}
        invalid = []
        for limit in (False, 0, 101, '20', -1):
            value = deepcopy(valid)
            value['arguments']['limit'] = limit
            invalid.append(value)
        for field in ('path', 'raw_context', 'operator', 'command', 'source'):
            value = deepcopy(valid)
            value['arguments'][field] = 'PRIVATE_SENTINEL'
            invalid.append(value)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(RequestError):
                parse_request(json.dumps(value).encode())
        self.assertEqual(self.invoke('attempts', '--limit', '101')[0], 2)

    def test_public_validator_rejects_private_fields_and_false_success(self):
        attempt = self.append(self.create(), 'action_started', 'started')
        valid = self.detail(attempt)
        cases = []
        changed = deepcopy(valid)
        changed['attempt']['private_context'] = 'PRIVATE_SENTINEL'
        cases.append(changed)
        changed = deepcopy(valid)
        changed['events'][0]['outcome'] = 'PRIVATE_SENTINEL'
        cases.append(changed)
        changed = deepcopy(valid)
        changed['attempt']['actions'][0]['state'] = 'observed-complete'
        cases.append(changed)
        changed = deepcopy(valid)
        changed['attempt']['actions'][0]['target']['required_checks'][0]['revision'] = 99
        cases.append(changed)
        changed = deepcopy(valid)
        changed['next_event'] = 99
        cases.append(changed)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                reporting.validate_attempt_detail(value)

    def test_endpoint_paths_and_protected_bindings_do_not_escape(self):
        import test_manager_protected_recording as protected
        fixture = protected.ProtectedRecordingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.assertEqual(fixture.record(fixture.prepare(), adopt=True)[0], 0)
        with HostStore.open_existing(fixture.store, protected.HOST, owner_uid=os.geteuid()) as store:
            selected = [item['stable_id'] for item in store.current()['resources']]
            plan = journal._fixture_plan(store, expected_revision=1, stable_resource_ids=selected)
            attempt = journal._FixtureJournal(store).create(plan, self.worker, stable_resource_ids=selected).as_dict()
            result = reporting.attempt_detail(store, attempt['attempt_id'])
            raw = json.dumps(result)
            for private in (protected.SECRET, str(fixture.secret), fixture.reference):
                self.assertNotIn(private, raw)
            context = json.loads(store._db.execute('SELECT context FROM attempts').fetchone()[0])
            for binding in context['target']['inputs']:
                self.assertNotIn(binding['token'], raw)
            self.assertEqual(result['attempt']['inputs'][0]['state'], 'bound')
        check = {'id': 'web', 'kind': 'endpoint', 'resource': 'first', 'timeout_seconds': 2,
                 'url': 'http://127.0.0.1:1234/PRIVATE_PATH', 'expected_status': 200}
        public = reporting._check(check, 'accepted', 1, 'a' * 64)
        self.assertNotIn('PRIVATE_PATH', json.dumps(public))
        self.assertEqual(public['predicates'][1], {'property': 'url', 'redacted': True, 'value': None})

    def test_status_cli_includes_original_history_independently_of_current_observations(self):
        import test_manager_status_cli as status_tests
        fixture = status_tests.StatusCliTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        declaration = fixture.declaration()
        fixture.writer.adopt(declaration, 0, ['app'])
        selected = [row['stable_id'] for row in fixture.writer.current()['resources']]
        plan = journal._fixture_plan(fixture.writer, expected_revision=1, stable_resource_ids=selected)
        attempt = journal._FixtureJournal(fixture.writer).create(plan, self.worker, stable_resource_ids=selected).as_dict()
        attempt = journal._FixtureJournal(fixture.writer).append(attempt['attempt_id'], expected_sequence=0,
            action_id=attempt['actions'][0]['action_id'], kind='action_started', outcome='started').as_dict()
        status, result = fixture.invoke()
        self.assertEqual(status, 0)
        page = result['result']['report']['attempts']
        self.assertEqual(page['attempts'][0]['state'], 'unknown')
        self.assertNotIn('attempt_history_unavailable', result['result']['report']['blockers'])
        self.assertFalse((fixture.root / 'missing.lock').exists())


    def test_old_schema_history_is_refused_without_migration_or_empty_success(self):
        directory = self.root / 'old-store'
        with patch('mpkg_manager.store.SCHEMA_VERSION', 3):
            with HostStore.create(directory, HOST, owner_uid=os.geteuid()) as old:
                old.record_intent(load_declaration(b'schema=1\ncomponents=[]\nresources=[]\n'), 0)
        self.boundary._store_directory = directory
        before = (directory / 'state.sqlite3').read_bytes()
        for args in [('attempts',), ('attempt', str(uuid.uuid4())), ('status',)]:
            status, error = self.invoke(*args)
            self.assertEqual(status, 6)
            self.assertEqual(error['error']['code'], 'attempt_history_requires_migration')
        self.assertEqual((directory / 'state.sqlite3').read_bytes(), before)

    def test_removed_decision_target_retains_original_adoption_obligations(self):
        self.store.record_intent(load_declaration(b'schema=1\ncomponents=[]\nresources=[]\n'), 1)
        attempt = self.create()
        entry = self.detail(attempt)['attempt']
        action = entry['actions'][0]
        self.assertFalse(action['decision_target']['declared'])
        self.assertIsNone(action['decision_target']['kind'])
        self.assertEqual(action['target']['adoption_revision'], 1)
        self.assertEqual(action['target']['required_checks'][0]['id'], 'original')
        self.assertEqual(entry['decision_checks'], [])
        self.assertEqual(entry['revision'], 2)

    def test_partial_event_history_corruption_refuses_the_whole_response(self):
        attempt = self.append(self.create(), 'action_started', 'started')
        self.append(attempt, 'command_completed', 'succeeded')
        self.corrupt('attempt_events', 'DELETE FROM attempt_events WHERE sequence=1')
        status, result = self.invoke('attempts')
        self.assertEqual(status, 6)
        self.assertEqual(result['error']['code'], 'store_corrupt')
        self.assertNotIn('result', result)

    def test_private_internal_exception_is_fixed_diagnostic_without_partial_history(self):
        self.create()
        with patch.object(reporting, '_entry', side_effect=OSError('/PRIVATE_PATH/TOKEN')):
            status, result = self.invoke('attempts')
        self.assertNotEqual(status, 0)
        self.assertEqual(result['error']['code'], 'store_read_failed')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_malformed_page_cannot_claim_completeness_or_success(self):
        self.create()
        valid = self.page()
        changes = [lambda x: x.update(has_more=True),
                   lambda x: x.update(next_after=str(uuid.uuid4())),
                   lambda x: x.update(observed_through_ordinal=0),
                   lambda x: x['attempts'][0].update(state='observed-complete'),
                   lambda x: x['attempts'][0]['actions'][0]['target']['required_checks'][0].update(timeout_seconds=100)]
        for change in changes:
            value = deepcopy(valid)
            change(value)
            with self.assertRaises(ValueError):
                reporting.validate_attempt_page(value)

    def test_unrelated_new_event_or_wrong_attempt_reply_is_rejected_by_client(self):
        attempt = self.create()
        page = self.detail(attempt)
        output = io.StringIO()
        wrong = deepcopy(page)
        wrong['attempt']['attempt_id'] = str(uuid.uuid4())
        wrong['attempt']['event_details']['attempt_id'] = wrong['attempt']['attempt_id']
        sender = lambda raw: _Reply(json.dumps({'version': 1, 'ok': True, 'result': wrong}).encode(), 0)
        with redirect_stdout(output):
            code = main(['attempt', attempt['attempt_id'], '--json'], _sender=sender)
        self.assertNotEqual(code, 0)
        self.assertNotIn('result', json.loads(output.getvalue()))



    def test_mixed_classification_input_indexes_match_original_declaration_order(self):
        import test_manager_protected_recording as protected
        fixture = protected.ProtectedRecordingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        source = fixture.source.read_text().replace('manage=["content_input"]', 'manage=["present"]')
        source = source.replace('desired={content_input="config-input"}', 'desired={present=true}')
        source = source.replace('files=[', 'files=[{path="PUBLIC_NAME",classification="nonsecret"},')
        fixture.source.write_text(source)
        (fixture.inputs / 'PUBLIC_NAME').write_text('PUBLIC_BYTES')
        self.assertEqual(fixture.record(fixture.prepare(), adopt=True, capture=True)[0], 0)
        with HostStore.open_existing(fixture.store, protected.HOST, owner_uid=os.geteuid()) as store:
            selected = [item['stable_id'] for item in store.current()['resources']]
            plan = journal._fixture_plan(store, expected_revision=1, stable_resource_ids=selected)
            attempt = journal._FixtureJournal(store).create(plan, self.worker, stable_resource_ids=selected).as_dict()
            report = reporting.attempt_detail(store, attempt['attempt_id'])
        slots = report['attempt']['inputs']
        self.assertEqual([(item['classification'], item['file_index']) for item in slots],
                         [('nonsecret', 0), ('protected', 1)])
        self.assertEqual([item['origin_revision'] for item in slots], [1, 1])
        self.assertNotIn('PUBLIC_NAME', json.dumps(report))
        self.assertNotIn('PUBLIC_BYTES', json.dumps(report))
        self.assertNotIn(protected.SECRET, json.dumps(report))

    def test_human_output_preserves_both_target_roles_and_check_definitions(self):
        self.store.record_intent(load_declaration(SOURCE.replace('1.0', '2.0').encode()), 1)
        attempt = self.create()
        output = io.StringIO()
        def sender(raw):
            reply = handle_request(raw, boundary=self.boundary)
            return _Reply(reply, 0 if json.loads(reply)['ok'] else 2)
        with redirect_stdout(output):
            code = main(['attempt', attempt['attempt_id']], _sender=sender)
        self.assertEqual(code, 0)
        text = output.getvalue()
        self.assertIn('Adopted target at revision 1', text)
        self.assertIn('Decision check original at revision 2', text)
        self.assertIn('1.0', text)
        self.assertIn('2.0', text)
        self.assertIn('not_attempted', text)
        self.assertIn('Continue: mpkg-manager attempt', text)



    def test_complete_nested_scope_within_byte_budget_exceeds_legacy_count_limit(self):
        consumers = ['external:consumer' + str(index) for index in range(4100)]
        source = SOURCE.replace('checks=["original"]',
                                'checks=["original"]\nconsumers=' + json.dumps(consumers))
        fixture = AttemptReportingTests()
        with patch(__name__ + '.SOURCE', source):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        attempt = fixture.create()
        page = fixture.page()
        self.assertLess(reporting._size(page), reporting.MAX_PAGE_BYTES)
        action = page['attempts'][0]['actions'][0]
        self.assertEqual(action['target']['consumers'], consumers)
        self.assertEqual(action['decision_target']['consumers'], consumers)
        self.assertEqual(fixture.detail(attempt)['attempt'], page['attempts'][0])


if __name__ == '__main__':
    unittest.main()
