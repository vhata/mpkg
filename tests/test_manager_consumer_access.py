"""Synthetic NSS replies, owned paths and isolated owned worker processes."""
from dataclasses import FrozenInstanceError, replace
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager import consumer_access as access
from mpkg_manager import _access_process as transport
from mpkg_manager import _access_worker as worker
from mpkg_manager._access_process import AccessResult
from mpkg_manager.query_process import QueryResult


HOST = '12345678-1234-4234-8234-123456789abc'
WHEN = '2026-11-02T18:00:00Z'
PRIVATE = 'private-access-sentinel'


def target(path='/srv/private/target', kind='file', consumer='external:reader'):
    return {'id': 'data', 'kind': kind, 'identity': {'path': path}, 'consumers': [consumer]}


def check(**changes):
    return {'id': 'read-data', 'kind': 'access', 'resource': 'data', 'timeout_seconds': 3,
            'as_user': 'reader', 'operation': 'read', 'consumer': 'external:reader'} | changes


class Queries:
    def __init__(self, *, uid=1201, gid=1202, groups=(1202, 1203)):
        self.uid, self.gid, self.groups = uid, gid, groups
        self.calls, self.override = [], None

    def __call__(self, argv, *, timeout):
        self.calls.append((argv, timeout))
        if self.override:
            result = self.override(argv, len(self.calls))
            if result is not None:
                return result
        database, key = argv[-2:]
        if database == 'passwd' and key in ('reader', str(self.uid)):
            raw = f'reader:{PRIVATE}:{self.uid}:{self.gid}:{PRIVATE}:/private:/usr/bin/nologin\n'.encode()
        elif database == 'initgroups' and key == 'reader':
            raw = ('reader ' + ' '.join(map(str, self.groups)) + '\n').encode()
        else:
            raise AssertionError('Unexpected query')
        return QueryResult('ok', raw, 0)


class ObservationTests(unittest.TestCase):
    def observe(self, *, definition=None, resource=None, queries=None, runner=None, **kwargs):
        return access.observe_consumer_access(check() if definition is None else definition,
            target() if resource is None else resource, host_id=HOST, observed_at=WHEN,
            query_runner=Queries() if queries is None else queries,
            worker_runner=(lambda request, timeout: AccessResult('ok')) if runner is None else runner,
            **kwargs)

    def test_complete_repeated_credentials_and_private_request(self):
        queries, requests = Queries(), []
        def runner(request, *, timeout):
            requests.append((request, timeout))
            return AccessResult('ok')
        result = self.observe(queries=queries, runner=runner)
        self.assertEqual(result.access_result, 'match')
        self.assertEqual(len(queries.calls), 12)
        self.assertEqual([item[0] for item in queries.calls[:6]], [item[0] for item in queries.calls[6:]])
        self.assertEqual([item[0] for item in queries.calls[:6]], [
            ('/usr/bin/getent', '--service=files', '--', 'passwd', 'reader'),
            ('/usr/bin/getent', '--', 'passwd', 'reader'),
            ('/usr/bin/getent', '--service=files', '--', 'passwd', '1201'),
            ('/usr/bin/getent', '--', 'passwd', '1201'),
            ('/usr/bin/getent', '--service=files', '--', 'initgroups', 'reader'),
            ('/usr/bin/getent', '--', 'initgroups', 'reader')])
        self.assertEqual(requests[0][0], {'path': '/srv/private/target', 'kind': 'file',
            'operation': 'read', 'uid': 1201, 'gid': 1202, 'groups': [1202, 1203]})
        self.assertTrue(0 < requests[0][1] <= 3)
        self.assertTrue(all(0 < timeout <= 2 for _, timeout in queries.calls))

    def test_denial_is_distinct_from_missing_or_failed_evidence(self):
        denied = self.observe(runner=lambda *a, **k: AccessResult('denied'))
        self.assertEqual((denied.access_result, denied.reason), ('mismatch', 'access_denied'))
        for reason in ('target_unavailable', 'credentials_unavailable', 'entry_limit', 'timeout'):
            with self.subTest(reason=reason):
                result = self.observe(runner=lambda *a, **k: AccessResult(reason))
                self.assertEqual((result.access_result, result.reason), ('unavailable', reason))

    def test_binding_is_complete_immutable_and_redacted(self):
        definition = check(as_user='private-user')
        # Identity resolution is intentionally separate from predicate binding.
        queries = Queries()
        queries.override = lambda argv, n: QueryResult('ok', b'private-user:x:1201:1202:p:/h:/s\n', 0) if argv[-2] == 'passwd' else QueryResult('ok', b'private-user 1202\n', 0)
        result = self.observe(definition=definition, resource=target('/srv/' + PRIVATE), queries=queries)
        self.assertTrue(result.matches_context(definition, target('/srv/' + PRIVATE), host_id=HOST))
        for changed in (definition | {'as_user': 'another'}, definition | {'timeout_seconds': 2},
                        definition | {'operation': 'list'}, definition | {'id': 'other'}):
            self.assertFalse(result.matches_context(changed, target('/srv/' + PRIVATE), host_id=HOST))
        self.assertFalse(result.matches_context(definition, target('/different'), host_id=HOST))
        self.assertNotIn(PRIVATE, repr(result) + json.dumps(result.as_dict()))
        self.assertNotIn('private-user', repr(result) + json.dumps(result.as_dict()))
        self.assertEqual(result.as_dict()['functional_result'], 'unverified')
        public = result.as_dict(); public['limitations'].clear()
        self.assertTrue(result.as_dict()['limitations'])
        with self.assertRaises(FrozenInstanceError):
            result.reason = 'other'
        with self.assertRaises(access.ConsumerAccessError):
            replace(result, reason=PRIVATE)

    def test_local_consumer_and_unsupported_resource_are_explicit(self):
        result = self.observe(definition=check(consumer='app'), resource=target(consumer='app'))
        self.assertEqual(result.access_result, 'match')
        for resource, definition, expected in (
            (target(kind='symlink'), check(), 'unsupported_resource'),
            (target(kind='directory'), check(), 'unsupported_operation'),
            (target(), check(as_user='1201'), 'unsupported_account')):
            queries = Queries()
            result = self.observe(resource=resource, definition=definition, queries=queries)
            self.assertEqual(result.reason, expected)
            self.assertEqual(queries.calls, [])
        volume = {'id': 'data', 'kind': 'volume', 'identity': {'engine': 'local', 'name': 'data'},
                  'consumers': ['external:reader']}
        result = self.observe(resource=volume, engine_aliases={'local': 'engine-id'})
        self.assertEqual(result.reason, 'unsupported_resource')

    def test_invalid_context_is_rejected_before_any_query(self):
        for definition, resource in ((check(consumer='foreign'), target()),
                                     (check(timeout_seconds=True), target()),
                                     (check(), target('relative/path')),
                                     (check(kind='endpoint'), target())):
            with self.subTest(definition=definition), self.assertRaises(access.ConsumerAccessError):
                self.observe(definition=definition, resource=resource)

    def test_declared_path_normalization_is_used_by_binding_and_worker(self):
        requests = []
        result = self.observe(resource=target('/srv/nested/../target'),
            runner=lambda request, timeout: requests.append(request) or AccessResult('ok'))
        self.assertEqual(requests[0]['path'], '/srv/target')
        self.assertTrue(result.matches_context(check(), target('/srv/target'), host_id=HOST))

    def test_conflicting_missing_and_malformed_accounts_never_probe(self):
        fixtures = [
            (2, QueryResult('ok', b'reader:x:999:1202:p:/h:/s\n', 0), 'account_conflict'),
            (3, QueryResult('ok', b'alias:x:1201:1202:p:/h:/s\n', 0), 'account_conflict'),
            (1, QueryResult('ok', b'', 2), 'account_unavailable'),
            (1, QueryResult('ok', b'not a passwd record\n', 0), 'account_output_invalid'),
            (5, QueryResult('ok', b'reader 1202 1202\n', 0), 'account_output_invalid'),
            (5, QueryResult('ok', b'reader 1202 4294967295\n', 0), 'account_output_invalid'),
            (5, QueryResult('ok', b'reader 1203\n', 0), 'account_conflict'),
            (6, QueryResult('ok', b'reader 1202 1204\n', 0), 'account_conflict')]
        for at, reply, reason in fixtures:
            with self.subTest(at=at, reason=reason):
                queries = Queries()
                queries.override = lambda argv, count: reply if count == at else None
                result = self.observe(queries=queries, runner=lambda *a, **k: self.fail('Worker invoked'))
                self.assertEqual(result.reason, reason)
        self.assertEqual(self.observe(queries=Queries(uid=0)).reason, 'unsupported_account')

    def test_groups_and_output_bounds_fail_closed(self):
        for raw in (b'reader ' + b' '.join(str(n).encode() for n in range(257)) + b'\n',
                    b'x' * (access.MAX_QUERY_BYTES + 1), b'reader 1202\nreader 1203\n'):
            queries = Queries()
            queries.override = lambda argv, n: QueryResult('ok', raw, 0) if n == 5 else None
            self.assertEqual(self.observe(queries=queries).access_result, 'unavailable')

    def test_changed_credentials_invalidate_success_and_denial(self):
        for code in ('ok', 'denied'):
            queries = Queries()
            def runner(request, *, timeout):
                queries.groups = (1202, 1204)
                return AccessResult(code)
            self.assertEqual(self.observe(queries=queries, runner=runner).reason, 'account_changed')

    def test_caller_and_worker_mutation_do_not_rebind_evidence(self):
        definition, resource, queries = check(), target(), Queries()
        original_check, original_target = json.loads(json.dumps(definition)), json.loads(json.dumps(resource))
        def override(argv, count):
            if count == 1:
                definition['as_user'] = 'foreign'
                resource['identity']['path'] = '/changed'
        queries.override = override
        def runner(request, *, timeout):
            self.assertEqual(request['path'], '/srv/private/target')
            request['groups'].append(999)
            return AccessResult('ok')
        result = self.observe(definition=definition, resource=resource, queries=queries, runner=runner)
        self.assertEqual(result.access_result, 'match')
        self.assertTrue(result.matches_context(original_check, original_target, host_id=HOST))

    def test_late_queries_and_worker_results_never_match(self):
        now = [0.0]
        queries = Queries()
        def late(argv, count):
            if count == 1:
                now[0] = 2.1
        queries.override = late
        with patch.object(access.time, 'monotonic', side_effect=lambda: now[0]):
            self.assertEqual(self.observe(queries=queries).reason, 'account_query_timeout')
        now[0] = 0
        def worker_late(request, *, timeout):
            now[0] = 3.1
            return AccessResult('ok')
        with patch.object(access.time, 'monotonic', side_effect=lambda: now[0]):
            self.assertEqual(self.observe(runner=worker_late).reason, 'collection_timeout')

    def test_invalid_results_and_private_exceptions_are_redacted(self):
        for value in ({'code': 'ok'}, None, PRIVATE):
            self.assertEqual(self.observe(runner=lambda *a, **k: value).reason, 'worker_result_invalid')
        def failed(*a, **k):
            raise RuntimeError(PRIVATE)
        result = self.observe(runner=failed)
        self.assertEqual(result.reason, 'worker_runner_failed')
        self.assertNotIn(PRIVATE, json.dumps(result.as_dict()))
        result = self.observe(queries=failed)
        self.assertEqual(result.reason, 'account_query_failed')
        with self.assertRaises(KeyboardInterrupt):
            self.observe(runner=lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))

    def test_query_allowlist_cannot_select_tools_databases_or_environment(self):
        with patch.object(access, 'run_bounded', return_value=QueryResult('ok', b'x', 0)) as run:
            valid = ('/usr/bin/getent', '--service=files', '--', 'initgroups', 'reader')
            self.assertEqual(access.run_readonly(valid).code, 'ok')
            self.assertEqual(run.call_args.kwargs['environment'], access.ENVIRONMENT)
            self.assertTrue(run.call_args.kwargs['require_empty_stderr'])
            for argv in (('sh', '-c', 'true'), valid + ('other',), valid[:-2] + ('shadow', 'reader'),
                         valid[:-1] + ('1201',), ('/usr/bin/getent', '--service=ldap', '--', 'passwd', 'reader')):
                self.assertEqual(access.run_readonly(argv).code, 'invalid_query')
            self.assertEqual(run.call_count, 1)


def own_request(path, kind='file'):
    return {'path': str(path), 'kind': kind, 'operation': 'read' if kind == 'file' else 'list',
            'uid': os.getuid(), 'gid': os.getgid(), 'groups': sorted(os.getgroups())}


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.file = self.root / 'content'
        self.file.write_bytes(PRIVATE.encode())

    def tearDown(self):
        self.temporary.cleanup()

    def run_worker(self, path=None, kind='file', **changes):
        return transport.run_access(own_request(self.file if path is None else path, kind) | changes, timeout=2)

    def test_real_worker_reads_and_lists_without_changing_parent_credentials(self):
        before = os.getresuid(), os.getresgid(), os.getgroups()
        self.assertEqual(self.run_worker().code, 'ok')
        self.assertEqual(self.run_worker(self.root, 'directory').code, 'ok')
        self.file.write_bytes(b'')
        self.assertEqual(self.run_worker().code, 'ok')
        self.assertEqual((os.getresuid(), os.getresgid(), os.getgroups()), before)

    def test_real_worker_checks_ancestor_search_and_target_read_permissions(self):
        self.file.chmod(0)
        self.assertEqual(self.run_worker().code, 'denied')
        self.file.chmod(0o600)
        self.root.chmod(0o600)
        try:
            self.assertEqual(self.run_worker().code, 'denied')
        finally:
            self.root.chmod(0o700)

    def test_real_worker_refuses_symlinks_fifo_and_type_mismatch(self):
        link = self.root / 'link'; link.symlink_to(self.file)
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        self.assertEqual(self.run_worker(link).code, 'target_unsupported')
        self.assertEqual(self.run_worker(fifo).code, 'target_unsupported')
        self.assertEqual(self.run_worker(self.root).code, 'target_unsupported')
        directory = self.root / 'dir'; directory.mkdir()
        ancestor = self.root / 'ancestor'; ancestor.symlink_to(directory, target_is_directory=True)
        self.assertEqual(self.run_worker(ancestor / 'absent').code, 'target_unsupported')
        self.assertEqual(self.run_worker(self.root / 'absent').code, 'target_unavailable')

    def test_real_worker_never_approximates_other_credentials(self):
        self.assertEqual(self.run_worker(uid=os.getuid() + 1).code, 'credentials_unavailable')
        groups = sorted(set(os.getgroups()) | {4000000000})
        self.assertEqual(self.run_worker(groups=groups).code, 'credentials_unavailable')

    def test_full_read_and_directory_list_limits_are_unavailable(self):
        self.file.write_bytes(b'x' * (worker.MAX_READ + 1))
        self.assertEqual(self.run_worker().code, 'read_limit')
        for number in range(worker.MAX_ENTRIES + 1):
            (self.root / str(number)).touch()
        self.assertEqual(self.run_worker(self.root, 'directory').code, 'entry_limit')

    def test_path_replacement_during_read_is_detected(self):
        original = os.read
        replaced = False
        def read(fd, size):
            nonlocal replaced
            raw = original(fd, size)
            if not replaced:
                replaced = True
                self.file.rename(self.root / 'old')
                self.file.write_bytes(PRIVATE.encode())
            return raw
        with patch.object(worker.os, 'read', side_effect=read), self.assertRaises(worker.AccessFailure) as raised:
            worker._access(own_request(self.file))
        self.assertEqual(raised.exception.code, 'target_changed')

    def test_denied_held_target_cannot_hide_path_replacement(self):
        original = os.open
        def opened(path, flags, *args, **kwargs):
            if str(path).startswith('/proc/self/fd/'):
                self.file.rename(self.root / 'old')
                self.file.write_bytes(b'new')
                raise PermissionError(errno.EACCES, PRIVATE)
            return original(path, flags, *args, **kwargs)
        with patch.object(worker.os, 'open', side_effect=opened), self.assertRaises(worker.AccessFailure) as raised:
            worker._access(own_request(self.file))
        self.assertEqual(raised.exception.code, 'target_changed')

    def test_invalid_numeric_path_and_scope_requests_do_not_drop_credentials(self):
        invalid = [own_request(self.file) | {'uid': 0}, own_request(self.file) | {'uid': True},
                   own_request(self.file) | {'path': '/a/../b'}, own_request(self.file) | {'argv': ['id']},
                   own_request(self.file) | {'groups': [os.getgid(), os.getgid()]},
                   own_request(self.file) | {'operation': 'list'}]
        with patch.object(worker, '_drop', side_effect=AssertionError('Dropped credentials')):
            for request in invalid:
                self.assertEqual(worker.probe(request), {'code': 'invalid_request'})

    def test_namespace_and_credential_changes_invalidate_empty_or_failed_checks(self):
        for operation in (None, worker.AccessFailure('denied')):
            with patch.object(worker, '_namespaces', side_effect=[('before',), ('after',)]), \
                    patch.object(worker, '_drop', return_value=('credentials',)), \
                    patch.object(worker, '_access', side_effect=operation):
                self.assertEqual(worker.probe(own_request(self.file)), {'code': 'namespace_changed'})
        with patch.object(worker, '_namespaces', return_value=('same',)), \
                patch.object(worker, '_drop', return_value=('before',)), \
                patch.object(worker, '_credentials', return_value=('after',)), \
                patch.object(worker, '_access'):
            self.assertEqual(worker.probe(own_request(self.file)), {'code': 'credentials_changed'})

    def test_root_drop_order_is_verified_without_changing_test_credentials(self):
        operations = []
        request = own_request(self.file)
        with patch.object(worker.resource, 'setrlimit'), patch.object(worker.ctypes, 'CDLL') as libc, \
                patch.object(worker.os, 'geteuid', return_value=0), \
                patch.object(worker.os, 'setgroups', side_effect=lambda groups: operations.append(('groups', groups))), \
                patch.object(worker.os, 'setresgid', side_effect=lambda *ids: operations.append(('gid', ids))), \
                patch.object(worker.os, 'setresuid', side_effect=lambda *ids: operations.append(('uid', ids))), \
                patch.object(worker, '_credentials', return_value='verified'):
            libc.return_value.prctl.return_value = 0
            self.assertEqual(worker._drop(request), 'verified')
        self.assertEqual(operations, [('groups', request['groups']), ('gid', (request['gid'],) * 3),
                                      ('uid', (request['uid'],) * 3)])

    def test_full_slots_groups_capabilities_and_no_new_privs_are_required(self):
        request = {'uid': 1201, 'gid': 1202, 'groups': [1202, 1203]}
        fields = {'Uid': '1201 1201 1201 1201', 'Gid': '1202 1202 1202 1202',
                  'Groups': '1202 1203', 'CapInh': '0', 'CapPrm': '0',
                  'CapEff': '0', 'CapBnd': '1ffff', 'CapAmb': '0', 'NoNewPrivs': '1'}
        def raw(value):
            return ''.join(f'{name}:\t{item}\n' for name, item in value.items()).encode()
        with patch.object(worker.os, 'getresuid', return_value=(1201,) * 3), \
                patch.object(worker.os, 'getresgid', return_value=(1202,) * 3), \
                patch.object(worker.os, 'getgroups', return_value=[1202, 1203]):
            with patch.object(worker, '_read_proc', return_value=raw(fields)):
                self.assertTrue(worker._credentials(request))
            for changed in ({'Uid': '1201 1201 1201 0'}, {'Gid': '1202 1202 0 1202'},
                            {'Groups': '1202'}, {'Groups': '1202 1203 999'},
                            {'CapEff': '1'}, {'CapPrm': '1'}, {'CapInh': '1'},
                            {'CapAmb': '1'}, {'NoNewPrivs': '0'}):
                with self.subTest(changed=changed), \
                        patch.object(worker, '_read_proc', return_value=raw(fields | changed)), \
                        self.assertRaises(worker.AccessFailure):
                    worker._credentials(request)

    def test_nonidentity_namespace_maps_are_unsupported(self):
        with patch.object(worker, '_read_proc', return_value=b'0 1000 1\n'), \
                self.assertRaises(worker.AccessFailure) as raised:
            worker._namespaces()
        self.assertEqual(raised.exception.code, 'namespace_unsupported')


class TransportTests(unittest.TestCase):
    def test_invalid_request_or_deadline_never_spawns_worker(self):
        with patch.object(transport.subprocess, 'Popen', side_effect=AssertionError('Spawned worker')):
            for timeout in (0, -1, True, float('nan'), float('inf'), 61):
                self.assertEqual(transport.run_access(own_request('/private'), timeout=timeout).code,
                                 'invalid_request')
            self.assertEqual(transport.run_access(own_request('/private') | {'uid': 0}, timeout=1).code,
                             'invalid_request')

    def test_exact_result_schema_and_fixed_codes(self):
        for raw in (b'{"code":"ok","path":"secret"}', b'{"code":"ok","code":"ok"}',
                    b'{"code":"private-secret"}', b'[]', b'null'):
            self.assertEqual(transport._decode(raw).code, 'worker_output_invalid')
        self.assertEqual(transport._decode(b'{"code":"denied"}').code, 'denied')

    def test_request_is_private_and_worker_launch_is_fixed(self):
        popen = subprocess.Popen
        calls = []
        def spawn(argv, **kwargs):
            calls.append((argv, kwargs))
            return popen(argv, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / PRIVATE; path.write_text(PRIVATE)
            with patch.object(transport.subprocess, 'Popen', side_effect=spawn):
                result = transport.run_access(own_request(path), timeout=2)
        self.assertEqual(result.code, 'ok')
        argv, kwargs = calls[0]
        self.assertEqual(argv, (sys.executable, '-I', str(transport._WORKER)))
        self.assertNotIn(PRIVATE, repr(argv) + repr(kwargs))
        self.assertEqual(kwargs['env'], transport.ENVIRONMENT)
        self.assertTrue(kwargs['close_fds']); self.assertTrue(kwargs['start_new_session'])
        self.assertEqual(kwargs['cwd'], '/')

    def test_private_worker_errors_output_limits_and_timeout(self):
        popen = subprocess.Popen
        cases = [(f'import sys; sys.stderr.write({PRIVATE!r})', 'worker_failed'),
                 ('print("x" * 5000)', 'worker_output_limit'),
                 ('import time; time.sleep(5)', 'timeout'),
                 ('raise SystemExit(2)', 'worker_failed')]
        for script, expected in cases:
            def spawn(argv, **kwargs):
                return popen((sys.executable, '-I', '-c', script), **kwargs)
            with self.subTest(expected=expected), patch.object(transport.subprocess, 'Popen', side_effect=spawn):
                result = transport.run_access(own_request('/private'), timeout=0.2)
                self.assertEqual(result.code, expected)
                self.assertNotIn(PRIVATE, repr(result))

    def test_cancellation_stops_owned_worker_and_does_not_export_request(self):
        popen = subprocess.Popen
        children = []
        def spawn(argv, **kwargs):
            child = popen((sys.executable, '-I', '-c', 'import time; time.sleep(5)'), **kwargs)
            children.append(child)
            return child
        with patch.object(transport.subprocess, 'Popen', side_effect=spawn), \
                patch.object(transport.selectors.DefaultSelector, 'select', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                transport.run_access(own_request('/' + PRIVATE), timeout=2)
        self.assertIsNotNone(children[0].poll())


if __name__ == '__main__':
    unittest.main()
