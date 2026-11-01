"""Host-safe tests: temporary files/SQLite only, no real service/package tools."""
import importlib.util
import ast
import contextlib
import hashlib
import io
import json
import os
import re
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import tarfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid


PROOFS = Path(__file__).resolve().parents[1] / 'scripts' / 'proofs'
SPEC = importlib.util.spec_from_file_location('proof_core', PROOFS / 'core.py')
core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core)
sys.path.insert(0, str(PROOFS))
import compose_proof
import native_proof
import oci_acquire
import image_import
import native_manifest
import native_service
import run as proof_run
import docker_ready
import docker_baseline
import native_conflict
import service_environment
import docker_resume
import account_defaults
import native_service_recover
import native_service_observe
import docker_variant_plan
import docker_diagnostic_resume
import docker_variants
import docker_variant_experiment
import docker_variant_retire
import docker_supplement_resume
import protected_output


class GuestGuardTests(unittest.TestCase):
    def setUp(self):
        self.guest = str(uuid.uuid4())
        self.marker = {'schema': 1, 'guest_id': self.guest,
                       'fixture_id': 'first-release-2026-10-31',
                       'disposable': True,
                       'disk_serial': 'mpkg' + self.guest.replace('-', '')[:16],
                       'disk_bytes': 42949672960}
        self.metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                                        st_uid=0, st_gid=0, st_nlink=1)

    def validate(self, dmi_uuid, vendor, root_device=(254, 2)):
        return core.validate_guest(self.guest, self.marker, self.metadata,
                                   dmi_uuid, vendor, root_device, (254, 2),
                                   self.marker['disk_serial'], 42949672960)

    def test_matching_marker_is_insufficient_without_vm_identity(self):
        with self.assertRaisesRegex(core.Refused, 'guest_machine_mismatch'):
            self.validate(str(uuid.uuid4()), 'QEMU')
        with self.assertRaisesRegex(core.Refused, 'guest_machine_mismatch'):
            self.validate(self.guest, 'production vendor')
        self.assertEqual(self.validate(self.guest, 'QEMU'), self.guest)

    def test_vm_marker_does_not_allow_live_iso_or_wrong_root_disk(self):
        with self.assertRaisesRegex(core.Refused, 'guest_root_disk_mismatch'):
            self.validate(self.guest, 'QEMU', root_device=(0, 20))

    def test_marker_permissions_and_unexpected_fields_refuse(self):
        self.metadata.st_mode = stat.S_IFREG | 0o644
        with self.assertRaisesRegex(core.Refused, 'guest_marker_permissions'):
            self.validate(self.guest, 'QEMU')
        self.metadata.st_mode = stat.S_IFREG | 0o600
        self.marker['command'] = 'untrusted'
        with self.assertRaisesRegex(core.Refused, 'guest_marker_mismatch'):
            self.validate(self.guest, 'QEMU')

    def test_real_cli_refuses_host_before_any_experiment(self):
        # A random expected UUID cannot identify the host or an assembled guest.
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([
                sys.executable, '-I', str(PROOFS / 'run.py'), 'run',
                '--guest-id', str(uuid.uuid4()), '--proof', 'journal',
            ], cwd=temporary, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 73)
            self.assertEqual(json.loads(result.stdout)['status'], 'refused')
            self.assertEqual(result.stderr, '')
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_guest_image_entrypoints_refuse_host_before_docker(self):
        for filename in ('image_import.py', 'image_manifest.py', 'native_manifest.py', 'docker_ready.py', 'native_conflict.py', 'docker_resume.py', 'native_service_recover.py', 'native_service_observe.py', 'docker_diagnostic_resume.py', 'docker_supplement_resume.py', 'protected_output.py'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                result = subprocess.run([
                    sys.executable, '-I', str(PROOFS / filename),
                    '--guest-id', str(uuid.uuid4()),
                ], cwd=temporary, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 73)
                self.assertEqual(json.loads(result.stdout)['status'], 'refused')
                self.assertEqual(result.stderr, '')
                self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_native_service_setup_refuses_host_before_system_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([
                sys.executable, '-I', str(PROOFS / 'native_service.py'), 'setup',
                '--guest-id', str(uuid.uuid4()),
            ], cwd=temporary, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 73)
            self.assertEqual(json.loads(result.stdout)['status'], 'refused')
            self.assertEqual(result.stderr, '')
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_docker_baseline_setup_refuses_host_before_system_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([
                sys.executable, '-I', str(PROOFS / 'docker_baseline.py'), 'setup',
                '--guest-id', str(uuid.uuid4()),
            ], cwd=temporary, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 73)
            self.assertEqual(json.loads(result.stdout)['status'], 'refused')
            self.assertEqual(result.stderr, '')
            self.assertEqual(list(Path(temporary).iterdir()), [])


class ProtectedOutputTests(unittest.TestCase):
    def test_git_environment_discards_inherited_config_and_credentials(self):
        with mock.patch.dict(os.environ, {'GIT_DIR': '/private/repository',
                                         'GIT_CONFIG_COUNT': '1', 'GIT_TRACE': '/private/log',
                                         'SSH_AUTH_SOCK': '/private/agent',
                                         'GIT_OBJECT_DIRECTORY': '/private/objects'}):
            result = protected_output.isolated_environment(Path('/fixture/home'))
        self.assertEqual(result['HOME'], '/fixture/home')
        self.assertEqual(result['GIT_CONFIG_GLOBAL'], '/dev/null')
        self.assertEqual(result['GIT_CONFIG_NOSYSTEM'], '1')
        self.assertEqual(result['GIT_TERMINAL_PROMPT'], '0')
        self.assertFalse(set(result) & {'GIT_DIR', 'GIT_CONFIG_COUNT', 'GIT_TRACE',
                                        'SSH_AUTH_SOCK', 'GIT_OBJECT_DIRECTORY'})

    def test_object_scan_requires_reachable_commit_tree_and_exact_projection(self):
        projection, secret = b'public projection\n', b'PRIVATE_VALUE'
        ids = {'commit': '1' * 40, 'tree': '2' * 40, 'blob': '3' * 40}
        bodies = {'commit': b'commit data', 'tree': b'tree data', 'blob': projection}

        def git(*arguments):
            if arguments[0] == 'ls-tree':
                return b'projection.json\n'
            if arguments[0] == 'rev-list':
                return ('\n'.join(ids.values()) + '\n').encode()
            if arguments[:2] == ('cat-file', '--batch-all-objects'):
                return ''.join(identifier + ' ' + kind + ' ' + str(len(bodies[kind])) + '\n'
                               for kind, identifier in ids.items()).encode()
            if arguments[0] == 'cat-file':
                return bodies[arguments[1]]
            if arguments[0] in ('remote', 'status'):
                return b''
            self.fail(arguments)

        self.assertEqual(protected_output.git_objects(git, projection, [secret]),
                         {'commit': 1, 'tree': 1, 'blob': 1})
        for kind in ('commit', 'tree', 'blob'):
            previous = bodies[kind]
            bodies[kind] += secret
            with self.assertRaisesRegex(protected_output.Refused, 'protected_output_leak'):
                protected_output.git_objects(git, projection, [secret])
            bodies[kind] = previous

        def unreachable(*arguments):
            if arguments[0] == 'rev-list':
                return (ids['commit'] + '\n').encode()
            return git(*arguments)
        with self.assertRaisesRegex(protected_output.Refused, 'protected_git_reachability'):
            protected_output.git_objects(unreachable, projection, [secret])

    def test_real_fixed_children_confine_failure_timeout_and_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = protected_output.command_faults(
                    directory, b'PRIVATE_TEST_SENTINEL',
                    protected_output.isolated_environment(directory), python=sys.executable)
            self.assertEqual(set(result), {'failure', 'output-bound', 'timeout'})
            self.assertTrue(all(row['sentinel_absent'] for row in result.values()))
            self.assertNotIn('PRIVATE_TEST_SENTINEL', json.dumps(result))
            self.assertEqual(stdout.getvalue(), '')
            self.assertEqual(stderr.getvalue(), '')
            self.assertEqual(len(list(directory.iterdir())), 3)

    def test_failure_without_emission_receipt_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                protected_output, 'command', side_effect=protected_output.Refused('fixed_tool_failed')):
            with self.assertRaises(FileNotFoundError):
                protected_output.command_faults(Path(temporary), b'SENTINEL', {})


class DockerAttributionDescriptorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.proc = Path(self.temporary.name)
        self.process = self.proc / '123'
        self.process.mkdir()
        for name in ('fd', 'ns', 'net'):
            (self.process / name).mkdir()
        fields = {'Uid': '963 963 963 963', 'Gid': '1001 1001 1001 1001', 'Groups': '1000 1001',
                  'Umask': '0002', **{name: '0000000000000000' for name in
                                    ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}}
        (self.process / 'status').write_text(''.join(name + ':\t' + value + '\n' for name, value in fields.items()))
        self.stat_raw = '123 (Radarr) ' + ' '.join(['S'] + ['0'] * 18 + ['123'])
        (self.process / 'stat').write_text(self.stat_raw)
        for name in ('uid_map', 'gid_map'):
            (self.process / name).write_text('0 0 4294967295\n')
        for name in ('user', 'mnt', 'net'):
            (self.process / 'ns' / name).touch()
        self.net_inode = (self.process / 'ns/net').stat().st_ino
        (self.process / 'net/tcp').write_text('header\n0: 0100007F:45D6 00000000:0000 0A 0:0 0:0 0 0 0 77\n')
        (self.process / 'net/tcp6').write_text('header\n')
        (self.process / 'exe').symlink_to('/fixed/Radarr')
        (self.process / 'fd/10').symlink_to('/unrelated/file')
        (self.process / 'fd/11').symlink_to('socket:[77]')
        self.fixture = object.__new__(docker_variants.Variant)
        self.fixture.plan = {'bridge': False}
        self.fixture.specs = {'radarr': {'process': 'Radarr', 'port': 17878}}
        self.fixture.container = mock.Mock(return_value={'Id': 'container', 'State': {'Running': True, 'StartedAt': 'start'}})
        self.fixture.docker = mock.Mock(return_value=b'PID COMMAND\n123 Radarr\n')

    def observe(self, vanish=None, error=None, changed_process=False, changed_listener=False,
                process_gone=False, changed_namespace=False):
        real_readlink, real_stat = os.readlink, os.stat
        def readlink(path):
            if Path(path) == self.process / 'fd' / str(vanish):
                if error:
                    raise error
                Path(path).unlink()
                if changed_process:
                    (self.process / 'stat').write_text(self.stat_raw[:-3] + '456')
                if changed_listener:
                    (self.process / 'net/tcp').write_text('header\n')
                if process_gone:
                    (self.process / 'stat').unlink()
                if changed_namespace:
                    (self.process / 'ns/mnt').rename(self.process / 'ns/mnt.old')
                    (self.process / 'ns/mnt').touch()
            return real_readlink(path)
        def observed_stat(path, *args, **kwargs):
            if os.fspath(path) == '/proc/self/ns/net':
                return SimpleNamespace(st_ino=self.net_inode)
            return real_stat(path, *args, **kwargs)
        with mock.patch.object(docker_variants, 'Path', side_effect=lambda path: self.proc if path == '/proc' else Path(path)), \
                mock.patch.object(docker_variants.os, 'readlink', side_effect=readlink), \
                mock.patch.object(docker_variants.os, 'stat', side_effect=observed_stat):
            return self.fixture.attribution('radarr')

    def test_disappearing_unrelated_fd_keeps_positive_listener_attribution(self):
        result = self.observe(vanish=10)
        self.assertEqual(result['listener_inodes'], ['socket:[77]'])
        self.assertEqual(result['start_ticks'], '123')
        self.assertEqual(result['groups'], [1000, 1001])

    def test_disappearing_listener_or_permission_failure_is_not_accepted(self):
        with self.assertRaisesRegex(docker_variants.Refused, 'listener_pending'):
            self.observe(vanish=11)
        with self.assertRaises(PermissionError):
            self.observe(vanish=10, error=PermissionError(13, 'private details'))
        with self.assertRaises(FileNotFoundError):
            docker_variants.descriptor_targets(self.process / 'missing-fd-directory')

    def test_process_or_listener_change_during_fd_churn_refuses(self):
        with self.assertRaisesRegex(docker_variants.Refused, 'changed_during_attribution'):
            self.observe(vanish=10, changed_process=True)
        (self.process / 'fd/10').symlink_to('/unrelated/file')
        with self.assertRaisesRegex(docker_variants.Refused, 'changed_during_attribution'):
            self.observe(vanish=10, changed_listener=True)

    def test_process_disappearance_and_namespace_replacement_are_not_skipped(self):
        with self.assertRaises(FileNotFoundError):
            self.observe(vanish=10, process_gone=True)
        (self.process / 'stat').write_text(self.stat_raw)
        (self.process / 'fd/10').symlink_to('/unrelated/file')
        with self.assertRaisesRegex(docker_variants.Refused, 'changed_during_attribution'):
            self.observe(vanish=10, changed_namespace=True)

    def test_pre_request_attribution_failure_never_dispatches_or_retries_http(self):
        self.fixture.enabled = False
        before = {'pid': 123, 'namespaces': {'net': 42}}
        with mock.patch.object(self.fixture, 'engine', return_value={'engine': 'bound'}), \
                mock.patch.object(self.fixture, 'attribution', side_effect=[before,
                    docker_variants.Refused('docker_baseline_listener_pending')]) as attribution, \
                mock.patch.object(docker_variants, 'bounded_request') as request:
            with self.assertRaisesRegex(docker_variants.Refused, 'listener_pending'):
                self.fixture.request('radarr', '/api/v3/config/naming', key='PRIVATE_SENTINEL')
            self.assertEqual(attribution.call_count, 2)
            request.assert_not_called()


class DockerVariantPrimitiveTests(unittest.TestCase):
    def test_radarr_response_status_and_shape_precede_field_access(self):
        self.assertEqual(docker_variants.response_object(201, b'{"id":1}', 201), {'id': 1})
        for status, raw, shape in ((400, b'[{"message":"PRIVATE_SENTINEL"}]', 'array'),
                                   (400, b'{"id":1,"secret":"PRIVATE_SENTINEL"}', 'object'),
                                   (201, b'"PRIVATE_SENTINEL"', 'string'),
                                   (201, b'PRIVATE_SENTINEL', 'unparseable')):
            with self.subTest(status=status, shape=shape), self.assertRaises(
                    docker_variants.ResponseMismatch) as failure:
                docker_variants.response_object(status, raw, 201)
            with mock.patch.object(docker_variants, 'FAILURE_STAGE', 'radarr_rootfolder_validate'):
                public = docker_variants.failure_evidence(failure.exception)
            self.assertEqual(public['http_status'], status)
            self.assertEqual(public['json_type'], shape)
            self.assertNotIn('PRIVATE_SENTINEL', str(failure.exception) + json.dumps(public))
        # The previous field-access expression raises a generic exception.
        with self.assertRaises(AttributeError):
            json.loads(b'[{"message":"PRIVATE_SENTINEL"}]').get('id')

    def test_variant_failure_projection_never_formats_exception_values(self):
        local = {}
        exec(compile("def attribution():\n    raise FileNotFoundError(2, 'PRIVATE_SENTINEL', '/private/key')\n",
                     '/opt/mpkg-proofs/docker_variants.py', 'exec'), local)
        try:
            local['attribution']()
        except FileNotFoundError as error:
            with mock.patch.object(docker_variants, 'FAILURE_STAGE', 'radarr_rootfolder_post'):
                result = docker_variants.failure_evidence(error)
        self.assertEqual(result, {'stage': 'radarr_rootfolder_post', 'exception_type': 'FileNotFoundError',
            'errno': 2, 'fixed_source_frames': [{'source': 'docker_variants.py', 'function': 'attribution', 'line': 2}]})
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(result))
        self.assertNotIn('/private/key', json.dumps(result))
        with self.assertRaisesRegex(docker_variants.Refused, 'diagnostic_stage_invalid'):
            docker_variants.stage('PRIVATE_SENTINEL')

    def test_retirement_entrypoint_refuses_host_before_removal_or_prior_history_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, '-I', str(PROOFS / 'docker_variant_retire.py'),
                                     '--variant', 'network-exclusive-delete', '--guest-id', str(uuid.uuid4())],
                                    cwd=temporary, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 73)
            self.assertEqual(json.loads(result.stdout)['status'], 'refused')
            self.assertEqual(result.stderr, '')
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_retirement_refuses_an_unexpected_stopped_consumer(self):
        fixture = object.__new__(docker_variant_retire.Retirement)
        fixture.specs = {'sonarr': {}, 'radarr': {}}
        fixture.manifest = {'resources': {'container_ids': {'sonarr': 'retired-id', 'radarr': 'accepted-radarr'}}}
        with mock.patch.object(fixture, 'docker', return_value=b'accepted-radarr\nstopped-other-consumer\n') as docker, \
                mock.patch.object(fixture, 'container') as container:
            with self.assertRaisesRegex(docker_variant_retire.Refused, 'remaining_consumer_scope_changed'):
                fixture.remaining()
            docker.assert_called_once_with('ps', '--all', '--quiet', '--no-trunc')
            container.assert_not_called()

    def test_empty_declared_network_requires_empty_actual_attachments(self):
        fixture = object.__new__(docker_variant_retire.Retirement)
        network = {'Id': 'accepted-id', 'Name': docker_variant_plan.NETWORK, 'Driver': 'bridge',
                   'Scope': 'local', 'Labels': {}, 'Options': {}, 'IPAM': {'Driver': 'default'}}
        fixture.manifest = {'resources': {'network': dict(network, consumers=['retired-sonarr'])}}
        current = dict(network, Internal=False, EnableIPv6=False, Containers={'unexpected-consumer': {}})
        with mock.patch.object(fixture, 'remaining', return_value=set()), \
                mock.patch.object(fixture, 'docker', return_value=json.dumps([current]).encode()) as docker:
            with self.assertRaisesRegex(docker_variant_retire.Refused, 'network_identity_or_consumers_changed'):
                fixture.network_identity()
            docker.assert_called_once_with('network', 'inspect', docker_variant_plan.NETWORK)

    def test_unresolved_retirement_blocks_another_probe_or_cleanup(self):
        fixture = object.__new__(docker_variant_retire.Retirement)
        with tempfile.TemporaryDirectory() as temporary:
            fixture.directory = Path(temporary)
            with mock.patch.object(fixture, 'inspect') as inspect, mock.patch.object(fixture, 'docker') as docker:
                with self.assertRaisesRegex(docker_variant_retire.Refused, 'fresh_attempt_required'):
                    fixture.execute()
                inspect.assert_not_called()
                docker.assert_not_called()

    def test_experiment_entrypoint_rejects_host_before_opening_assembly_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, '-I', str(PROOFS / 'docker_variant_experiment.py'),
                                     '--variant', 'volume-delete', '--guest-id', str(uuid.uuid4())],
                                    cwd=temporary, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 73)
            self.assertEqual(json.loads(result.stdout)['status'], 'refused')
            self.assertEqual(result.stderr, '')
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_atomic_source_change_refuses_intervening_bytes_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'compose.yaml'
            core.write_new(path, b'accepted')
            raw, evidence = core.read_regular(path)
            path.write_bytes(b'intervening edit')
            with self.assertRaisesRegex(docker_variant_experiment.Refused, 'file_drift'):
                docker_variant_experiment.atomic_bytes(path, raw, evidence, b'candidate')
            self.assertEqual(path.read_bytes(), b'intervening edit')
            self.assertEqual({item.name for item in Path(temporary).iterdir()}, {'compose.yaml'})

    def test_selected_container_replacement_cannot_authorize_resource_or_consumer_drift(self):
        before = {'container_ids': {'sonarr': 'old-sonarr', 'radarr': 'same-radarr'},
                  'network': {'Id': 'accepted-network', 'consumers': ['old-sonarr', 'same-radarr']}}
        after = {'container_ids': {'sonarr': 'new-sonarr', 'radarr': 'same-radarr'},
                 'network': {'Id': 'accepted-network', 'consumers': ['new-sonarr', 'same-radarr']}}
        docker_variant_experiment.preserved_resources(before, after, replacement=True)
        with self.assertRaisesRegex(docker_variant_experiment.Refused, 'unselected_container_changed'):
            docker_variant_experiment.preserved_resources(before, after, replacement=False)
        after['network']['Id'] = 'replacement-network'
        with self.assertRaisesRegex(docker_variant_experiment.Refused, 'resource_identity_changed'):
            docker_variant_experiment.preserved_resources(before, after, replacement=True)
        after['network']['Id'] = 'accepted-network'
        after['container_ids']['radarr'] = 'restarted-radarr'
        with self.assertRaisesRegex(docker_variant_experiment.Refused, 'unselected_container_changed'):
            docker_variant_experiment.preserved_resources(before, after, replacement=True)

    def test_protected_experiment_references_do_not_modify_assembly_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = core.Journal(root / 'baseline')
            changes = core.Journal(root / 'changes')
            before = baseline.path.read_bytes()
            path = root / 'input'
            core.write_new(path, b'fixture-private-bytes')
            reference = changes.capture(path)
            view = docker_variant_experiment.JournalView(baseline, changes)
            self.assertTrue(view.unchanged({'experiment': reference}, path))
            self.assertEqual(baseline.path.read_bytes(), before)
            with self.assertRaisesRegex(docker_variant_experiment.Refused, 'reference_shape'):
                view.resolve({'experiment': reference, 'baseline': reference})
            changes.close()
            baseline.close()

    def test_unknown_experiment_blocks_even_another_application_check(self):
        fixture = object.__new__(docker_variant_experiment.Experiment)
        with tempfile.TemporaryDirectory() as temporary:
            fixture.directory = Path(temporary)
            fixture.manifest = {}
            with mock.patch.object(fixture, 'inspect') as inspect:
                with self.assertRaisesRegex(docker_variant_experiment.Refused, 'fresh_attempt_required'):
                    fixture.start()
                inspect.assert_not_called()

    def test_exact_digest_candidate_cannot_reach_lifecycle_or_source_mutation(self):
        fixture = object.__new__(docker_variant_experiment.Experiment)
        fixture.plan = docker_variant_plan.variant_plan('docker-exact-digest')
        fixture.specs = fixture.plan['applications']
        fixture.manifest = {}
        fixture.before = {'applications': {'sonarr': 'same'}, 'resources': {'volume': 'same'}}
        with tempfile.TemporaryDirectory() as temporary:
            fixture.directory = Path(temporary)
            fixture.changes = core.Journal(fixture.directory)
            with mock.patch.object(fixture, 'images', return_value={}), \
                    mock.patch.object(fixture, 'histories_unchanged'), \
                    mock.patch.object(fixture, 'inspect', return_value=fixture.before), \
                    mock.patch.object(fixture, 'stop_sonarr') as stop, \
                    mock.patch.object(fixture, 'compose') as compose, \
                    mock.patch.object(docker_variant_experiment, 'atomic_bytes') as replace:
                result = fixture.update()
                self.assertTrue(result['candidate_blocked_by_exact_intent'])
                self.assertFalse(result['image_change_requested'])
                stop.assert_not_called()
                compose.assert_not_called()
                replace.assert_not_called()
            fixture.changes.close()

    def test_all_variant_entrypoints_reject_host_before_fixture_or_docker_work(self):
        for variant in docker_variant_plan.VARIANTS:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                result = subprocess.run([sys.executable, '-I', str(PROOFS / 'docker_variants.py'), 'setup',
                                         '--variant', variant, '--guest-id', str(uuid.uuid4())],
                                        cwd=temporary, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 73)
                self.assertEqual(json.loads(result.stdout)['status'], 'refused')
                self.assertEqual(result.stderr, '')
                self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_resource_inventory_counts_stopped_consumers_and_binds_volume_mountpoint(self):
        fixture = object.__new__(docker_variants.Variant)
        fixture.guest = 'fixture-guest'
        fixture.plan = docker_variant_plan.variant_plan('volume-keep')
        fixture.specs = fixture.plan['applications']
        containers = {'sonarr': {'Id': 'sonarr-id', 'Mounts': [
            {'Destination': '/mnt/media', 'Source': '/mnt/media'},
            {'Destination': '/config', 'Source': '/accepted-volume', 'Name': docker_variant_plan.VOLUME}]},
            'radarr': {'Id': 'radarr-id', 'Mounts': [{'Destination': '/config', 'Source': '/opt/docker/radarr/config'}]}}
        fixture.container = lambda role: containers[role]
        volume = {'Name': docker_variant_plan.VOLUME, 'Driver': 'local', 'Options': None, 'Scope': 'local',
                  'Labels': fixture.labels(), 'Mountpoint': '/accepted-volume', 'CreatedAt': 'bound-creation'}
        extra = []
        def docker(*args):
            if args == ('ps', '--all', '--quiet', '--no-trunc'):
                return ('\n'.join(['sonarr-id', 'radarr-id'] + extra) + '\n').encode()
            if args == ('volume', 'inspect', docker_variant_plan.VOLUME):
                return json.dumps([volume]).encode()
            if args == ('volume', 'ls', '--quiet'):
                return (docker_variant_plan.VOLUME + '\n').encode()
            if args == ('network', 'ls', '--format', '{{.Name}}'):
                return b'host\nnone\nbridge\n'
            raise AssertionError(args)
        fixture.docker = docker
        self.assertEqual(fixture.objects()['volume']['consumers'], ['sonarr-id'])
        extra.append('stopped-unmanaged-container')
        with self.assertRaisesRegex(docker_variants.Refused, 'other_container_present'):
            fixture.objects()
        extra.clear()
        containers['sonarr']['Mounts'][1]['Source'] = '/replacement-volume'
        with self.assertRaisesRegex(docker_variants.Refused, 'volume_consumers_changed'):
            fixture.objects()

    def test_variant_check_does_not_accept_a_changed_wanted_policy(self):
        fixture = object.__new__(docker_variants.Variant)
        fixture.guest = 'fixture-guest'
        fixture.plan = docker_variant_plan.variant_plan('docker-exact-digest')
        fixture.specs = fixture.plan['applications']
        manifest = {'schema': 1, 'guest_id': fixture.guest,
                    'plan': docker_variant_plan.variant_plan('docker-update-allowed-tag'),
                    'inputs': {role: {} for role in fixture.specs}}
        with mock.patch.object(fixture, 'engine') as engine:
            with self.assertRaisesRegex(docker_variants.Refused, 'manifest_changed'):
                fixture.inspect(manifest)
            engine.assert_not_called()

    def test_wanted_tag_policy_is_distinct_from_frozen_older_execution(self):
        allowed = docker_variant_plan.variant_plan('docker-update-allowed-tag')
        exact = docker_variant_plan.variant_plan('docker-exact-digest')
        self.assertEqual(allowed['resolved_sonarr_execution'], exact['resolved_sonarr_execution'])
        self.assertEqual(allowed['wanted_declaration']['image'], 'lscr.io/linuxserver/sonarr:latest')
        self.assertFalse(allowed['wanted_declaration']['exact_image'])
        self.assertTrue(allowed['wanted_declaration']['updates_allowed'])
        self.assertTrue(exact['wanted_declaration']['exact_image'])
        self.assertNotEqual(exact['wanted_declaration']['image'], exact['accepted_update_candidate'])
        self.assertTrue(exact['fresh_older_database_required'])

    def test_variant_resources_and_consumers_are_explicit(self):
        shared = docker_variant_plan.variant_plan('network-shared')
        exclusive = docker_variant_plan.variant_plan('network-exclusive-delete')
        self.assertEqual(set(shared['applications']), {'sonarr', 'radarr'})
        self.assertEqual(set(exclusive['applications']), {'sonarr'})
        source = docker_variant_plan.compose_document(shared, 'radarr')
        self.assertTrue(source['networks']['fixture']['external'])
        self.assertEqual(source['services']['radarr']['ports'][0]['host_ip'], '127.0.0.1')
        volume = docker_variant_plan.variant_plan('volume-keep')
        source = docker_variant_plan.compose_document(volume, 'sonarr')
        self.assertEqual(source['volumes']['configuration']['name'], 'mpkg-fixture-sonarr-config')
        self.assertEqual(source['services']['sonarr']['volumes'][0]['type'], 'volume')
        self.assertEqual(docker_variant_plan.compose_document(volume, 'radarr')['services']['radarr']['volumes'][0]['type'], 'bind')

    def test_container_copy_reads_one_regular_file_without_extracting_or_following(self):
        def archive(name='config.xml', kind=tarfile.REGTYPE, extra=False):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w') as tar:
                member = tarfile.TarInfo(name)
                member.type, member.uid, member.gid, member.mode = kind, 963, 1001, 0o600
                raw = b'<Config/>'
                member.size = len(raw) if kind == tarfile.REGTYPE else 0
                if kind == tarfile.SYMTYPE:
                    member.linkname = '/etc/shadow'
                tar.addfile(member, io.BytesIO(raw) if member.size else None)
                if extra:
                    tar.addfile(tarfile.TarInfo('another-file'))
            return output.getvalue()
        raw, metadata = docker_variant_plan.read_config_archive(archive(), 'config.xml')
        self.assertEqual(raw, b'<Config/>')
        self.assertEqual(metadata['uid'], 963)
        for changed in (archive('../config.xml'), archive(kind=tarfile.SYMTYPE), archive(extra=True)):
            with self.assertRaises(docker_variant_plan.Refused):
                docker_variant_plan.read_config_archive(changed, 'config.xml')

    def test_namespace_opener_cannot_switch_the_callers_namespace(self):
        opener = docker_variant_plan.NamespaceOpener(-1, (0, 0))
        with mock.patch.object(docker_variant_plan.os, 'fstat') as stat_call:
            with self.assertRaisesRegex(docker_variant_plan.Refused, 'requires_private_child'):
                opener.open(None, 1)
            stat_call.assert_not_called()


class DockerBaselineTests(unittest.TestCase):
    def test_initial_protected_and_unmanaged_values_survive_serialization(self):
        initial = b'<Config><Port>18989</Port><ApiKey>fixture-only</ApiKey><Other>kept</Other></Config>'
        current = b'<Config>\n<Other>kept</Other><Port>18989</Port><ApiKey>fixture-only</ApiKey><Added>default</Added></Config>'
        docker_baseline.preserve_initial_values(initial, current)
        for changed in (current.replace(b'fixture-only', b'changed'), current.replace(b'kept', b'changed')):
            with self.assertRaisesRegex(docker_baseline.Refused, 'protected_or_unmanaged_xml_changed'):
                docker_baseline.preserve_initial_values(initial, changed)

    def test_shared_check_requires_actual_directory_identity_not_only_accessible_root(self):
        expected = {'id': 1, 'path': str(docker_baseline.RADARR_ROOT), 'accessible': True,
                    'unmappedFolders': [{'name': docker_baseline.SENTINEL.name,
                                        'path': str(docker_baseline.SENTINEL)}]}
        docker_baseline.validate_shared_response(200, expected, 1)
        for field, value in [('unmappedFolders', []), ('id', 2), ('accessible', False)]:
            with self.subTest(field=field), self.assertRaisesRegex(
                    docker_baseline.Refused, 'unmanaged_shared_check_failed'):
                docker_baseline.validate_shared_response(200, dict(expected, **{field: value}), 1)

    def test_runtime_xml_rejects_duplicate_protected_fields_and_entities(self):
        for raw in (b'<Config><ApiKey>a</ApiKey><ApiKey>b</ApiKey></Config>',
                    b'<!DOCTYPE Config><Config/>'):
            with self.subTest(raw=raw), self.assertRaises(docker_baseline.Refused):
                docker_baseline.xml_values(raw)

    def test_console_wrappers_require_expected_uuid_before_execution(self):
        for script in PROOFS.glob('guest-*.sh'):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as temporary:
                result = subprocess.run(['/bin/bash', str(script)], cwd=temporary,
                                        env={'PATH': '/usr/bin:/bin'}, capture_output=True,
                                        text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('expected guest UUID is required', result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_manifest_hash_observer_guards_before_read_and_emits_no_file_contents(self):
        script = (PROOFS / 'guest-image-manifest.sh').read_text()
        program = script.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        code = compile(ast.parse(program), '<manifest-hash-observer>', 'exec')
        guard = mock.Mock(return_value='guest')
        read = mock.Mock(return_value=({'schema': 1, 'guest_id': 'guest', 'private': 'PRIVATE_SENTINEL'}, 'a' * 64))
        install = mock.Mock()
        def terminate(status):
            raise SystemExit(status)
        modules = {'core': SimpleNamespace(Refused=core.Refused, require_guest=guard),
                   'native_manifest': SimpleNamespace(trusted_json=read),
                   'run': SimpleNamespace(trusted_install=install),
                   'sys': SimpleNamespace(path=[], argv=['-', 'guest'], exit=terminate),
                   'resource': SimpleNamespace(RLIMIT_CORE=4, setrlimit=mock.Mock())}
        with mock.patch.dict(sys.modules, modules):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exec(code, {})
            self.assertEqual(json.loads(output.getvalue()),
                             {'status': 'observed', 'guest_id': 'guest', 'compose_sha256': 'a' * 64})
            read.assert_called_once_with('compose.json')
            self.assertNotIn('PRIVATE_SENTINEL', output.getvalue())
            read.reset_mock()
            install.reset_mock()
            guard.side_effect = core.Refused('wrong_guest')
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
                exec(code, {})
            self.assertEqual(caught.exception.code, 73)
            read.assert_not_called()
            install.assert_not_called()


class DockerVolumeInitializationTests(unittest.TestCase):
    def test_child_uses_held_own_proc_view_and_still_rejects_namespace_drift(self):
        class ReachedRoot(BaseException):
            pass
        class ChildExit(BaseException):
            pass
        for observed in (42, 43):
            with self.subTest(namespace=observed):
                calls = []
                def fork():
                    calls.append('fork')
                    return 0
                def opened(path, flags):
                    self.assertEqual(path, '/proc/self/ns')
                    calls.append('open_own_proc')
                    return 91
                def inspected(path, *, dir_fd):
                    self.assertEqual((path, dir_fd), ('mnt', 91))
                    calls.append('inspect_held_view')
                    return SimpleNamespace(st_ino=observed)
                def entered(descriptor):
                    calls.append('enter_root')
                    raise ReachedRoot()
                def exited(status):
                    raise ChildExit(status)
                operations = SimpleNamespace(fork=fork, open=opened, O_RDONLY=0, O_DIRECTORY=1, O_CLOEXEC=2,
                    CLONE_NEWNS=3, setns=lambda *_: calls.append('setns'), stat=inspected,
                    close=lambda _: calls.append('close_own_proc'), fchdir=entered, _exit=exited)
                with mock.patch.object(docker_variants, 'os', operations):
                    if observed == 42:
                        with self.assertRaises(ReachedRoot):
                            docker_variants.config_credential_check(10, 11, 42, {}, b'synthetic', 'sonarr')
                        self.assertEqual(calls, ['fork', 'open_own_proc', 'setns', 'inspect_held_view', 'close_own_proc', 'enter_root'])
                    else:
                        with self.assertRaises(ChildExit) as caught:
                            docker_variants.config_credential_check(10, 11, 42, {}, b'synthetic', 'sonarr')
                        self.assertEqual(caught.exception.args, (1,))
                        self.assertNotIn('enter_root', calls)

    def test_initializer_exit_zero_requires_actual_setgid_metadata_before_removal(self):
        identifier = 'a' * 64
        value = {'Id': identifier, 'Image': 'sha256:' + 'b' * 64, 'Config': {'User': '0:1001'},
                 'State': {'Running': False, 'ExitCode': 0}, 'HostConfig': {'NetworkMode': 'none'},
                 'Mounts': [{'Name': docker_variant_plan.VOLUME, 'Destination': '/config'}]}
        for reported in (b'963:1001:770\n', b'963:1001:2770\n'):
            with self.subTest(metadata=reported):
                calls = []
                def docker(*args, **kwargs):
                    calls.append(args)
                    return {'volume': b'created\n', 'create': identifier.encode(), 'start': b'', 'wait': b'0\n',
                            'logs': reported, 'inspect': json.dumps([value]).encode(), 'rm': b''}[args[0]]
                fixture = SimpleNamespace(docker=docker, guest='guest', plan={'variant': 'volume-keep'},
                    specs={'sonarr': {'image': compose_proof.SONARR}}, image_ids={'sonarr': {'image_id': value['Image']}})
                if reported == b'963:1001:2770\n':
                    docker_variants.Variant.prepare_volume(fixture)
                    self.assertIn(('rm', identifier), calls)
                else:
                    with self.assertRaisesRegex(docker_variants.Refused, 'initialization_metadata_mismatch'):
                        docker_variants.Variant.prepare_volume(fixture)
                    self.assertFalse(any(call[0] == 'rm' for call in calls))
                created = next(call for call in calls if call[0] == 'create')
                self.assertEqual(created[created.index('--user') + 1], '0:1001')
                self.assertEqual([created[index + 1] for index, item in enumerate(created) if item == '--cap-add'], ['CHOWN', 'FOWNER'])
                self.assertIn("stat -c '%u:%g:%a' /config", created[-1])


class VolumeKeepDiagnosticTests(unittest.TestCase):
    def test_radarr_observer_reports_shape_without_any_response_values(self):
        script = (PROOFS / 'guest-volume-keep-radarr-diagnostic.sh').read_text()
        parsed = ast.parse(script.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0])
        nodes = [node for node in parsed.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('response_view', 'error_view')]
        namespace = {'json': json, 'Refused': core.Refused, 'RADARR_ROOT': Path('/fixed/root')}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<radarr-diagnostic-functions>', 'exec'), namespace)
        observe = namespace['response_view']
        result = observe('rootfolders', 200, json.dumps([
            {'id': 1, 'path': '/fixed/root', 'accessible': True, 'private': 'PRIVATE_SENTINEL'},
            {'id': 2, 'path': '/PRIVATE_SENTINEL'}]).encode())
        self.assertEqual(result, {'http_status': 200, 'json_type': 'array', 'count': 2,
            'all_entries_objects': True, 'expected_path_count': 1, 'expected_path_id_positive': True,
            'expected_path_accessible': True})
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(result))
        self.assertEqual(observe('naming', 400, b'[{"error":"PRIVATE_SENTINEL"}]'),
                         {'http_status': 400, 'json_type': 'array'})
        self.assertEqual(observe('naming', 200, b'PRIVATE_SENTINEL'),
                         {'http_status': 200, 'json_type': 'unparseable'})
        self.assertEqual(namespace['error_view'](KeyError('PRIVATE_SENTINEL')),
                         {'exception_type': 'KeyError', 'errno': None})

    def test_stage_diagnostic_emits_only_fixed_source_coordinates_and_error_kind(self):
        script = (PROOFS / 'guest-volume-keep-stage-diagnostic.sh').read_text()
        program = script.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        parsed = ast.parse(program)
        nodes = [node for node in parsed.body if isinstance(node, ast.FunctionDef)
                 and node.name == 'error_view' or isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id in ('SAFE_TYPES', 'SAFE_FILES')
                         for target in node.targets)]
        namespace = {'Path': Path, 're': re}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<stage-diagnostic-functions>', 'exec'), namespace)
        local = {}
        exec(compile("def observation():\n    raise KeyError('PRIVATE_SENTINEL')\n",
                     '/opt/mpkg-proofs/docker_variants.py', 'exec'), local)
        try:
            local['observation']()
        except KeyError as error:
            result = namespace['error_view'](error)
        self.assertEqual(result, {'exception_type': 'KeyError', 'errno': None,
            'fixed_source_frames': [{'source': 'docker_variants.py', 'function': 'observation', 'line': 2}]})
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(result))
        self.assertEqual(namespace['error_view'](FileNotFoundError(2, 'PRIVATE_SENTINEL', '/private/key')),
                         {'exception_type': 'FileNotFoundError', 'errno': 2, 'fixed_source_frames': []})

    def functions(self, **extra):
        script = (PROOFS / 'guest-volume-keep-diagnostic.sh').read_text()
        program = script.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        parsed = ast.parse(program)
        nodes = [node for node in parsed.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('metadata', 'predicates', 'child_probe')]
        namespace = {'stat': stat, 'Refused': core.Refused, **extra}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<volume-diagnostic-functions>', 'exec'), namespace)
        return namespace

    def test_reports_config_mode_separately_from_other_credential_predicates(self):
        predicate = self.functions()['predicates']
        config = {'directory': True, 'uid': 963, 'gid': 1001, 'mode': '0o2770'}
        sentinel = {'regular': True, 'links': 1, 'uid': 963, 'gid': 1001, 'mode': '0o640'}
        database = {'regular': True, 'links': 1, 'uid': 963, 'gid': 1001, 'size': 4096, 'mode': '0o664'}
        baseline = predicate(config, sentinel, database, xattr_count=0, sentinel_matches=True)
        self.assertTrue(all(baseline.values()))
        changed = predicate(dict(config, mode='0o775'), sentinel, database, xattr_count=0, sentinel_matches=True)
        self.assertEqual([name for name, value in changed.items() if not value], ['config_metadata'])
        changed = predicate(config, sentinel, database, xattr_count=1, sentinel_matches=True)
        self.assertEqual([name for name, value in changed.items() if not value], ['config_xattrs_empty'])

    def test_namespace_failure_reports_stage_errno_without_private_exception(self):
        operations = SimpleNamespace(CLONE_NEWNS=1, O_RDONLY=0, O_DIRECTORY=1, O_CLOEXEC=2,
            open=mock.Mock(return_value=13), setns=mock.Mock(side_effect=PermissionError(1, 'PRIVATE_SENTINEL')))
        function = self.functions(os=operations)['child_probe']
        result = function(10, 11, 12, {'groups': [1001]}, b'synthetic only', 'sonarr')
        self.assertEqual(result, {'stage': 'enter_mount_namespace', 'failed': True, 'error_kind': 'os_error', 'errno': 1})
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(result))
        operations.setns.assert_called_once_with(11, 1)


class RealNativeConflictTests(unittest.TestCase):
    def test_real_conflict_cannot_be_replaced_by_synthetic_or_unresolved_failure(self):
        value = {'libalpm_version': '16.0.1', 'prepare_result': -1, 'error_number': 46,
                 'exact_pair': True, 'candidate_count': 167, 'removal_count': 0,
                 'local_package_count': 0, 'all_questions_denied': True, 'fetch_calls': 0,
                 'question_count': 1, 'question_mask': 4}
        native_conflict.validate_result(value)
        for changed in ({'status': 'BLOCK conflict'}, dict(value, exact_pair=False),
                        dict(value, error_number=45), dict(value, removal_count=1),
                        dict(value, fetch_calls=1), dict(value, prepare_result=0)):
            with self.subTest(result=changed), self.assertRaisesRegex(
                    native_conflict.Refused, 'real_native_conflict_not_observed'):
                native_conflict.validate_result(changed)

    def test_conflict_selection_matches_frozen_real_case_not_synthetic_fixture(self):
        source = json.loads((PROOFS.parents[1] / 'docs/fixtures/2026-10-31-arch-native-inputs.json').read_bytes())
        case = source['native_incompatible_requests']
        self.assertEqual(native_conflict.TARGETS, {item['name']: item['version'] for item in case['candidates']})
        self.assertEqual(native_conflict.DATABASES,
                         {item['repository']: item['sha256_computed'] for item in source['repository_databases']})
        self.assertEqual(native_conflict.RESOLUTION_SHA256,
                         case['readonly_native_resolution']['stdout_sha256_computed'])
        with self.assertRaisesRegex(native_conflict.Refused, 'frozen_conflict_resolution_changed'):
            native_conflict.parse_candidates(b'extra mpkg-proof-conflict 1-1 synthetic\n')


class DockerSupplementResumeTests(unittest.TestCase):
    def inventory(self):
        value = {'observed_index_images': [], 'retained_child_images': [], 'verified_associations': [],
                 'unverified_associations': [], 'observed_image_ids': []}
        for name, repository, index, child, config, version in oci_acquire.IMAGES:
            reference = 'lscr.io/' + repository + '@sha256:' + index
            value['observed_index_images'].append({'Id': 'sha256:' + index, 'Os': 'linux', 'Architecture': 'amd64',
                'RepoTags': ['lscr.io/' + repository + ':mpkg-fixture-' + name], 'RepoDigests': [reference]})
            value['retained_child_images'].append({'Id': 'sha256:' + child, 'Os': 'linux', 'Architecture': 'amd64',
                                                  'RepoTags': [], 'RepoDigests': []})
            value['observed_image_ids'].extend(['sha256:' + index, 'sha256:' + child])
            value['verified_associations'].append({'reference': reference, 'image_id': 'sha256:' + index,
                'index_digest': 'sha256:' + index, 'manifest_digest': 'sha256:' + child,
                'config_digest': 'sha256:' + config, 'platform': 'linux/amd64', 'version_label': version})
        value['observed_image_ids'].sort()
        return value

    def test_no_runtime_result_can_be_invented_from_an_unset_acceptance_pin(self):
        with mock.patch.object(docker_supplement_resume, 'OBSERVED', None):
            with self.assertRaisesRegex(docker_supplement_resume.Refused, 'runtime_evidence_pending'):
                docker_supplement_resume.preparation_evidence('unobserved-guest')

    def test_failed_https_acquisition_stays_empty_and_cannot_gain_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failed = root / 'image-attestation-preparation'
            failed.mkdir(mode=0o700)
            core.write_new(failed / 'started.json', b'{}')
            core.write_new(failed / 'state.sqlite3', b'prior unknown history')
            supplement = root / 'input'
            for path in (supplement, supplement / 'blobs', supplement / 'blobs/sha256'):
                path.mkdir(mode=0o700)
            with mock.patch.object(docker_supplement_resume, 'Path', side_effect=lambda value:
                    supplement if value == '/opt/mpkg-proof-inputs/oci-supplement' else Path(value)), \
                    mock.patch.object(docker_supplement_resume, 'trusted_path'):
                identities = docker_supplement_resume.failed_acquisition_state(root)
                docker_supplement_resume.evidence_unchanged({}, identities)
                for extra in (failed / 'result.json', supplement / 'acquisition.json', supplement / 'blobs/sha256/partial'):
                    with self.subTest(extra=extra.name):
                        core.write_new(extra, b'not accepted evidence')
                        with self.assertRaisesRegex(docker_supplement_resume.Refused, 'acquisition_contents_changed'):
                            docker_supplement_resume.failed_acquisition_state(root)
                        with self.assertRaisesRegex(docker_supplement_resume.Refused, 'prior_evidence_changed'):
                            docker_supplement_resume.evidence_unchanged({}, identities)
                        extra.unlink()
                self.assertEqual((failed / 'state.sqlite3').read_bytes(), b'prior unknown history')

    def test_auxiliary_report_refuses_other_platform_subject_or_runtime_layers(self):
        report = {'schema': 1, 'source_archive_sha256': docker_supplement_resume.SOURCE_SHA256,
                  'source_archive_bytes': docker_supplement_resume.ARCHIVE_BYTES,
                  'docker_or_runtime_operations': False, 'registry_signatures_verified': False,
                  'images': [], 'descriptor_bytes_total': 0}
        for offset, (name, repository, index, child, _, _) in enumerate(oci_acquire.IMAGES):
            manifest = {'digest': 'sha256:' + str(offset + 1) * 64, 'size': 1112,
                        'mediaType': docker_supplement_resume.MANIFEST}
            config = {'digest': 'sha256:' + str(offset + 4) * 64, 'size': 2,
                      'mediaType': 'application/vnd.oci.empty.v1+json'}
            layer = {'digest': 'sha256:' + str(offset + 7) * 64, 'size': 20,
                     'mediaType': docker_supplement_resume.ATTESTATION}
            report['images'].append({'fixture_name': name, 'repository': repository,
                'original_index_digest': 'sha256:' + index, 'selected_child_digest': 'sha256:' + child,
                'attestation_descriptor': dict(manifest, platform={'os': 'unknown', 'architecture': 'unknown'},
                    annotations={'vnd.docker.reference.type': 'attestation-manifest',
                                 'vnd.docker.reference.digest': 'sha256:' + child}),
                'blobs': [manifest, config, layer]})
            report['descriptor_bytes_total'] += 1134
        self.assertEqual(len(docker_supplement_resume.supplement_records(report)[0]), 3)
        changed = json.loads(json.dumps(report))
        changed['images'][0]['attestation_descriptor']['annotations']['vnd.docker.reference.digest'] = 'sha256:' + 'f' * 64
        with self.assertRaisesRegex(docker_supplement_resume.Refused, 'selected_attestation_changed'):
            docker_supplement_resume.supplement_records(changed)
        changed = json.loads(json.dumps(report))
        changed['images'][0]['blobs'][2]['mediaType'] = 'application/vnd.oci.image.layer.v1.tar+gzip'
        with self.assertRaisesRegex(docker_supplement_resume.Refused, 'descriptor_shape'):
            docker_supplement_resume.supplement_records(changed)

    def test_retained_children_are_recorded_without_substituting_original_indexes(self):
        value = self.inventory()
        self.assertEqual(len(docker_supplement_resume.image_inventory(value)), 6)
        value['observed_index_images'][0]['Id'] = value['retained_child_images'][0]['Id']
        with self.assertRaisesRegex(docker_supplement_resume.Refused, 'inventory_scope'):
            docker_supplement_resume.image_inventory(value)
        value = self.inventory()
        value['observed_index_images'][0]['RepoTags'] = ['unapproved.example/image:alias']
        with self.assertRaisesRegex(docker_supplement_resume.Refused, 'inventory_identity_shape'):
            docker_supplement_resume.image_inventory(value)
        value = self.inventory()
        value['verified_associations'][0]['version_label'] = 'unobserved-version'
        with self.assertRaisesRegex(docker_supplement_resume.Refused, 'verified_associations_changed'):
            docker_supplement_resume.image_inventory(value)

    def test_full_archive_check_refuses_extra_or_corrupt_blob_without_extracting(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'archive.tar'
            raw = b'bounded metadata fixture'
            name = 'blobs/sha256/' + hashlib.sha256(raw).hexdigest()
            def archive(contents, extra=False):
                with tarfile.open(path, 'w:') as tar:
                    member = tarfile.TarInfo(name)
                    member.size = len(contents)
                    tar.addfile(member, io.BytesIO(contents))
                    if extra:
                        member = tarfile.TarInfo('index.json')
                        member.size = 2
                        tar.addfile(member, io.BytesIO(b'{}'))
            archive(raw)
            expected = {name: len(raw)}
            self.assertEqual(docker_supplement_resume.archive_members(path, expected=expected)[0], expected)
            archive(raw, extra=True)
            with self.assertRaisesRegex(docker_supplement_resume.Refused, 'extra_or_resized_member'):
                docker_supplement_resume.archive_members(path, expected=expected)
            archive(b'x' * len(raw))
            with self.assertRaisesRegex(docker_supplement_resume.Refused, 'blob_digest_changed'):
                docker_supplement_resume.archive_members(path, expected=expected)
            self.assertEqual({item.name for item in Path(temporary).iterdir()}, {'archive.tar'})

    def test_supplemented_resume_timeout_preserves_history_and_blocks_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'prior'
            core.write_new(path, b'immutable earlier history')
            with mock.patch.object(docker_supplement_resume, 'preparation_evidence', return_value=(
                    root, {}, {}, {path: b'immutable earlier history'}, {})), \
                    mock.patch.object(docker_supplement_resume, 'package_units', return_value={}), \
                    mock.patch.object(docker_supplement_resume.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=999, gr_mem=[])), \
                    mock.patch.object(docker_supplement_resume.pwd, 'getpwall', return_value=[]), \
                    mock.patch.object(docker_supplement_resume, 'units'), mock.patch.object(docker_supplement_resume, 'quiescent'), \
                    mock.patch.object(docker_supplement_resume, 'command', side_effect=docker_supplement_resume.Refused('startup_timeout_unknown')) as command:
                with self.assertRaisesRegex(docker_supplement_resume.Refused, 'startup_timeout_unknown'):
                    docker_supplement_resume.resume('guest')
                with self.assertRaisesRegex(docker_supplement_resume.Refused, 'fresh_resume_required'):
                    docker_supplement_resume.resume('guest')
                command.assert_called_once_with(['/usr/bin/systemctl', 'start', 'docker.service'], timeout=90)
            self.assertEqual(path.read_bytes(), b'immutable earlier history')
            journal = core.Journal(root / 'docker-supplement-resume')
            self.assertEqual(journal.export()[0]['state'], 'unknown')
            journal.close()


class DockerDiagnosticActivationTests(unittest.TestCase):
    def test_only_the_observed_child_associations_are_accepted(self):
        name, repository, index, child, _, _ = oci_acquire.IMAGES[0]
        value = {'Id': 'sha256:' + child, 'Os': 'linux', 'Architecture': 'amd64',
                 'RepoTags': ['lscr.io/' + repository + ':mpkg-fixture-' + name],
                 'RepoDigests': ['lscr.io/' + repository + '@sha256:' + child]}
        docker_diagnostic_resume.validate_child(value, name, repository, child)
        for changed in (dict(value, Id='sha256:' + index), dict(value, RepoTags=[]),
                        dict(value, RepoDigests=['lscr.io/' + repository + '@sha256:' + index])):
            with self.assertRaisesRegex(docker_diagnostic_resume.Refused, 'child_inventory_changed'):
                docker_diagnostic_resume.validate_child(changed, name, repository, child)

    def test_unknown_preparation_cannot_be_substituted_by_completed_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            journal = core.Journal(root)
            attempt = str(uuid.uuid4())
            journal.begin(attempt)
            with mock.patch.object(docker_diagnostic_resume, 'trusted_path', side_effect=lambda path, **kwargs: path.lstat()):
                docker_diagnostic_resume.journal_bytes(root, None)
                with self.assertRaisesRegex(docker_diagnostic_resume.Refused, 'prior_history_changed'):
                    docker_diagnostic_resume.journal_bytes(root, 'unverified')
                journal.finish(attempt, 'unverified')
                docker_diagnostic_resume.journal_bytes(root, 'unverified')
                with self.assertRaisesRegex(docker_diagnostic_resume.Refused, 'prior_history_changed'):
                    docker_diagnostic_resume.journal_bytes(root, None)
            journal.close()

    def test_cold_activation_timeout_never_retries_or_changes_prior_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prior = root / 'prior-private-evidence'
            core.write_new(prior, b'unchanged')
            with mock.patch.object(docker_diagnostic_resume, 'retained_state', return_value=(
                    root, {}, {'prior-private-evidence': b'unchanged'})), \
                    mock.patch.object(docker_diagnostic_resume, 'package_units', return_value={}), \
                    mock.patch.object(docker_diagnostic_resume.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=999, gr_mem=[])), \
                    mock.patch.object(docker_diagnostic_resume.pwd, 'getpwall', return_value=[]), \
                    mock.patch.object(docker_diagnostic_resume, 'units'), mock.patch.object(docker_diagnostic_resume, 'quiescent'), \
                    mock.patch.object(docker_diagnostic_resume, 'command', side_effect=docker_diagnostic_resume.Refused('timeout_unknown')) as command:
                with self.assertRaisesRegex(docker_diagnostic_resume.Refused, 'timeout_unknown'):
                    docker_diagnostic_resume.activate('guest')
                with self.assertRaisesRegex(docker_diagnostic_resume.Refused, 'fresh_attempt_required'):
                    docker_diagnostic_resume.activate('guest')
                command.assert_called_once_with(['/usr/bin/systemctl', 'start', 'docker.service'], timeout=90)
            self.assertEqual(prior.read_bytes(), b'unchanged')
            journal = core.Journal(root / 'docker-diagnostic-activation')
            self.assertEqual(journal.export()[0]['state'], 'unknown')
            journal.close()


class DockerResumeTests(unittest.TestCase):
    def records(self, guest):
        acquisition = {'schema': 1, 'docker_or_runtime_operations': False,
                       'archive': {'filename': 'images.oci.tar', 'sha256': '1' * 64, 'bytes': 10240},
                       'images': []}
        imported = {'engine_id': 'known-engine', 'archive_sha256': '1' * 64,
                    'load_command_completed': True, 'unverified_associations': [], 'verified_associations': []}
        compose = {'schema': 1, 'guest_id': guest, 'engine_id': 'known-engine', 'images': []}
        for name, repository, index, manifest, config, version in oci_acquire.IMAGES:
            acquisition['images'].append({'fixture_name': name, 'repository': 'lscr.io/' + repository,
                'index_digest': 'sha256:' + index, 'manifest_digest': 'sha256:' + manifest,
                'config_digest': 'sha256:' + config, 'platform': 'linux/amd64', 'version_label': version})
            association = {'reference': 'lscr.io/' + repository + '@sha256:' + index,
                           'image_id': 'sha256:' + config}
            imported['verified_associations'].append(association)
            if name != 'sonarr-older':
                compose['images'].append(dict(association, platform='linux/amd64'))
        return acquisition, imported, compose

    def test_resume_requires_all_three_observed_associations_on_same_engine(self):
        acquisition, imported, _ = self.records(str(uuid.uuid4()))
        self.assertEqual(len(docker_resume.image_bindings(imported, acquisition, 'known-engine')), 3)
        for changed in (dict(imported, engine_id='other-engine'),
                        dict(imported, unverified_associations=['older-sonarr']),
                        dict(imported, load_command_completed=False),
                        dict(imported, verified_associations=imported['verified_associations'][:2])):
            with self.subTest(changed=changed), self.assertRaises(docker_resume.Refused):
                docker_resume.image_bindings(changed, acquisition, 'known-engine')

    def test_observed_result_cannot_hide_unfinished_or_restored_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            guest, attempt = str(uuid.uuid4()), str(uuid.uuid4())
            core.write_new(directory / 'result.json', core.canonical(
                {'schema': 1, 'guest_id': guest, 'status': 'observed'}))
            journal = core.Journal(directory)
            journal.begin(attempt)
            with mock.patch.object(docker_resume, 'trusted_path'):
                with self.assertRaisesRegex(docker_resume.Refused, 'prior_attempt_not_complete'):
                    docker_resume.completed_result(directory, guest)
                journal.finish(attempt, 'observed-complete')
                self.assertEqual(docker_resume.completed_result(directory, guest)[0]['status'], 'observed')
                journal.db.execute('UPDATE store_guard SET recovery_required=1')
                with self.assertRaisesRegex(docker_resume.Refused, 'prior_attempt_not_complete'):
                    docker_resume.completed_result(directory, guest)
            journal.close()

    def test_start_failure_remains_unknown_and_blocks_another_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest, root = str(uuid.uuid4()), Path(temporary)
            acquisition, imported, compose = self.records(guest)
            readiness = {'engine_id': 'known-engine', 'enabled_services': False, 'packages_and_units': {}}
            source = {'acquisition.json': acquisition, 'compose.json': compose}
            with mock.patch.object(docker_resume, 'state_root', return_value=root), \
                    mock.patch.object(docker_resume, 'no_application_state'), \
                    mock.patch.object(docker_resume, 'completed_result', side_effect=lambda path, guest:
                        (readiness if path.name == 'docker-readiness' else imported, '2' * 64)), \
                    mock.patch.object(docker_resume, 'trusted_json', side_effect=lambda name: (source[name], '3' * 64)), \
                    mock.patch.object(docker_resume, 'package_units', return_value={}), \
                    mock.patch.object(docker_resume.grp, 'getgrnam', return_value=SimpleNamespace(gr_mem=[], gr_gid=999)), \
                    mock.patch.object(docker_resume.pwd, 'getpwall', return_value=[]), \
                    mock.patch.object(docker_resume, 'units'), mock.patch.object(docker_resume, 'quiescent'), \
                    mock.patch.object(docker_resume, 'command', side_effect=docker_resume.Refused('tool_timeout_external_work_unknown')) as command:
                with self.assertRaisesRegex(docker_resume.Refused, 'timeout_external_work_unknown'):
                    docker_resume.resume(guest)
                with self.assertRaisesRegex(docker_resume.Refused, 'fresh_restore_required'):
                    docker_resume.resume(guest)
                command.assert_called_once_with(['/usr/bin/systemctl', 'start', 'docker.service'], timeout=90)
            journal = core.Journal(root / 'docker-resume')
            self.assertEqual(journal.export()[0]['state'], 'unknown')
            journal.close()
            self.assertFalse((root / 'docker-resume' / 'result.json').exists())

    def test_resume_requires_inactive_disabled_unit_with_existing_fixed_dropin(self):
        value = {'LoadState': 'loaded', 'FragmentPath': '/usr/lib/systemd/system/docker.service',
                 'DropInPaths': '/etc/systemd/system/docker.service.d/50-mpkg-fixture.conf',
                 'UnitFileState': 'disabled', 'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0',
                 'LimitCORE': '0', 'Environment': '', 'EnvironmentFiles': '', 'PassEnvironment': '',
                 'ExecStart': '{ path=/usr/bin/dockerd ; argv[]=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock ; ignore_errors=no ; pid=0 ; }'}
        docker_resume.unit_state('docker.service', value, active=False)
        for field, replacement in (('UnitFileState', 'enabled'), ('DropInPaths', ''),
                                   ('ActiveState', 'active'), ('LimitCORE', 'infinity')):
            with self.subTest(field=field), self.assertRaises(docker_resume.Refused):
                docker_resume.unit_state('docker.service', dict(value, **{field: replacement}), active=False)


class ServiceEnvironmentTests(unittest.TestCase):
    def test_absent_display_field_requires_typed_empty_array_for_each_service(self):
        expected = {
            'docker.service': 'docker_2eservice',
            'containerd.service': 'containerd_2eservice',
            'sshd.service': 'sshd_2eservice',
            'mpkg-fixture-external.service': 'mpkg_2dfixture_2dexternal_2eservice',
        }
        for unit, object_name in expected.items():
            original = {'Environment': '', 'PassEnvironment': ''}
            with self.subTest(unit=unit), mock.patch.object(
                    service_environment, 'command', return_value=b'a(sb) 0\n') as query:
                value = service_environment.verified_environment_files(unit, original)
            self.assertEqual(value['EnvironmentFiles'], '')
            self.assertNotIn('EnvironmentFiles', original)
            query.assert_called_once_with([
                '/usr/bin/busctl', '--system', '--no-pager', '--timeout=10s',
                'get-property', 'org.freedesktop.systemd1',
                '/org/freedesktop/systemd1/unit/' + object_name,
                'org.freedesktop.systemd1.Service', 'EnvironmentFiles',
            ], timeout=15)

    def test_typed_nonempty_wrong_type_and_query_failure_never_mean_empty(self):
        private = b'PRIVATE_SENTINEL'
        for raw in (b'', b'as 0', b'a(sb) 1 "' + private + b'" false',
                    b'a(sb) 0 ' + private, b'a(sb) 00', b'a(sb) -1'):
            with self.subTest(raw=raw), mock.patch.object(
                    service_environment, 'command', return_value=raw), self.assertRaisesRegex(
                    service_environment.Refused, '^service_environment_files_not_verified$'):
                service_environment.verified_environment_files('sshd.service', {'EnvironmentFiles': ''})
        with mock.patch.object(service_environment, 'command', side_effect=service_environment.Refused(
                'PRIVATE_SENTINEL')), self.assertRaisesRegex(
                service_environment.Refused, '^service_environment_files_not_verified$'):
            service_environment.verified_environment_files('sshd.service', {})

    def test_unexpected_unit_or_nonempty_display_is_not_queried_or_normalized(self):
        with mock.patch.object(service_environment, 'command') as query:
            with self.assertRaisesRegex(service_environment.Refused, 'unit_unsupported'):
                service_environment.verified_environment_files('other.service', {})
            for existing in ('/private/environment (ignore_errors=no)', None):
                with self.assertRaisesRegex(service_environment.Refused, 'files_not_empty'):
                    service_environment.verified_environment_files('sshd.service', {'EnvironmentFiles': existing})
        query.assert_not_called()

    def test_observation_callers_verify_fixed_services_including_external_consumer(self):
        for unit in ('docker.service', 'containerd.service', 'sshd.service',
                     native_service.ROLES['external'][3]):
            owner = docker_ready if unit in docker_ready.UNITS else native_service
            observe = owner.properties if owner is docker_ready else owner.service_properties
            with self.subTest(unit=unit), mock.patch.object(
                    owner, 'command', return_value=b'Environment=\nPassEnvironment=\n'), mock.patch.object(
                    service_environment, 'command', return_value=b'a(sb) 0\n') as query:
                self.assertEqual(observe(unit)['EnvironmentFiles'], '')
                self.assertEqual(query.call_count, 1)
        with mock.patch.object(docker_ready, 'command', return_value=b'LoadState=loaded\n'), mock.patch.object(
                service_environment, 'command') as query:
            self.assertNotIn('EnvironmentFiles', docker_ready.properties('docker.socket'))
        query.assert_not_called()


class DockerReadinessTests(unittest.TestCase):
    def test_diagnostic_hides_unexpected_tail_even_after_exact_command_prefix(self):
        script = (PROOFS / 'guest-docker-diagnostic.sh').read_text()
        embedded = script.split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]
        tree = ast.parse(embedded)
        definition = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                          and node.name == 'safe_execution')
        namespace = {'re': re}
        exec(compile(ast.Module(body=[definition], type_ignores=[]), '<diagnostic-format>', 'exec'), namespace)
        expected = '/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock'
        prefix = '{ path=/usr/bin/dockerd ; argv[]=' + expected + ' ; '
        secret = 'UNEXPECTED_PRIVATE_SENTINEL'
        for raw in (prefix + secret + ' ; ignore_errors=no ; }',
                    prefix + secret + '=private ; }',
                    '{ path=/usr/bin/dockerd ; argv[]=' + secret + ' ; }'):
            public = namespace['safe_execution'](raw, expected)
            self.assertNotIn(secret, json.dumps(public))
        self.assertTrue(namespace['safe_execution'](prefix + secret + ' ; }', expected)
                        ['ExecStart_expected_path_and_argv'])

    def test_activated_socket_accepts_running_state_but_not_failed_state(self):
        value = {'LoadState': 'loaded', 'FragmentPath': '/usr/lib/systemd/system/docker.socket',
                 'DropInPaths': '', 'UnitFileState': 'disabled', 'ActiveState': 'active',
                 'SubState': 'running', 'Listen': '/run/docker.sock (Stream)',
                 'SocketMode': '0660', 'SocketUser': 'root', 'SocketGroup': 'docker'}
        docker_ready.assert_unit('docker.socket', value, started=True)
        docker_ready.assert_unit('docker.socket', dict(value, SubState='listening'), started=True)
        with self.assertRaisesRegex(docker_ready.Refused, 'docker_unit_not_ready'):
            docker_ready.assert_unit('docker.socket', dict(value, SubState='failed'), started=True)

    def test_service_must_be_packaged_and_start_only_fixed_local_arguments(self):
        value = {
            'LoadState': 'loaded', 'FragmentPath': '/usr/lib/systemd/system/docker.service',
            'DropInPaths': '', 'UnitFileState': 'disabled', 'ActiveState': 'inactive', 'MainPID': '0',
            'Environment': '', 'EnvironmentFiles': '', 'PassEnvironment': '',
            'ExecStart': '{ path=/usr/bin/dockerd ; argv[]=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock ; ignore_errors=no ; pid=0 ; }',
        }
        docker_ready.assert_unit('docker.service', value)
        for field, replacement in [('ExecStart', value['ExecStart'].replace('-H fd://', '-H tcp://0.0.0.0:2375')),
                                   ('DropInPaths', '/etc/systemd/system/docker.service.d/unmanaged.conf'),
                                   ('EnvironmentFiles', '/etc/docker/daemon-env'),
                                   ('ActiveState', 'active')]:
            with self.subTest(field=field), self.assertRaises(docker_ready.Refused):
                docker_ready.assert_unit('docker.service', dict(value, **{field: replacement}))

    def test_engine_must_match_empty_fixed_baseline(self):
        value = {'ID': 'fixture-engine', 'ServerVersion': '29.9.2', 'OSType': 'linux',
                 'Architecture': 'x86_64', 'DockerRootDir': '/var/lib/docker',
                 'Containers': 0, 'Images': 0, 'Swarm': {'LocalNodeState': 'inactive'}}
        self.assertEqual(docker_ready.validate_engine(value), 'fixture-engine')
        for field, replacement in [('Containers', 1), ('Images', 1), ('DockerRootDir', '/unbound'),
                                   ('Swarm', {'LocalNodeState': 'active'}), ('ServerVersion', 'other')]:
            with self.subTest(field=field), self.assertRaisesRegex(
                    docker_ready.Refused, 'docker_engine_baseline_mismatch'):
                docker_ready.validate_engine(dict(value, **{field: replacement}))


class NativeRecoveryTests(unittest.TestCase):
    def test_observation_records_only_its_own_completion_and_keeps_prior_bytes(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as temporary:
                root = core.private_directory(Path(temporary) / 'native-service')
                recovery = core.private_directory(Path(temporary) / 'native-service-recovery')
                seed = Path(temporary) / 'private-seed'
                core.write_new(seed, b'fixture-only')
                for directory, count in ((root, 8), (recovery, 0)):
                    journal = core.Journal(directory)
                    journal.begin(str(uuid.uuid4()))
                    for _ in range(count):
                        journal.capture(seed)
                    journal.close()
                before = [(directory / 'state.sqlite3').read_bytes() for directory in (root, recovery)]
                with mock.patch.object(native_service_observe, 'bindings', return_value=(root, recovery, *before)), \
                        mock.patch.object(native_service_observe.native, 'trusted_path', side_effect=lambda path, **kwargs: path.lstat()), \
                        mock.patch.object(native_service_observe.native, 'check',
                            side_effect=native_service_observe.Refused('injected') if fail else None,
                            return_value={'status': 'observed'}) as check:
                    if fail:
                        with self.assertRaisesRegex(native_service_observe.Refused, 'injected'):
                            native_service_observe.observe('guest')
                    else:
                        result = native_service_observe.observe('guest')
                        self.assertTrue(result['original_attempt_remains_unknown'])
                        self.assertTrue(result['recovery_attempt_remains_unknown'])
                    with self.assertRaisesRegex(native_service_observe.Refused, 'fresh_attempt_required'):
                        native_service_observe.observe('guest')
                    self.assertEqual(check.call_count, 1)
                    with self.assertRaisesRegex(native_service_observe.Refused, 'history_not_expected_unknown'):
                        native_service_observe.unknown_history(root, 7)
                self.assertEqual([(directory / 'state.sqlite3').read_bytes() for directory in (root, recovery)], before)
                observed = root.parent / 'native-service-observation'
                self.assertEqual((observed / 'original-state.sqlite3').read_bytes(), before[0])
                self.assertEqual((observed / 'recovery-state.sqlite3').read_bytes(), before[1])
                journal = core.Journal(observed)
                self.assertEqual(journal.export()[0]['state'], 'unknown' if fail else 'observed-complete')
                journal.close()

    def test_partial_group_guard_rejects_a_user_or_changed_group(self):
        groups = [SimpleNamespace(gr_name='fixture-native', gr_gid=1500, gr_mem=[]),
                  SimpleNamespace(gr_name='media', gr_gid=1001, gr_mem=[])]
        with mock.patch.object(native_service_recover.grp, 'getgrall', return_value=groups), \
                mock.patch.object(native_service_recover.pwd, 'getpwall', return_value=[]) as users, \
                mock.patch.object(native_service_recover, 'absent'):
            native_service_recover.partial_accounts()
            users.return_value = [SimpleNamespace(pw_name='fixture-native', pw_uid=1500, pw_gid=1500)]
            with self.assertRaisesRegex(native_service_recover.Refused, 'account_state_changed'):
                native_service_recover.partial_accounts()
            users.return_value = []
            groups[0].gr_mem = ['unexpected']
            with self.assertRaisesRegex(native_service_recover.Refused, 'group_state_changed'):
                native_service_recover.partial_accounts()

    def test_recovery_never_recreates_native_group_before_fixed_useradd(self):
        with mock.patch.object(native_service_recover, 'useradd_arguments', return_value=['/usr/bin/useradd', 'fixture-native']), \
                mock.patch.object(native_service_recover, 'command', side_effect=native_service_recover.Refused('injected')) as command:
            with self.assertRaisesRegex(native_service_recover.Refused, 'injected'):
                native_service_recover.continue_setup('guest', Path('/unused'), b'', [], 'version', None)
            command.assert_called_once_with(['/usr/bin/useradd', 'fixture-native'])

    def test_continuation_preserves_original_unknown_and_has_its_own_terminal(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as temporary:
                root = core.private_directory(Path(temporary) / 'native-service')
                guest, original = str(uuid.uuid4()), str(uuid.uuid4())
                journal = core.Journal(root)
                journal.begin(original)
                journal.close()
                before = (root / 'state.sqlite3').read_bytes()
                with mock.patch.object(native_service_recover, 'preflight', return_value=(
                        root, original, before, b'baseline', [], 'version')), \
                        mock.patch.object(native_service_recover, 'continue_setup',
                            side_effect=native_service_recover.Refused('injected') if fail else None,
                            return_value={'status': 'observed'}) as continuation:
                    if fail:
                        with self.assertRaisesRegex(native_service_recover.Refused, 'injected'):
                            native_service_recover.recover(guest)
                    else:
                        self.assertTrue(native_service_recover.recover(guest)['original_attempt_remains_unknown'])
                    with self.assertRaisesRegex(native_service_recover.Refused, 'fresh_attempt_required'):
                        native_service_recover.recover(guest)
                    self.assertEqual(continuation.call_count, 1)
                recovery = root.parent / 'native-service-recovery'
                self.assertEqual((recovery / 'original-state.sqlite3').read_bytes(), before)
                original_journal, recovery_journal = core.Journal(root), core.Journal(recovery)
                self.assertEqual(original_journal.export()[0]['state'], 'unknown')
                self.assertEqual(recovery_journal.export()[0]['state'], 'unknown' if fail else 'observed-complete')
                original_journal.close()
                recovery_journal.close()


class FixtureAccountTests(unittest.TestCase):
    def test_account_arguments_use_bound_defaults_and_preserve_fixed_homes(self):
        expected = {'native': ('fixture-native', '1500', '1500', '/home/fixture-native'),
                    'external': ('fixture-external', '1501', '1501', '/home/fixture-external'),
                    'compose': ('compose', '963', '962', '/opt/docker')}
        with mock.patch.object(account_defaults, 'require_mail_defaults') as checked:
            for role, (name, uid, gid, home) in expected.items():
                argv = account_defaults.useradd_arguments(role)
                self.assertEqual(argv[0], '/usr/bin/useradd')
                self.assertEqual(argv[-1], name)
                for key, value in (('--uid', uid), ('--gid', gid), ('--home-dir', home), ('--groups', 'media')):
                    self.assertEqual(argv[argv.index(key) + 1], value)
                self.assertNotIn('-K', argv)
                self.assertNotIn('CREATE_MAIL_SPOOL=no', argv)
                self.assertIn('--no-create-home' if role == 'compose' else '--create-home', argv)
            self.assertEqual(checked.call_count, 3)
            with self.assertRaisesRegex(account_defaults.Refused, 'role_unsupported'):
                account_defaults.useradd_arguments('arbitrary')
            self.assertEqual(checked.call_count, 3)

    def test_changed_defaults_refuse_before_any_package_or_account_tool(self):
        metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        identity = [1, 2, 3, 4, 0, 0, stat.S_IFREG | 0o644, 1]
        with mock.patch.object(Path, 'lstat', return_value=metadata), mock.patch.object(
                account_defaults, 'read_regular', return_value=(b'CREATE_MAIL_SPOOL=yes\n', identity)), \
                mock.patch.object(account_defaults, 'command') as command:
            with self.assertRaisesRegex(account_defaults.Refused, 'defaults_changed'):
                account_defaults.useradd_arguments('native')
            command.assert_not_called()


class NativeServiceTests(unittest.TestCase):
    def test_effective_keywords_allow_canonical_case_but_values_and_duplicates_stay_exact(self):
        root = Path('/var/lib/mpkg-proofs/example/native-service')
        raw = native_service.configuration('native', root).replace(
            b'ListenAddress 127.0.0.1\n', b'ListenAddress 127.0.0.1:22222\n')
        native_service.assert_effective(raw, 'native', root)
        for changed in (raw + b'port 22222\n', raw + b'AllowUsers fixture-native\n',
                        raw.replace(b'internal-sftp', b'INTERNAL-SFTP'),
                        raw.replace(b'ForceCommand internal-sftp\n', b'ForceCommand internal-sftp \n')):
            with self.subTest(raw=changed), self.assertRaisesRegex(
                    native_service.Refused, 'effective_configuration_mismatch'):
                native_service.assert_effective(changed, 'native', root)

    def test_effective_diagnostic_reports_whitespace_without_exposing_values(self):
        script = (PROOFS / 'guest-native-service-diagnostic.sh').read_text()
        embedded = script.split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]
        definition = next(node for node in ast.parse(embedded).body if isinstance(node, ast.FunctionDef)
                          and node.name == 'effective_summary')
        namespace = {}
        exec(compile(ast.Module(body=[definition], type_ignores=[]), '<effective-summary>', 'exec'), namespace)
        raw = b'allowusers fixture-native \nhostkey PRIVATE_SENTINEL\nother OTHER_PRIVATE_SENTINEL\n'
        result = namespace['effective_summary'](raw, {'allowusers': 'fixture-native', 'hostkey': '/expected'})
        self.assertFalse(result['allowusers']['exact_match'])
        self.assertTrue(result['allowusers']['strip_match'])
        self.assertEqual(result['allowusers']['trailing_whitespace'], [True])
        self.assertFalse(result['hostkey']['strip_match'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(result))
        mixed = namespace['effective_summary'](b'AllowUsers fixture-native \nHostKey PRIVATE_SENTINEL\n',
                                               {'allowusers': 'fixture-native', 'hostkey': '/expected'})
        self.assertEqual(mixed['allowusers']['occurrences'], 0)
        self.assertEqual(mixed['allowusers']['casefold_key_occurrences'], 1)
        self.assertTrue(mixed['allowusers']['casefold_key_strip_match'])
        self.assertFalse(mixed['allowusers']['casefold_key_exact_value_match'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(mixed))
        duplicate = namespace['effective_summary'](b'allowusers fixture-native\nallowusers fixture-native\n',
                                                   {'allowusers': 'fixture-native'})
        self.assertEqual(duplicate['allowusers']['occurrences'], 2)
        self.assertFalse(duplicate['allowusers']['strip_match'])

    def test_running_unit_must_use_exact_command_dropin_and_no_environment_options(self):
        manager = {
            'ExecStart': '{ path=/usr/bin/sshd ; argv[]=/usr/bin/sshd -D ; ignore_errors=no ; pid=123 ; }',
            'DropInPaths': str(native_service.MANAGED_DROPINS / '50-mpkg-fixture.conf'),
            'Environment': '', 'EnvironmentFiles': '', 'PassEnvironment': '',
        }
        native_service.assert_startup(manager, 'native')
        for field, value in [('ExecStart', manager['ExecStart'].replace('sshd -D ;', 'sshd -D -p 22 ;')),
                             ('DropInPaths', manager['DropInPaths'] + ' /unmanaged.conf'),
                             ('EnvironmentFiles', '/etc/conf.d/sshd (ignore_errors=yes)'),
                             ('Environment', 'SSHD_OPTS=-p22')]:
            with self.subTest(field=field), self.assertRaisesRegex(
                    native_service.Refused, 'fixture_service_startup_drift'):
                native_service.assert_startup(dict(manager, **{field: value}), 'native')

    def test_external_data_check_does_not_require_retired_exclusive_data(self):
        visited = []
        def metadata(path):
            visited.append(path)
            directory = path == native_service.SHARED
            return SimpleNamespace(st_uid=1500, st_gid=1001,
                                   st_mode=(stat.S_IFDIR | 0o2770) if directory else (stat.S_IFREG | 0o640))
        with mock.patch.object(Path, 'lstat', metadata), mock.patch.object(
                native_service.os, 'listxattr', return_value=[]):
            result = native_service.data_inventory(external_only=True)
        self.assertEqual(len(result), 2)
        self.assertNotIn(native_service.EXCLUSIVE, visited)

    def test_effective_config_rejects_extra_listeners_or_password_authentication(self):
        root = Path('/var/lib/mpkg-proofs/example/native-service')
        raw = native_service.configuration('native', root).decode().lower()
        # sshd -T combines ListenAddress with its port and normalizes case.
        raw = raw.replace('listenaddress 127.0.0.1\n', 'listenaddress 127.0.0.1:22222\n')
        native_service.assert_effective(raw.encode(), 'native', root)
        for changed in (raw + 'listenaddress 0.0.0.0:22222\n',
                        raw.replace('passwordauthentication no', 'passwordauthentication yes')):
            with self.assertRaisesRegex(native_service.Refused, 'fixture_effective_configuration_mismatch'):
                native_service.assert_effective(changed.encode(), 'native', root)

    def test_bounded_private_stdin_reaches_child_without_argument_exposure(self):
        value = b'fixture-only-value\n'
        result = proof_run.command([sys.executable, '-I', '-c',
                                    'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'],
                                   input_bytes=value)
        self.assertEqual(result, value)
        with mock.patch.object(proof_run.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(proof_run.Refused, 'tool_input_bound'):
                proof_run.command(['/unexecuted'], input_bytes=b'x' * 4097)
            launch.assert_not_called()


class NativeManifestTests(unittest.TestCase):
    def setUp(self):
        self.source = json.loads((PROOFS.parents[1] / 'docs' / 'fixtures' /
                                 '2026-10-31-arch-native-inputs.json').read_bytes())
        recipe = self.source['aur_packages'][0]
        self.build = {
            'schema': 1, 'guest_id': str(uuid.uuid4()), 'package_base': 'gitstatus',
            'recipe_commit': recipe['recipe_commit'],
            'recipe_files': {name: item['sha256_computed']
                             for name, item in recipe['recipe_files'].items()},
            'sources': [{'filename': item['filename'], 'algorithm': algorithm,
                         'digest': digest, 'verified': True}
                        for item in recipe['sources']
                        for algorithm, digest in item['digests_published_in_recipe'].items()],
            'build_uid': 1600, 'source_verification_exit_code': 0,
            'generated_metadata_matches': True, 'build_exit_code': 0,
            'check_status': 'not-defined',
            'artifact': {'name': 'gitstatus', 'version': '1.5.5-1',
                         'sha256': 'a' * 64, 'size': 100},
        }

    def test_actual_build_cannot_be_substituted_by_design_metadata(self):
        self.assertEqual(native_manifest.validate_build(
            self.build, self.source, self.build['guest_id']), self.build['artifact'])
        for field, value in [('build_uid', 0), ('build_exit_code', 1),
                             ('check_status', 'passed'), ('generated_metadata_matches', False)]:
            with self.subTest(field=field), self.assertRaisesRegex(
                    native_manifest.Refused, 'actual_gitstatus_build_required'):
                native_manifest.validate_build(dict(self.build, **{field: value}),
                                               self.source, self.build['guest_id'])

    def test_build_source_digest_drift_refuses(self):
        self.build['sources'][0]['digest'] = '0' * 128
        with self.assertRaisesRegex(native_manifest.Refused, 'actual_gitstatus_build_required'):
            native_manifest.validate_build(self.build, self.source, self.build['guest_id'])

    def test_signature_evidence_requires_pinned_bytes_and_verified_trust(self):
        planned = self.source['repository_packages'][0]
        record = {'name': planned['name'], 'version': planned['version'], 'size': 100,
                  'sha256': planned['package_sha256_published_in_database'],
                  'url': planned['url'], 'signature_sha256': 'b' * 64,
                  'signing_fingerprint': 'A' * 40, 'primary_fingerprint': 'B' * 40,
                  'trust': native_manifest.TRUST}
        native_manifest.validate_acquisition(record, planned, {planned['url']})
        for field, value in [('trust', 'unverified'), ('sha256', 'f' * 64),
                             ('url', 'https://unbound.invalid/package')]:
            with self.subTest(field=field), self.assertRaisesRegex(
                    native_manifest.Refused, 'verified_native_acquisition_required'):
                native_manifest.validate_acquisition(dict(record, **{field: value}),
                                                     planned, {planned['url']})


class LocalMechanismTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def journal(self):
        journal = core.Journal(self.root / 'private')
        self.addCleanup(journal.close)
        return journal

    def test_unknown_start_survives_reopen_and_blocks_new_attempt(self):
        journal = self.journal()
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        second = core.Journal(journal.directory)
        self.addCleanup(second.close)
        self.assertEqual(second.export(), [
            {'id': attempt, 'state': 'unknown', 'events': ['started']}])
        with self.assertRaisesRegex(core.Refused, 'unresolved_attempt'):
            second.begin(str(uuid.uuid4()))
        journal.finish(attempt, 'observed-complete')
        self.assertEqual(second.export()[0]['events'],
                         ['started', 'observed-complete'])
        with self.assertRaisesRegex(core.Refused, 'attempt_not_started'):
            journal.finish(attempt, 'observed-complete')

    def test_failed_durable_start_has_no_published_attempt(self):
        journal = self.journal()
        journal.db.execute('PRAGMA query_only=ON')
        with self.assertRaises(sqlite3.OperationalError):
            journal.begin(str(uuid.uuid4()))
        self.assertEqual(journal.export(), [])

    def test_failed_completion_preserves_unknown_start(self):
        journal = self.journal()
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        journal.db.execute('PRAGMA query_only=ON')
        with self.assertRaises(sqlite3.OperationalError):
            journal.finish(attempt, 'observed-complete')
        self.assertEqual(journal.export()[0]['state'], 'unknown')
        self.assertEqual(journal.export()[0]['events'], ['started'])

    def test_restored_history_does_not_authorize_or_undo_external_effect(self):
        journal = self.journal()
        snapshot = self.root / 'snapshot'
        journal.backup(snapshot)
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        effect = self.root / 'external-effect'
        core.write_new(effect, b'external state remains')
        journal.finish(attempt, 'observed-complete')
        restored = core.Journal.restore(snapshot, self.root / 'restored')
        self.addCleanup(restored.close)
        self.assertEqual(restored.export(), [])
        with self.assertRaisesRegex(core.Refused, 'history_recovery_required'):
            restored.begin(str(uuid.uuid4()))
        self.assertEqual(effect.read_bytes(), b'external state remains')
        with self.assertRaisesRegex(core.Refused, 'restore_destination_exists'):
            core.Journal.restore(snapshot, self.root / 'restored')

    def test_failed_restore_does_not_publish_unguarded_history(self):
        journal = self.journal()
        snapshot = self.root / 'snapshot'
        journal.backup(snapshot)
        target = self.root / 'restore-target'
        def interrupt():
            raise RuntimeError('injected publication interruption')
        with self.assertRaises(RuntimeError):
            core.Journal.restore(snapshot, target, before_publish=interrupt)
        self.assertFalse(target.exists())
        staging = next(self.root.glob('.mpkg-restore-*'))
        quarantined = core.Journal(staging)
        self.addCleanup(quarantined.close)
        with self.assertRaisesRegex(core.Refused, 'history_recovery_required'):
            quarantined.begin(str(uuid.uuid4()))

    def test_protected_capture_replay_drift_and_projection(self):
        journal = self.journal()
        source = self.root / 'secret.env'
        raw = b'SECRET=unique-private-sentinel\nLITERAL=$dollar\n'
        core.write_new(source, raw)
        reference = journal.capture(source)
        self.assertTrue(journal.unchanged(reference, source))
        replay = self.root / 'replay.env'
        journal.replay(reference, replay)
        self.assertEqual(replay.read_bytes(), raw)
        self.assertEqual(stat.S_IMODE(replay.stat().st_mode), 0o600)
        source.write_bytes(raw + b'CHANGED=1\n')
        self.assertFalse(journal.unchanged(reference, source))
        projection = json.dumps(journal.export())
        self.assertNotIn('unique-private-sentinel', projection)
        self.assertNotIn(reference, projection)
        with self.assertRaises(FileExistsError):
            journal.replay(reference, replay)

    def test_full_database_cannot_publish_protected_reference(self):
        journal = self.journal()
        pages = journal.db.execute('PRAGMA page_count').fetchone()[0]
        journal.db.execute('PRAGMA max_page_count=' + str(pages))
        source = self.root / 'input'
        core.write_new(source, os.urandom(1024 * 1024))
        with self.assertRaises(sqlite3.OperationalError) as failure:
            journal.capture(source)
        self.assertEqual(failure.exception.sqlite_errorcode, sqlite3.SQLITE_FULL)
        self.assertEqual(journal.db.execute('SELECT COUNT(*) FROM protected')
                         .fetchone()[0], 0)

    def test_xml_preserves_bytes_and_rejects_prepublication_drift(self):
        source = self.root / 'config.xml'
        raw = (b'<Config><!-- note --><Port note="keep">19891</Port>'
               b'<ApiKey>protected</ApiKey><Unknown>leave alone</Unknown></Config>')
        core.write_new(source, raw, 0o640)
        accepted, identity = core.read_regular(source)
        expected = raw.replace(b'>19891<', b'>19892<')
        self.assertEqual(core.replace_xml(source, accepted, identity, 19892), expected)
        self.assertEqual(source.read_bytes(), expected)
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o640)
        with self.assertRaisesRegex(core.Refused, 'config_changed'):
            core.replace_xml(source, accepted, identity, 19893)
        accepted, identity = core.read_regular(source)
        with self.assertRaisesRegex(core.Refused, 'config_changed'):
            core.replace_xml(source, accepted, identity, 19893,
                             before_publish=lambda: source.write_bytes(expected + b'\n'))
        self.assertEqual(source.read_bytes(), expected + b'\n')
        self.assertFalse(list(self.root.glob('.mpkg-proof-*')))

    def test_xml_rejects_entities_duplicate_fields_and_hardlinks(self):
        for raw in (b'<!DOCTYPE x><Config><Port>19891</Port></Config>',
                    b'<Config><Port>19891</Port><Port>19892</Port></Config>'):
            with self.subTest(raw=raw), self.assertRaises(core.Refused):
                core.change_xml_port(raw, 19893)
        source = self.root / 'config.xml'
        core.write_new(source, b'<Config><Port>19891</Port></Config>')
        os.link(source, self.root / 'alias')
        with self.assertRaisesRegex(core.Refused, 'input_shape_unsupported'):
            core.read_regular(source)

    def test_xml_cannot_change_commented_port_instead_of_real_port(self):
        for raw in (
                b'<Config><!-- <Port>1111</Port> --><Port><![CDATA[19891]]></Port></Config>',
                b'<Config><!-- <Port>1111</Port> --><Port/></Config>'):
            with self.subTest(raw=raw), self.assertRaises(core.Refused):
                core.change_xml_port(raw, 19892)

    def test_retirement_sharing_drift_partial_and_fresh_disposition(self):
        data = core.private_directory(self.root / 'data')
        core.write_new(data / 'first', b'a')
        core.write_new(data / 'second', b'b')
        inventory = core.inventory_tree(data)
        with self.assertRaisesRegex(core.Refused, 'data_shared'):
            core.delete_inventory(data, inventory, ['external:consumer'])
        core.write_new(data / 'new', b'new')
        with self.assertRaisesRegex(core.Refused, 'data_inventory_changed'):
            core.delete_inventory(data, inventory, [])
        inventory = core.inventory_tree(data)
        with self.assertRaisesRegex(core.Refused, 'injected_partial_delete'):
            core.delete_inventory(data, inventory, [], fail_after=1)
        self.assertEqual(len(list(data.iterdir())), 2)
        self.assertEqual(core.delete_inventory(data, core.inventory_tree(data), []), 2)
        self.assertEqual(list(data.iterdir()), [])

    def test_retirement_does_not_follow_symlink(self):
        data = core.private_directory(self.root / 'data')
        outside = self.root / 'outside'
        core.write_new(outside, b'preserve')
        (data / 'alias').symlink_to(outside)
        with self.assertRaisesRegex(core.Refused, 'data_alias_unsupported'):
            core.inventory_tree(data)
        self.assertEqual(outside.read_bytes(), b'preserve')

    def test_flat_directory_inventory_is_bounded(self):
        data = core.private_directory(self.root / 'data')
        for number in range(1001):
            (data / str(number)).touch()
        with self.assertRaisesRegex(core.Refused, 'data_inventory_bound'):
            core.inventory_tree(data)

    def test_ping_requires_pinned_application_json_shape(self):
        self.assertTrue(core.ping_ok(b'{"status":"OK"}'))
        self.assertTrue(core.ping_ok(b'{"Status":"OK"}'))
        for raw in (b'OK', b'{"status":"Error"}', b'[]',
                    b'{"status":"Error","Status":"OK"}'):
            with self.subTest(raw=raw):
                self.assertFalse(core.ping_ok(raw))

    def test_covering_listeners_include_ipv4_wildcard_and_refuse_ipv6(self):
        port = '4DB3'
        header = 'header\n'
        row = '0: {}:{} 00000000:0000 0A 0 0 0 0 0 {}\n'
        table = header + row.format('0100007F', port, '101')
        table += row.format('00000000', port, '202')
        self.assertEqual(compose_proof.covering_listeners(table, header, 19891),
                         {'socket:[101]', 'socket:[202]'})
        with self.assertRaisesRegex(compose_proof.Refused, 'listener_family_ambiguous'):
            compose_proof.covering_listeners(table, header + row.format('0' * 32, port, '303'), 19891)

    def test_http_whole_request_deadline_stops_trickling_or_stalled_child(self):
        class StalledOpener:
            def open(self, request, timeout):
                time.sleep(10)
        started = time.monotonic()
        with self.assertRaisesRegex(compose_proof.Refused, 'application_request_timeout_unknown'):
            compose_proof.bounded_request(StalledOpener(), None, seconds=0.05)
        self.assertLess(time.monotonic() - started, 2)

    def test_exact_versions_and_coordinated_upgrade_are_required(self):
        rows = [['I', 'gnupg', '2.4.9-3', '0'],
                ['A', 'gnupg', '2.4.9-4', '0'], ['A', 'tmux', '3.6b-4', '0']]
        manifest = {'targets': ['tmux'], 'exact_versions': {'tmux': '3.6b-4'},
                    'coordinated_upgrade': {'name': 'gnupg', 'from': '2.4.9-3', 'to': '2.4.9-4'}}
        self.assertEqual(native_proof.enforce_version_intent(rows, manifest), 'gnupg')
        with self.assertRaisesRegex(native_proof.Refused, 'coordinated_upgrade_baseline_required'):
            native_proof.enforce_version_intent([rows[0], rows[2]], manifest)
        manifest['exact_versions']['tmux'] = 'unsupported-version'
        with self.assertRaisesRegex(native_proof.Refused, 'exact_pin_unavailable'):
            native_proof.enforce_version_intent(rows, manifest)


class OciAcquisitionTests(unittest.TestCase):
    def test_guest_import_binds_report_to_all_fixed_images(self):
        report = {'schema': 1, 'docker_or_runtime_operations': False,
                  'archive': {'filename': 'images.oci.tar', 'sha256': '1' * 64, 'bytes': 10240},
                  'images': []}
        for name, repository, index, manifest, config, version in oci_acquire.IMAGES:
            report['images'].append({'fixture_name': name, 'repository': 'lscr.io/' + repository,
                                     'index_digest': 'sha256:' + index,
                                     'manifest_digest': 'sha256:' + manifest,
                                     'config_digest': 'sha256:' + config,
                                     'platform': 'linux/amd64', 'version_label': version})
        self.assertEqual(image_import.validate_acquisition(report), report['archive'])
        report['images'][0]['index_digest'] = 'sha256:' + '0' * 64
        with self.assertRaisesRegex(image_import.Refused, 'acquisition_image_binding_changed'):
            image_import.validate_acquisition(report)

    def test_descriptor_rejects_bad_digest_size_and_media(self):
        valid = {'mediaType': 'allowed', 'digest': 'sha256:' + '1' * 64, 'size': 3}
        self.assertEqual(oci_acquire.descriptor(valid, {'allowed'}, 10),
                         (valid['digest'], 3))
        for key, value in [('digest', '../../escape'), ('size', 11),
                           ('size', True), ('mediaType', 'unknown')]:
            with self.subTest(key=key), self.assertRaises(oci_acquire.Refused):
                oci_acquire.descriptor(dict(valid, **{key: value}), {'allowed'}, 10)

    def test_redirect_drops_bearer_without_logging_signed_query(self):
        class Response:
            def __init__(self, status, headers, body=b''):
                self.status, self.headers, self.body = status, headers, io.BytesIO(body)
            def close(self):
                pass
            def read1(self, size):
                return self.body.read(size)
        requests = []
        responses = [Response(307, {'Location': 'https://pkg-containers.githubusercontent.com/blob?signature=private'}),
                     Response(200, {'Content-Type': 'application/octet-stream'}, b'abc')]
        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                return responses.pop(0)
        registry = oci_acquire.Registry()
        registry.opener = Opener()
        output, logs = io.BytesIO(), io.StringIO()
        with contextlib.redirect_stdout(logs):
            registry.transfer('https://lscr.io/v2/example/blobs/sha256:fake',
                              {'Authorization': 'Bearer private-token'}, output, 3, 2)
        self.assertEqual(requests[0].get_header('Authorization'), 'Bearer private-token')
        self.assertIsNone(requests[1].get_header('Authorization'))
        self.assertEqual(output.getvalue(), b'abc')
        self.assertEqual(logs.getvalue(), '')

    def test_acquisition_archives_only_verified_selected_closure(self):
        def digest(raw):
            return 'sha256:' + hashlib.sha256(raw).hexdigest()
        config = core.canonical({'os': 'linux', 'architecture': 'amd64',
                                 'config': {'Labels': {'org.opencontainers.image.version': 'fixture-version'}}})
        layer = b'opaque compressed layer fixture; never extracted'
        config_record = {'mediaType': 'application/vnd.oci.image.config.v1+json',
                         'digest': digest(config), 'size': len(config)}
        layer_record = {'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                        'digest': digest(layer), 'size': len(layer)}
        manifest = core.canonical({'schemaVersion': 2,
            'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'config': config_record, 'layers': [layer_record]})
        selected = {'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                    'digest': digest(manifest), 'size': len(manifest),
                    'platform': {'os': 'linux', 'architecture': 'amd64'}}
        index = core.canonical({'schemaVersion': 2,
            'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': [selected]})
        blobs = {digest(raw): raw for raw in (config, layer, manifest, index)}
        class Registry:
            def manifest(self, repository, wanted):
                return blobs[wanted], json.loads(blobs[wanted])
            def headers(self, repository):
                return {}
            def transfer(self, url, headers, sink, limit, seconds):
                raw = blobs[url.rsplit('/', 1)[1]]
                self.assert_bound = len(raw) <= limit
                if not self.assert_bound:
                    raise AssertionError('fixture exceeds declared bound')
                sink.write(raw)
        images = (('fixture', 'linuxserver/sonarr', digest(index)[7:],
                   digest(manifest)[7:], digest(config)[7:], 'fixture-version'),)
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / 'cache'
            core.private_directory(cache)
            core.private_directory(cache / 'layout')
            blob_dir = core.private_directory(cache / 'layout' / 'blobs' / 'sha256')
            unrelated = b'private unrelated cache entry'
            core.write_new(blob_dir / digest(unrelated)[7:], unrelated)
            with mock.patch.object(oci_acquire, 'Registry', Registry), \
                    mock.patch.object(oci_acquire, 'IMAGES', images), \
                    contextlib.redirect_stdout(io.StringIO()):
                oci_acquire.acquire(cache)
            snapshot = next(cache.glob('snapshot-*'))
            report = json.loads((snapshot / 'acquisition.json').read_bytes())
            self.assertFalse(report['docker_or_runtime_operations'])
            self.assertFalse(report['registry_signatures_verified'])
            with tarfile.open(snapshot / 'images.oci.tar') as archive:
                names = set(archive.getnames())
                self.assertEqual(names, {'index.json', 'oci-layout'} |
                                 {'blobs/sha256/' + key[7:] for key in blobs})
                self.assertNotIn('blobs/sha256/' + digest(unrelated)[7:], names)
                self.assertEqual(archive.extractfile('blobs/sha256/' + digest(layer)[7:]).read(), layer)
            archive_bytes = (snapshot / 'images.oci.tar').read_bytes()
            self.assertEqual(hashlib.sha256(archive_bytes).hexdigest(), report['archive']['sha256'])


if __name__ == '__main__':
    unittest.main()
