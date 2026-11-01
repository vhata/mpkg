"""Host-safe tests: temporary files/SQLite only, no real service/package tools."""
import importlib.util
import contextlib
import hashlib
import io
import json
import os
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
        for filename in ('image_import.py', 'image_manifest.py', 'native_manifest.py', 'docker_ready.py'):
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


class DockerReadinessTests(unittest.TestCase):
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


class NativeServiceTests(unittest.TestCase):
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
