"""Host-safe tests: temporary files/SQLite only, no real service/package tools."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid


PROOFS = Path(__file__).resolve().parents[1] / 'scripts' / 'proofs'
SPEC = importlib.util.spec_from_file_location('proof_core', PROOFS / 'core.py')
core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core)


class GuestGuardTests(unittest.TestCase):
    def setUp(self):
        self.guest = str(uuid.uuid4())
        self.marker = {'schema': 1, 'guest_id': self.guest,
                       'fixture_id': 'first-release-2026-10-31',
                       'disposable': True}
        self.metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                                        st_uid=0, st_gid=0, st_nlink=1)

    def test_matching_marker_is_insufficient_without_vm_identity(self):
        with self.assertRaisesRegex(core.Refused, 'guest_machine_mismatch'):
            core.validate_guest(self.guest, self.marker, self.metadata,
                                str(uuid.uuid4()), 'QEMU')
        with self.assertRaisesRegex(core.Refused, 'guest_machine_mismatch'):
            core.validate_guest(self.guest, self.marker, self.metadata,
                                self.guest, 'production vendor')
        self.assertEqual(core.validate_guest(
            self.guest, self.marker, self.metadata, self.guest, 'QEMU'), self.guest)

    def test_marker_permissions_and_unexpected_fields_refuse(self):
        self.metadata.st_mode = stat.S_IFREG | 0o644
        with self.assertRaisesRegex(core.Refused, 'guest_marker_permissions'):
            core.validate_guest(self.guest, self.marker, self.metadata,
                                self.guest, 'QEMU')
        self.metadata.st_mode = stat.S_IFREG | 0o600
        self.marker['command'] = 'untrusted'
        with self.assertRaisesRegex(core.Refused, 'guest_marker_mismatch'):
            core.validate_guest(self.guest, self.marker, self.metadata,
                                self.guest, 'QEMU')

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


if __name__ == '__main__':
    unittest.main()
