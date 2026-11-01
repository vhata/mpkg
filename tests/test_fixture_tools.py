"""Host boundary tests for disposable-fixture acquisition and extraction."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location(
    'fixture_runner', Path(__file__).resolve().parents[1] / 'scripts/fixture/runner.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class FixtureExtractionTests(unittest.TestCase):
    def archive(self, entries):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as tar:
            for name, kind, value in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    value = value.encode() if isinstance(value, str) else value
                    member.size = len(value)
                    member.mode = 0o6755
                    tar.addfile(member, io.BytesIO(value))
                else:
                    member.linkname = value
                    tar.addfile(member)
        output.seek(0)
        return output

    def test_escape_and_special_members_are_rejected_before_writes(self):
        cases = [('..','0',''), ('/outside','0',''), ('usr/link','2','../../outside'),
                 ('usr/link','2','/outside'), ('usr/link','1','../outside'), ('dev/a','3','')]
        for name, kind, target in cases:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as tmp:
                archive = self.archive([('safe', tarfile.REGTYPE, b'unchanged'),
                                        (name, kind.encode(), target)])
                with self.assertRaises(ValueError):
                    RUNNER.extract_tar(archive, Path(tmp)/'root')
                self.assertFalse((Path(tmp)/'root/safe').exists())

    def test_existing_parent_symlink_is_never_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';root.mkdir();outside=Path(tmp)/'outside';outside.mkdir()
            (root/'usr').symlink_to(outside, target_is_directory=True)
            archive=self.archive([('usr/escape',tarfile.REGTYPE,b'bad')])
            with self.assertRaises(ValueError):RUNNER.extract_tar(archive,root)
            self.assertFalse((outside/'escape').exists())

    def test_internal_links_and_regular_files_strip_privileged_bits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root'
            archive=self.archive([('usr/bin/tool',tarfile.REGTYPE,b'ok'),
                                  ('usr/bin/alias',tarfile.SYMTYPE,'tool')])
            RUNNER.extract_tar(archive,root)
            self.assertEqual((root/'usr/bin/tool').read_bytes(),b'ok')
            self.assertEqual((root/'usr/bin/tool').stat().st_mode & 0o7777,0o755)
            self.assertEqual((root/'usr/bin/alias').read_bytes(),b'ok')

    def test_cache_paths_and_writes_reject_existing_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'alias').symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):RUNNER.private_directory(root/'alias/child')
            (root/'target').symlink_to(root/'absent')
            with self.assertRaises(FileExistsError):RUNNER.write_new(root/'target',b'bad')

    def test_acquisition_rejects_other_hosts_credentials_and_traversal(self):
        for url in ['http://archive.archlinux.org/a','https://evil.invalid/a',
                    'https://user@archive.archlinux.org/a','https://archive.archlinux.org/../a',
                    'https://archive.archlinux.org/a?token=secret']:
            with self.subTest(url=url),self.assertRaises(ValueError):RUNNER.checked_url(url)


class FixtureTrustTests(unittest.TestCase):
    def test_failed_initialization_never_publishes_a_partial_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cache=root/'fixture';cache.mkdir();keys=root/'keys';keys.mkdir()
            for name in ('archlinux.gpg','archlinux-revoked'):(keys/name).write_text('')
            (keys/'archlinux-trusted').write_text('A'*40+':4:\n')
            result=SimpleNamespace(returncode=2,stderr=b'explicit failure')
            with mock.patch.object(RUNNER,'KEYRINGS',keys), mock.patch.object(RUNNER,'run_gpg',return_value=result):
                with self.assertRaises(RuntimeError):RUNNER.trust_home(cache)
            self.assertFalse((root/'fgpg').exists())
            diagnostics=list(root.glob('g*/failed-step-0.txt'))
            self.assertEqual(len(diagnostics),1)
            self.assertEqual(diagnostics[0].read_bytes(),b'explicit failure')

    def test_good_signature_without_full_trust_and_revoked_primary_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);artifact=root/'artifact';artifact.write_bytes(b'archive')
            signature=root/'signature';signature.write_bytes(b'signature')
            primary='A'*40;signer='B'*40
            (root/'archlinux-revoked').write_text('')
            valid=f'[GNUPG:] VALIDSIG {signer} 2026-11-01 123 0 4 0 1 10 00 {primary}\n'
            for trust,revoked in [('TRUST_UNDEFINED',''),('TRUST_FULLY',primary)]:
                (root/'archlinux-revoked').write_text(revoked+'\n')
                result=SimpleNamespace(returncode=0,stdout=(valid+f'[GNUPG:] {trust} 0 pgp\n').encode())
                with mock.patch.object(RUNNER,'KEYRINGS',root),mock.patch.object(RUNNER,'run_gpg',return_value=result):
                    with self.assertRaises(ValueError):RUNNER.verify_signature(root,artifact,signature)


if __name__ == '__main__':unittest.main()
