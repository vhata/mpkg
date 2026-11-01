"""Host boundary tests for disposable-fixture acquisition and extraction."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

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


if __name__ == '__main__':unittest.main()
