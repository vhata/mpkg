"""Integration tests; package tools are stubbed, Git runs in temporary repos."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'mpkg'


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        shutil.copy2(SCRIPT, self.repo / 'mpkg')
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        stub = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with open(os.environ['LOG'], 'a') as log:
    log.write(json.dumps([Path(sys.argv[0]).name, *sys.argv[1:]]) + '\\n')
if '--printsrcinfo' in sys.argv:
    print(os.environ.get('SRCINFO', 'pkgver = 1\\npkgrel = 1\\npkgdesc = Test\\ndepends = git'))
if sys.argv[1:2] == ['-Q']:
    print('vhata-test ' + os.environ.get('INSTALLED', '1-1'))
if sys.argv[1:2] == ['-Qi']:
    print('Name : git\\nProvides : None\\n\\nName : provider\\nProvides : virtual=1')
if Path(sys.argv[0]).name == 'sudo':
    sys.exit(int(os.environ.get('FAIL_MARK', '0')))
if '-si' in sys.argv or '-sif' in sys.argv:
    sys.exit(int(os.environ.get('FAIL_BUILD', '0')))
if Path(sys.argv[0]).name == 'yay':
    sys.exit(int(os.environ.get('FAIL_YAY', '0')))
if '-T' in sys.argv:
    if os.environ.get('MISSING') == '127':
        print(os.environ.get('MISSING_DEPS', 'git'))
    sys.exit(int(os.environ.get('MISSING', '0')))
'''
        for name in ('makepkg', 'sudo', 'pacman', 'yay'):
            path = bin_dir / name
            path.write_text(stub)
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ['PATH'],
                        LOG=str(self.root / 'log'))
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.com')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('add', 'mpkg')
        self.git('commit', '-qm', 'Initial')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo, env=self.env, text=True).strip()

    def invoke(self, *args, **env):
        return subprocess.run([str(self.repo / 'mpkg'), *args], cwd=self.root,
                              env=dict(self.env, **env), text=True, capture_output=True)

    def create(self):
        result = self.invoke('test', 'Test tools', 'git')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_create_edit_and_scoped_commits(self):
        unrelated = self.repo / 'unrelated'
        unrelated.write_text('staged')
        self.git('add', 'unrelated')
        self.create()
        self.assertEqual(self.git('log', '-1', '--format=%s'), '[pkgs] Create vhata-test: Test tools')
        self.assertEqual(self.git('diff', '--cached', '--name-only'), 'unrelated')
        result = self.invoke('test', '+python', '-git', '+python', '-absent')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git('log', '-1', '--format=%s'),
                         '[pkgs] Update vhata-test: add python; remove git')
        self.assertIn('pkgrel=2', (self.repo / 'vhata-test/PKGBUILD').read_text())
        calls = [json.loads(line) for line in (self.root / 'log').read_text().splitlines()]
        self.assertIn(['makepkg', '-si'], calls)
        self.assertFalse(any(call[0] == 'yay' for call in calls))

    def test_missing_yay_blocks_changes_but_allows_queries(self):
        self.create()
        build = self.repo / 'vhata-test/PKGBUILD'
        before = build.read_bytes()
        head = self.git('rev-parse', 'HEAD')
        bin_dir = self.root / 'bin'
        (bin_dir / 'yay').unlink()
        (bin_dir / 'python3').symlink_to(shutil.which('python3'))
        # Restrict PATH so an installed system yay cannot mask the missing stub.
        for args in [('test', '+gitstatus'), ('test', '--refresh'),
                     ('new', 'New package', 'git')]:
            result = self.invoke(*args, PATH=str(bin_dir))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('yay is required', result.stderr)
            self.assertEqual(build.read_bytes(), before)
            self.assertFalse((self.repo / 'vhata-new').exists())
            self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        for args in [('--list',), ('--info', 'test'), ('--description', 'test'),
                     ('--depends', 'test'), ('--help',)]:
            result = self.invoke(*args, PATH=str(bin_dir))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_aur_and_repo_dependencies_installed_before_local_build(self):
        self.create()
        result = self.invoke('test', '+gitstatus', '+zsh', MISSING='127',
                             MISSING_DEPS='gitstatus\nzsh')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.root / 'log').read_text().splitlines()]
        install = ['yay', '-S', '--needed', '--asdeps', '--', 'gitstatus', 'zsh']
        self.assertIn(install, calls)
        self.assertEqual(calls[calls.index(install) + 1], ['makepkg', '-si'])
        self.assertFalse(any('-Bi' in call for call in calls))

    def test_dependency_install_or_check_failure_prevents_build_and_commit(self):
        self.create()
        head = self.git('rev-parse', 'HEAD')
        for env in ({'MISSING': '127', 'MISSING_DEPS': 'gitstatus', 'FAIL_YAY': '1'},
                    {'MISSING': '1'}):
            (self.root / 'log').write_text('')
            result = self.invoke('test', '+gitstatus', **env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.git('rev-parse', 'HEAD'), head)
            calls = [json.loads(line) for line in (self.root / 'log').read_text().splitlines()]
            self.assertNotIn(['makepkg', '-si'], calls)

    def test_description_quoting_and_redefinition(self):
        self.create()
        desc = "Tools with 'quotes', $HOME and `commands`\nand newlines"
        result = self.invoke('test', desc, 'git>=2', 'python')
        self.assertEqual(result.returncode, 0, result.stderr)
        build = self.repo / 'vhata-test/PKGBUILD'
        actual = subprocess.check_output(['bash', '-c', 'source "$1"; printf "%s" "$pkgdesc"',
                                          'test', str(build)], text=True)
        self.assertEqual(actual, desc)
        self.assertIn('set description to', self.git('log', '-1', '--format=%B'))

    def test_failed_update_keeps_edits_without_commit(self):
        self.create()
        head = self.git('rev-parse', 'HEAD')
        for env in ({'FAIL_BUILD': '12'}, {'FAIL_MARK': '13'}):
            result = self.invoke('test', '+rust', **env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('No commit created', result.stderr)
            self.assertEqual(self.git('rev-parse', 'HEAD'), head)
            self.assertIn('rust', (self.repo / 'vhata-test/PKGBUILD').read_text())

    def test_queries_through_symlink(self):
        self.create()
        link = self.root / 'linked'
        link.symlink_to('repo/mpkg')
        result = subprocess.run([str(link), '--list'], cwd='/tmp', env=self.env,
                                text=True, capture_output=True)
        self.assertEqual(result.stdout, 'vhata-test\n')
        self.assertEqual(self.invoke('--description', 'test').stdout, 'Test\n')
        self.assertEqual(self.invoke('--depends', 'test').stdout, 'git\n')
        self.assertIn('Description: Test', self.invoke('--info', 'test', 'vhata-test').stdout)
        for args in [('--info',), ('--list', 'test'), ('--info', '../test'),
                     ('--info', 'test', 'missing'), ('test', '+bad;command')]:
            result = self.invoke(*args)
            self.assertNotEqual(result.returncode, 0, args)

    def test_refresh_no_rewrite_or_commit_and_provider_resolution(self):
        self.create()
        before = (self.repo / 'vhata-test/PKGBUILD').read_bytes()
        head = self.git('rev-parse', 'HEAD')
        info = 'pkgver = 1\npkgrel = 1\ndepends = git>=2\ndepends = virtual'
        result = self.invoke('test', '--refresh', SRCINFO=info)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('up to date', result.stdout)
        self.assertIn('["sudo", "pacman", "-D", "--asdeps", "git", "provider"]',
                      (self.root / 'log').read_text())
        for env in ({'INSTALLED': '0-1'}, {'MISSING': '127'}):
            result = self.invoke('test', '--refresh', **env)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in (self.root / 'log').read_text().splitlines()]
            self.assertIn(['makepkg', '-sif'], calls)
        self.assertEqual((self.repo / 'vhata-test/PKGBUILD').read_bytes(), before)
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)

    def test_invalid_existing_array_is_never_executed(self):
        self.create()
        build = self.repo / 'vhata-test/PKGBUILD'
        build.write_text('pkgrel=1\ndepends=($(touch sentinel))\n')
        before = build.read_text()
        self.assertNotEqual(self.invoke('test', '+git').returncode, 0)
        self.assertEqual(build.read_text(), before)
        self.assertFalse((self.repo / 'sentinel').exists())


if __name__ == '__main__':
    unittest.main()
