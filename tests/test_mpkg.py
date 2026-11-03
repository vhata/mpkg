"""Integration tests; package tools are stubbed, Git runs in temporary repos."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

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
import json, os, re, sys
from pathlib import Path
with open(os.environ['LOG'], 'a') as log:
    log.write(json.dumps([Path(sys.argv[0]).name, *sys.argv[1:]]) + '\\n')
installed_info = os.environ.get('INSTALLED_INFO', '\\n\\n'.join(
    'Name : ' + name + '\\nVersion : ' + version + '\\nProvides : ' + provides
    for name, version, provides in [
        ('git', '2.51.0-1', 'None'), ('python', '3.12.16-1', 'None'),
        ('rust', '1.90-1', 'None'), ('gitstatus', '1.5.5-1', 'None'),
        ('zsh', '5.9-1', 'None'), ('provider', '10-1', 'virtual=1')]))
if '--printsrcinfo' in sys.argv:
    print(os.environ.get('SRCINFO', 'pkgver = 1\\npkgrel = 1\\npkgdesc = Test\\ndepends = git'))
if sys.argv[1:2] == ['-Q']:
    print('vhata-test ' + os.environ.get('INSTALLED', '1-1'))
if sys.argv[1:2] == ['-Qi']:
    print(installed_info)
if Path(sys.argv[0]).name == 'vercmp':
    if os.environ.get('FAIL_VERCMP'):
        sys.exit(int(os.environ['FAIL_VERCMP']))
    comparisons = json.loads(os.environ.get('VERCMP_RESULTS', '{}'))
    comparisons.setdefault('2.51.0-1\\t2', 1)
    key = '\\t'.join(sys.argv[1:])
    if key not in comparisons:
        print('Unexpected version comparison: ' + repr(sys.argv[1:]), file=sys.stderr)
        sys.exit(88)
    print(comparisons[key])
if Path(sys.argv[0]).name == 'sudo':
    installed = set(re.findall(r'^Name\\s*:\\s*(\\S+)', installed_info, re.M))
    if sys.argv[1:4] != ['pacman', '-D', '--asdeps'] or not sys.argv[4:]:
        sys.exit(89)
    if any(target not in installed for target in sys.argv[4:]):
        print('Only installed package names can be marked', file=sys.stderr)
        sys.exit(90)
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
        for name in ('makepkg', 'sudo', 'pacman', 'yay', 'vercmp'):
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

    def calls(self):
        return [json.loads(line) for line in (self.root / 'log').read_text().splitlines()]

    @staticmethod
    def installed_info(*packages):
        return '\n\n'.join(f'Name : {name}\nVersion : {version}\nProvides : {provides}'
                           for name, version, provides in packages)

    def test_create_resolves_versioned_and_virtual_marking_targets(self):
        info = self.installed_info(('git', '2.51.0-1', 'None'),
                                   ('new-provider', '100-1', 'virtual=2'),
                                   ('old-provider', '200-1', 'virtual=1'))
        result = self.invoke('test', 'Versioned tools', 'git>=2', 'virtual>=2',
                             INSTALLED_INFO=info,
                             SRCINFO='pkgver = 1\npkgrel = 1\ndepends = git>=2\ndepends = virtual>=2',
                             VERCMP_RESULTS=json.dumps({'2\t2': 0, '1\t2': -1}))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        mark = ['sudo', 'pacman', '-D', '--asdeps', 'git', 'new-provider']
        self.assertIn(mark, calls)
        self.assertLess(calls.index(['makepkg', '-si']), calls.index(['pacman', '-Qi']))
        self.assertLess(calls.index(['pacman', '-Qi']), calls.index(mark))
        self.assertEqual(self.git('log', '-1', '--format=%s'),
                         '[pkgs] Create vhata-test: Versioned tools')

    def test_edit_resolves_virtual_marking_targets(self):
        self.create()
        (self.root / 'log').write_text('')
        result = self.invoke('test', '+virtual')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(['sudo', 'pacman', '-D', '--asdeps', 'git', 'provider'], self.calls())
        self.assertEqual(self.git('log', '-1', '--format=%s'),
                         '[pkgs] Update vhata-test: add virtual')

    def test_refresh_filters_provided_versions_for_every_operator(self):
        self.create()
        info = self.installed_info(('low', '100-1', 'other\n              virtual=1'),
                                   ('equal', '100-1', 'virtual=2'),
                                   ('high', '100-1', 'virtual=3'),
                                   ('versionless', '100-1', 'virtual'))
        # Signed native comparator results need not be limited to -1/0/1.
        comparisons = json.dumps({'1\t2': -12, '2\t2': 0, '3\t2': 9})
        for operator, selected in [('>=', ['equal', 'high']), ('>', ['high']),
                                   ('<=', ['equal', 'low']), ('<', ['low']),
                                   ('=', ['equal'])]:
            with self.subTest(operator=operator):
                (self.root / 'log').write_text('')
                result = self.invoke('test', '--refresh', INSTALLED_INFO=info,
                                     SRCINFO=f'pkgver = 1\npkgrel = 1\ndepends = virtual{operator}2',
                                     VERCMP_RESULTS=comparisons)
                self.assertEqual(result.returncode, 0, result.stderr)
                marks = [call for call in self.calls() if call[0] == 'sudo']
                self.assertEqual(marks, [['sudo', 'pacman', '-D', '--asdeps', *selected]])
                self.assertNotIn(['vercmp', '100-1', '2'], self.calls())

    def test_refresh_falls_back_from_incompatible_direct_name(self):
        self.create()
        (self.root / 'log').write_text('')
        info = self.installed_info(('virtual', '1-1', 'None'),
                                   ('provider', '99-1', 'virtual=2'))
        result = self.invoke('test', '--refresh', INSTALLED_INFO=info,
                             SRCINFO='pkgver = 1\npkgrel = 1\ndepends = virtual>=2',
                             VERCMP_RESULTS=json.dumps({'1-1\t2': -1, '2\t2': 0}))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(['sudo', 'pacman', '-D', '--asdeps', 'provider'], self.calls())
        self.assertNotIn(['sudo', 'pacman', '-D', '--asdeps', 'virtual'], self.calls())

    def test_direct_versions_use_native_epoch_release_and_prerelease_results(self):
        self.create()
        for installed, operator, wanted, comparison in [('2:1.0-1', '>', '1:99.0-3', 1),
                                                         ('1.5-1', '=', '1.5', 0),
                                                         ('1.0rc-1', '<', '1.0', -1)]:
            requirement = f'git{operator}{wanted}'
            with self.subTest(requirement=requirement):
                (self.root / 'log').write_text('')
                result = self.invoke('test', '--refresh',
                                     INSTALLED_INFO=self.installed_info(('git', installed, 'None')),
                                     SRCINFO=f'pkgver = 1\npkgrel = 1\ndepends = {requirement}',
                                     VERCMP_RESULTS=json.dumps({f'{installed}\t{wanted}': comparison}))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(['vercmp', installed, wanted], self.calls())
                self.assertIn(['sudo', 'pacman', '-D', '--asdeps', 'git'], self.calls())

    def test_refresh_prefers_a_satisfying_direct_name(self):
        self.create()
        (self.root / 'log').write_text('')
        info = self.installed_info(('virtual', '2-1', 'None'),
                                   ('other-provider', '99-1', 'virtual=2'))
        result = self.invoke('test', '--refresh', INSTALLED_INFO=info,
                             SRCINFO='pkgver = 1\npkgrel = 1\ndepends = virtual>=2',
                             VERCMP_RESULTS=json.dumps({'2-1\t2': 0}))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call for call in self.calls() if call[0] == 'sudo'],
                         [['sudo', 'pacman', '-D', '--asdeps', 'virtual']])

    def test_unversioned_requirement_accepts_an_unversioned_provide(self):
        self.create()
        (self.root / 'log').write_text('')
        result = self.invoke('test', '--refresh',
                             INSTALLED_INFO=self.installed_info(('provider', '99-1', 'virtual')),
                             SRCINFO='pkgver = 1\npkgrel = 1\ndepends = virtual')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(['sudo', 'pacman', '-D', '--asdeps', 'provider'], self.calls())
        self.assertFalse(any(call[0] == 'vercmp' for call in self.calls()))

    def test_unsatisfied_requirement_prevents_marking_and_commit(self):
        self.create()
        head = self.git('rev-parse', 'HEAD')
        for provider in [None, ('provider', '100-1', 'virtual'),
                         ('virtual', '1-1', 'None')]:
            with self.subTest(provider=provider):
                (self.root / 'log').write_text('')
                records = [('git', '2.51.0-1', 'None')]
                if provider is not None:
                    records.append(provider)
                result = self.invoke('test', '+virtual>=2',
                                     INSTALLED_INFO=self.installed_info(*records),
                                     VERCMP_RESULTS=json.dumps({'1-1\t2': -1}))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('No commit created', result.stderr)
                self.assertEqual(self.git('rev-parse', 'HEAD'), head)
                self.assertIn('virtual>=2', (self.repo / 'vhata-test/PKGBUILD').read_text())
                self.assertFalse(any(call[0] == 'sudo' for call in self.calls()))

    def test_comparison_failure_prevents_marking_and_commit(self):
        self.create()
        head = self.git('rev-parse', 'HEAD')
        for env in [{'FAIL_VERCMP': '17'},
                    {'VERCMP_RESULTS': json.dumps({'1\t2': 'invalid result'})}]:
            with self.subTest(env=env):
                (self.root / 'log').write_text('')
                result = self.invoke('test', '+virtual>=2', **env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('No commit created', result.stderr)
                self.assertEqual(self.git('rev-parse', 'HEAD'), head)
                self.assertFalse(any(call[0] == 'sudo' for call in self.calls()))

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
        startup = self.root / 'shell-startup'
        startup.write_text('printf "unexpected shell startup\\n"\nexit 42\n')
        with patch.dict(os.environ, {'BASH_ENV': str(startup), 'ENV': str(startup)}):
            actual = subprocess.check_output(['bash', '-c', 'source "$1"; printf "%s" "$pkgdesc"',
                                              'test', str(build)], text=True,
                                             env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
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
        (self.root / 'log').write_text('')
        result = self.invoke('test', '--refresh', SRCINFO=info)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('up to date', result.stdout)
        calls = self.calls()
        self.assertIn(['sudo', 'pacman', '-D', '--asdeps', 'git', 'provider'], calls)
        self.assertFalse(any(call[0] == 'yay' or call in
                             (['makepkg', '-si'], ['makepkg', '-sif']) for call in calls))
        self.assertEqual((self.repo / 'vhata-test/PKGBUILD').read_bytes(), before)
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        for reason, env in [('outdated version', {'INSTALLED': '0-1'}),
                            ('missing dependency', {'MISSING': '127'})]:
            with self.subTest(reason=reason):
                (self.root / 'log').write_text('')
                result = self.invoke('test', '--refresh', **env)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.calls()
                actions = [call for call in calls if call[0] in ('yay', 'sudo') or
                           call in (['makepkg', '-si'], ['makepkg', '-sif'])]
                expected = ([['yay', '-S', '--needed', '--asdeps', '--', 'git']]
                            if 'MISSING' in env else [])
                expected += [['makepkg', '-sif'],
                             ['sudo', 'pacman', '-D', '--asdeps', 'git']]
                self.assertEqual(actions, expected)
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
