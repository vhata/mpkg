"""Refresh integration coverage with isolated package-tool command logs."""
import json
import os
from pathlib import Path
import unittest

import test_mpkg


class ArchitectureDependencyTests(unittest.TestCase):
    def setUp(self):
        self.commands = test_mpkg.CommandTests()
        self.addCleanup(self.commands.doCleanups)
        self.commands.setUp()
        self.commands.create()
        self.architecture = os.uname().machine
        self.other_architecture = 'aarch64' if self.architecture != 'aarch64' else 'x86_64'
        self.build = self.commands.repo / 'vhata-test/PKGBUILD'
        self.original = self.build.read_bytes()
        self.head = self.commands.git('rev-parse', 'HEAD')

    def metadata(self, generic=(), active=('virtual>=2', 'rust')):
        fields = ['pkgver = 1', 'pkgrel = 1', 'pkgdesc = Test']
        fields.extend(f'depends = {dep}' for dep in generic)
        fields.extend(f'depends_{self.architecture} = {dep}' for dep in active)
        fields.append(f'depends_{self.other_architecture} = unavailable-other-architecture')
        return '\n'.join(fields)

    def invoke(self, *args, **env):
        # Setup and earlier invocations cannot supply this command's evidence.
        Path(self.commands.env['LOG']).write_text('')
        defaults = dict(
            INSTALLED='1-1',
            INSTALLED_INFO=self.commands.installed_info(
                ('git', '2.51.0-1', 'None'), ('rust', '1.90-1', 'None'),
                ('old-provider', '100-1', 'virtual=1'),
                ('new-provider', '10-1', 'virtual=2')),
            VERCMP_RESULTS=json.dumps({'1\t2': -1, '2\t2': 0}))
        return self.commands.invoke(*args, **(defaults | env))

    def assert_unchanged(self):
        self.assertEqual(self.build.read_bytes(), self.original)
        self.assertEqual(self.commands.git('rev-parse', 'HEAD'), self.head)

    def test_matching_version_refresh_installs_missing_active_dependencies(self):
        for generic in [(), ('git>=2',)]:
            with self.subTest(generic=generic):
                result = self.invoke('test', '--refresh', SRCINFO=self.metadata(generic),
                                     MISSING='127', MISSING_DEPS='virtual>=2')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('up to date', result.stdout)
                calls = self.commands.calls()
                check = ['pacman', '-T', *generic, 'virtual>=2', 'rust']
                self.assertEqual(calls[:8], [
                    ['makepkg', '--printsrcinfo'], ['pacman', '-Q', 'vhata-test'],
                    check, ['makepkg', '--printsrcinfo'], check,
                    ['yay', '-S', '--needed', '--asdeps', '--', 'virtual>=2'],
                    ['makepkg', '-sif'], ['pacman', '-Qi']])
                targets = ['git', 'new-provider', 'rust'] if generic else ['new-provider', 'rust']
                self.assertEqual(calls[-1], ['sudo', 'pacman', '-D', '--asdeps', *targets])
                self.assert_unchanged()

    def test_matching_version_refresh_marks_satisfied_active_dependencies(self):
        for generic in [(), ('git>=2',)]:
            with self.subTest(generic=generic):
                result = self.invoke('test', '--refresh', SRCINFO=self.metadata(generic))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('up to date', result.stdout)
                calls = self.commands.calls()
                self.assertEqual(calls[:4], [
                    ['makepkg', '--printsrcinfo'], ['pacman', '-Q', 'vhata-test'],
                    ['pacman', '-T', *generic, 'virtual>=2', 'rust'], ['pacman', '-Qi']])
                self.assertFalse(any(call[0] == 'yay' or call[1:] == ['-sif'] for call in calls))
                targets = ['git', 'new-provider', 'rust'] if generic else ['new-provider', 'rust']
                self.assertEqual(calls[-1], ['sudo', 'pacman', '-D', '--asdeps', *targets])
                self.assert_unchanged()

    def test_refresh_ignores_dependencies_for_other_architectures(self):
        result = self.invoke('test', '--refresh', SRCINFO=self.metadata(active=()), MISSING='127')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('up to date', result.stdout)
        self.assertEqual(self.commands.calls(), [
            ['makepkg', '--printsrcinfo'], ['pacman', '-Q', 'vhata-test']])
        self.assert_unchanged()

    def test_inspection_lists_dependencies_for_every_architecture(self):
        for mode in ('--depends', '--info'):
            with self.subTest(mode=mode):
                result = self.invoke(mode, 'test', SRCINFO=self.metadata(('git>=2',)))
                self.assertEqual(result.returncode, 0, result.stderr)
                for dep in ('git>=2', 'virtual>=2', 'rust', 'unavailable-other-architecture'):
                    self.assertIn(dep, result.stdout.split())
                self.assertEqual(self.commands.calls(), [['makepkg', '--printsrcinfo']])

    def test_active_dependency_failures_stop_later_operations(self):
        for env, code, last_call in [
            ({'MISSING': '1'}, 1, ['pacman', '-T', 'virtual>=2']),
            ({'FAIL_YAY': '12'}, 12,
             ['yay', '-S', '--needed', '--asdeps', '--', 'virtual>=2']),
            ({'FAIL_BUILD': '13'}, 13, ['makepkg', '-sif']),
            ({'FAIL_MARK': '14'}, 14, ['sudo', 'pacman', '-D', '--asdeps', 'new-provider']),
        ]:
            with self.subTest(env=env):
                result = self.invoke('test', '--refresh',
                                     SRCINFO=self.metadata(active=('virtual>=2',)),
                                     **({'MISSING': '127', 'MISSING_DEPS': 'virtual>=2'} | env))
                self.assertEqual(result.returncode, code, result.stderr)
                calls = self.commands.calls()
                self.assertEqual(calls[-1], last_call)
                if 'FAIL_MARK' not in env:
                    self.assertFalse(any(call[0] == 'sudo' for call in calls))
                self.assert_unchanged()

    def test_unsatisfied_active_requirement_prevents_marking(self):
        result = self.invoke('test', '--refresh',
                             SRCINFO=self.metadata(active=('virtual>=2',)),
                             INSTALLED_INFO=self.commands.installed_info(
                                 ('old-provider', '100-1', 'virtual=1')))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Cannot find installed provider for virtual>=2', result.stderr)
        self.assertFalse(any(call[0] == 'sudo' for call in self.commands.calls()))
        self.assert_unchanged()
