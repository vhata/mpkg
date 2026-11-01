"""Literal edits use disposable repos and stubbed package operations."""
import subprocess
import unittest

import test_mpkg


class LiteralEditingTests(unittest.TestCase):
    def setUp(self):
        self.command = test_mpkg.CommandTests()
        self.command.setUp()
        self.addCleanup(self.command.doCleanups)
        self.build = self.command.repo / 'vhata-test/PKGBUILD'

    def prepare(self, source):
        self.build.parent.mkdir(exist_ok=True)
        self.build.write_text(source)
        self.command.git('add', 'vhata-test/PKGBUILD')
        self.command.git('commit', '-qm', 'Fixture package')
        (self.command.root / 'log').write_text('')
        return self.command.git('rev-parse', 'HEAD')

    def assert_rejected(self, source, **env):
        head = self.prepare(source)
        result = self.command.invoke('test', '+python', **env)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.build.read_text(), source)
        self.assertEqual(self.command.git('rev-parse', 'HEAD'), head)
        self.assertEqual(self.command.calls(), [])
        return result

    def test_comment_parentheses_preserve_dependencies_and_surrounding_source(self):
        prefix = "# package header\npkgrel=1\npkgdesc='Tools'\narch=('any')\n\n"
        suffix = " # keep trailing comment\n\npackage() {\n  : # package body\n}\n"
        source = prefix + 'depends=(git # base (required)\n  python\n)' + suffix
        self.prepare(source)
        result = self.command.invoke('test', '+rust')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.build.read_text(), prefix.replace('pkgrel=1', 'pkgrel=2')
                         + 'depends=(\n  git\n  python\n  rust\n)' + suffix)
        self.assertIn(['sudo', 'pacman', '-D', '--asdeps', 'git', 'python', 'rust'],
                      self.command.calls())
        syntax = subprocess.run(['bash', '-n', str(self.build)], capture_output=True, text=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_multiline_description_remains_editable(self):
        description = "Tools\npkgrel=7\ndepends=(zsh)\nowner's tools for development"
        result = self.command.invoke('test', description, 'git')
        self.assertEqual(result.returncode, 0, result.stderr)
        before = self.build.read_text()
        (self.command.root / 'log').write_text('')
        result = self.command.invoke('test', '+python')
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = before.replace('pkgrel=1\n', 'pkgrel=2\n', 1)
        expected = expected.replace('depends=(\n  git\n)', 'depends=(\n  git\n  python\n)')
        self.assertEqual(self.build.read_text(), expected)
        self.assertIn(['sudo', 'pacman', '-D', '--asdeps', 'git', 'python'],
                      self.command.calls())

    def test_double_quoted_description_and_reversed_assignment_order(self):
        source = ('pkgdesc="Tools\npkgrel=19\ndepends=(zsh)\nfor development"\n'
                  '  depends=("git" \'python\')\n  pkgrel=4 # keep release comment\n')
        self.prepare(source)
        result = self.command.invoke('test', '-git', '+rust')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.build.read_text(), source.replace(
            'depends=("git" \'python\')', 'depends=(\n  python\n  rust\n)').replace(
            'pkgrel=4 # keep', 'pkgrel=5 # keep'))

    def test_comment_expressions_are_not_executed(self):
        sentinel = self.command.root / 'comment-sentinel'
        source = ('pkgrel=1\ndepends=(git # ) $(touch ' + str(sentinel)
                  + ') `touch ' + str(sentinel) + '` \\\n  python\n)\n')
        self.prepare(source)
        result = self.command.invoke('test', '+rust')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertIn(['sudo', 'pacman', '-D', '--asdeps', 'git', 'python', 'rust'],
                      self.command.calls())

    def test_unsupported_dependency_expressions_leave_source_and_history_untouched(self):
        sentinel = self.command.root / 'expression-sentinel'
        for expression in [f'$(touch {sentinel})', f'`touch {sentinel}`',
                           f"'$(touch {sentinel})'", '"$runtime_deps"', '${runtime_deps[@]}', 'git \\\n python',
                           "'git#not-a-comment'", 'git#not-a-comment', "'git)'", '[0]=git']:
            with self.subTest(expression=expression):
                self.assert_rejected(f'pkgrel=1\ndepends=({expression})\n')
                self.assertFalse(sentinel.exists())

    def test_ambiguous_assignments_and_shell_constructs_are_rejected(self):
        cases = [
            'pkgrel=1\npkgrel=2\ndepends=(git)\n',
            'pkgrel=1\ndepends=(git)\ndepends+=(python)\n',
            'pkgrel=1\ndepends=(git)\ndepends=(python)\n',
            'pkgrel=1\ndepends=(git); pkgrel=2\n',
            'pkgrel=1\ndepends=(git)\nif false; then\npkgrel=2\nfi\n',
            "cat <<'END'\npkgrel=1\ndepends=(git)\nEND\n",
            'pkgrel=1\ndepends=(git)\nother=$(printf unsafe)\n',
            'pkgrel=1\ndepends=(git)\nother=unfinished\\\n',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assert_rejected(source)

    def test_invalid_shell_source_is_rejected_before_writing(self):
        self.assert_rejected('pkgrel=1\ndepends=(git)\npackage() {\n  : && ;\n}\n')

    def test_function_assignments_do_not_override_literal_fields(self):
        source = ('pkgrel=1\ndepends=(git)\npackage()\n{\n'
                  '  pkgrel=7\n  depends=(zsh)\n  :\n}\n')
        self.prepare(source)
        result = self.command.invoke('test', '+python')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.build.read_text(), source.replace('pkgrel=1', 'pkgrel=2').replace(
            'depends=(git)', 'depends=(\n  git\n  python\n)'))

    def test_syntax_validation_does_not_source_bash_env_or_execute_functions(self):
        sentinel = self.command.root / 'startup-sentinel'
        startup = self.command.root / 'bash-env'
        startup.write_text(f'touch {sentinel}\n')
        source = f'pkgrel=1\ndepends=(git)\npackage() {{\n  touch {sentinel}\n}}\n'
        self.prepare(source)
        result = self.command.invoke('test', '+python', BASH_ENV=str(startup))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())

    def test_comment_line_endings_are_preserved(self):
        source = b'# header\r\npkgrel=1 # release\r\ndepends=(git) # dependencies\r\n'
        self.build.parent.mkdir()
        self.build.write_bytes(source)
        result = self.command.invoke('test', '+python')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.build.read_bytes(), source.replace(b'pkgrel=1', b'pkgrel=2').replace(
            b'depends=(git)', b'depends=(\n  git\n  python\n)'))

    def test_failed_output_syntax_check_does_not_overwrite_existing_package(self):
        counter = self.command.root / 'bash-invoked'
        bash = self.command.root / 'bin/bash'
        bash.write_text('#!/bin/sh\n'
                        f'if [ -e "{counter}" ]; then exit 2; fi\n'
                        f': > "{counter}"\nexit 0\n')
        bash.chmod(0o755)
        self.assert_rejected('pkgrel=1\ndepends=(git)\n')
        self.assertTrue(counter.exists())

    def test_failed_output_syntax_check_does_not_create_package_or_commit(self):
        # Force the validator to fail even for generated output, proving its
        # failure is checked before mkdir/write and before package-tool calls.
        bash = self.command.root / 'bin/bash'
        bash.write_text('#!/bin/sh\nexit 2\n')
        bash.chmod(0o755)
        head = self.command.git('rev-parse', 'HEAD')
        result = self.command.invoke('test', 'Tools', 'git')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.build.parent.exists())
        self.assertEqual(self.command.git('rev-parse', 'HEAD'), head)
        self.assertFalse((self.command.root / 'log').exists())


if __name__ == '__main__':
    unittest.main()
