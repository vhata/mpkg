"""Manager validation reads one bounded input and never invokes host tools."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mpkg_manager.declarations import MAX_DECLARATION_BYTES


PROJECT = Path(__file__).resolve().parents[1]


class ManagerCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / 'environment.toml'
        self.source.write_text('schema=1\ncomponents=[]\nresources=[]\n')
        self.env = os.environ | {'PYTHONPATH': str(PROJECT), 'PYTHONDONTWRITEBYTECODE': '1',
                                 'HOME': str(self.root), 'PATH': str(self.root)}

    def invoke(self, *arguments):
        return subprocess.run([sys.executable, '-m', 'mpkg_manager', *arguments],
                              cwd=self.root, env=self.env, text=True, capture_output=True, timeout=5)

    def test_validate_json_has_summary_without_state_writes(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        result = self.invoke('validate', str(self.source), '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value['valid'])
        self.assertEqual(value['application'], 'not_implemented')
        self.assertEqual(value['counts']['resources'], 0)
        self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir()}, before)
        self.assertEqual(result.stderr, '')

    def test_validation_errors_do_not_echo_input_or_argument_values(self):
        sentinel = 'DO_NOT_PRINT_SECRET_SENTINEL'
        self.source.write_text('schema=1\ncomponents=[]\nresources=[]\n' + sentinel + '=true')
        for arguments in [('validate', str(self.source), '--json'),
                          ('validate', str(self.source), '--' + sentinel),
                          (sentinel,)]:
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(json.loads(result.stdout)['valid'])
                self.assertNotIn(sentinel, result.stdout + result.stderr)
                self.assertNotIn(str(self.source), result.stdout + result.stderr)

    def test_rejects_nonregular_and_oversized_inputs_without_blocking(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        link = self.root / 'link'
        link.symlink_to(self.source)
        huge = self.root / 'huge'
        with huge.open('wb') as stream:
            stream.truncate(MAX_DECLARATION_BYTES + 1)
        for path, code in [(fifo, 'declaration_not_regular_file'),
                           (self.root, 'declaration_not_regular_file'),
                           (link, 'declaration_unavailable'), (huge, 'declaration_too_large'),
                           (self.root / 'missing', 'declaration_unavailable')]:
            with self.subTest(path=path):
                result = self.invoke('validate', str(path), '--json')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stdout)['error']['code'], code)

    def test_parser_conversion_and_nesting_limits_use_fixed_public_errors(self):
        sentinel = 'DO_NOT_PRINT_PARSER_SENTINEL'
        for value in ('9' * 5000, '[' * 2000 + '1' + ']' * 2000):
            with self.subTest(kind='integer' if value[0] == '9' else 'array'):
                raw = ('schema=1\ncomponents=[]\nresources=[]\n' + sentinel + '=' + value).encode()
                self.assertLess(len(raw), MAX_DECLARATION_BYTES)
                self.source.write_bytes(raw)
                result = self.invoke('validate', str(self.source), '--json')
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout), {
                    'valid': False, 'error': {'code': 'invalid_toml', 'path': []}})
                self.assertEqual(result.stderr, '')
                self.assertNotIn(sentinel, result.stdout)
                self.assertNotIn(str(self.source), result.stdout)
                self.assertEqual(self.source.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
