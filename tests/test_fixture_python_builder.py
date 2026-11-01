"""Host-safe checks for the guest builder's refusal/publication boundaries."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/fixture/guest-python-build.sh'


class PythonBuilderBoundaryTests(unittest.TestCase):
    def test_real_entrypoint_refuses_unbound_host(self):
        result = subprocess.run(['/usr/bin/bash', str(SCRIPT)],
                                env={'PATH': '/usr/bin:/bin'},
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('MPKG_PYTHON_REFUSED=', result.stderr)

    def check_tree(self, stage, listing):
        return subprocess.run([
            '/usr/bin/bash', '-c', 'source "$1"; stage_guard "$2" "$3"',
            'fixture-test', str(SCRIPT), str(stage), str(listing),
        ], capture_output=True, text=True, timeout=5)

    def test_publication_accepts_empty_files_and_internal_links(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stage = base / 'stage'
            stage.mkdir(mode=0o755)
            (stage / 'empty.py').touch(mode=0o644)
            (stage / 'module.py').write_text('value = 1\n')
            (stage / 'module.py').chmod(0o644)
            (stage / 'alias.py').symlink_to('module.py')
            result = self.check_tree(stage, base / 'paths')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_publication_refuses_escaping_links_and_privileged_files(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stage = base / 'stage'
            stage.mkdir(mode=0o755)
            (base / 'outside').write_text('outside')
            (stage / 'escape').symlink_to('../outside')
            result = self.check_tree(stage, base / 'paths')
            self.assertIn('stage_link_escape', result.stderr)
            (stage / 'escape').unlink()
            executable = stage / 'program'
            executable.write_text('placeholder')
            executable.chmod(0o4755)
            result = self.check_tree(stage, base / 'paths')
            self.assertIn('stage_mode', result.stderr)

    def test_publication_refuses_hardlinks_and_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stage = base / 'stage'
            stage.mkdir(mode=0o755)
            (stage / 'one').write_text('same inode')
            os.link(stage / 'one', stage / 'two')
            result = self.check_tree(stage, base / 'paths')
            self.assertIn('stage_hardlink', result.stderr)
            (stage / 'two').unlink()
            (base / 'alias').symlink_to(stage, target_is_directory=True)
            nested = stage / 'nested'
            nested.mkdir(mode=0o755)
            result = self.check_tree(base / 'alias/nested', base / 'paths')
            self.assertIn('stage_parent_link', result.stderr)


if __name__ == '__main__':
    unittest.main()
