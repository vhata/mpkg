"""Stage the Vim package without pacman, privilege changes, or live files."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'packages' / 'viminumrc'
SHELL_ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}


class VimPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        startup = Path(temporary.name) / 'shell-startup'
        startup.write_text('printf "unexpected shell startup\\n"\nexit 42\n')
        environment = patch.dict(os.environ, {'BASH_ENV': str(startup), 'ENV': str(startup)})
        environment.start()
        self.addCleanup(environment.stop)

    def test_payload_package_is_outside_metapackage_discovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copy2(ROOT / 'mpkg', root / 'mpkg')
            for name in ('vhata-fixture', 'packages/viminumrc'):
                package = root / name
                package.mkdir(parents=True)
                (package / 'PKGBUILD').write_text('pkgname=fixture\n')
            packages = subprocess.check_output([str(root / 'mpkg'), '--list'], text=True)
        self.assertEqual(packages.splitlines(), ['vhata-fixture'])

    def metadata(self, name):
        output = subprocess.check_output([
            'bash', '-c',
            'source "$1"; declare -n values="$2"; printf "%s\\0" "${values[@]}"',
            'metadata', str(PACKAGE / 'PKGBUILD'), name,
        ], env=SHELL_ENV)
        return output.decode().removesuffix('\0').split('\0')

    def test_payload_checksums_permissions_and_backup_paths(self):
        sources = self.metadata('source')
        checksums = self.metadata('sha256sums')
        self.assertEqual(len(sources), len(checksums))
        self.assertIn('vim', self.metadata('depends'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            srcdir = root / 'src'
            pkgdir = root / 'pkg'
            srcdir.mkdir()
            pkgdir.mkdir()
            for source, checksum in zip(sources, checksums):
                self.assertEqual(
                    hashlib.sha256((PACKAGE / source).read_bytes()).hexdigest(),
                    checksum, source,
                )
                shutil.copyfile(PACKAGE / source, srcdir / source)
            subprocess.run([
                'bash', '-euc',
                'source "$1"; srcdir=$2; pkgdir=$3; umask 0022; package',
                'stage', str(PACKAGE / 'PKGBUILD'), str(srcdir), str(pkgdir),
            ], cwd=root, env=SHELL_ENV, check=True)
            expected = {
                'usr/local/etc/vimrc/vimrc': 'vimrc',
                'usr/local/etc/vimrc/README.md': 'README.vimrc',
                'usr/local/etc/vimrc/bundle/surround.vim': 'surround.vim',
                'usr/local/etc/vimrc/bundle/autoload/repeat.vim': 'repeat.vim',
                'usr/local/etc/vimrc/bundle/README.md': 'bundle-README.md',
                'usr/local/etc/vimrc/bundle/LICENSE.txt': 'LICENSE.txt',
                'etc/profile.d/viminumrc.sh': 'viminumrc.sh',
            }
            self.assertEqual(
                {str(path.relative_to(pkgdir)) for path in pkgdir.rglob('*')
                 if not path.is_dir()}, set(expected),
            )
            for destination, source in expected.items():
                path = pkgdir / destination
                self.assertFalse(path.is_symlink(), destination)
                self.assertEqual(path.read_bytes(), (srcdir / source).read_bytes())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            readme = pkgdir / 'usr/local/etc/vimrc/README.md'
            for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', readme.read_text()):
                if '://' not in target:
                    self.assertTrue((readme.parent / target).is_file(), target)
            self.assertEqual(set(self.metadata('backup')), {
                'usr/local/etc/vimrc/vimrc', 'etc/profile.d/viminumrc.sh',
            })

    def test_profile_exports_shared_config_to_child_processes(self):
        for previous in (None, 'source /some/other/vimrc'):
            with self.subTest(previous=previous):
                env = dict(SHELL_ENV)
                if previous is not None:
                    env['VIMINIT'] = previous
                output = subprocess.check_output([
                    'sh', '-eu', '-c',
                    '. "$1"; exec sh -c \'printf "%s" "$VIMINIT"\'',
                    'profile', str(PACKAGE / 'viminumrc.sh'),
                ], env=env, text=True)
                self.assertEqual(output, 'source /usr/local/etc/vimrc/vimrc')


if __name__ == '__main__':
    unittest.main()
