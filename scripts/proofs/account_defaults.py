"""Use the bound shadow defaults instead of an unsupported login.defs key."""
import hashlib
from pathlib import Path
import stat

from core import Refused, read_regular
from run import command


# Member etc/default/useradd of the acquired shadow-4.20.0.arch1-1 archive
# SHA256 615c819eb2d3e22158289f3cc2447f81ae981a6d11b3418da30b6085306b3e77.
# That file declares CREATE_MAIL_SPOOL=no; -K cannot override this key.
DEFAULTS_SHA256 = 'b3056f0a7768f08b135f02bfbc6a88659f0c54cfbf3803f33a23d542b6b97f88'
ACCOUNTS = {'native': ('fixture-native', 1500, 1500, '/home/fixture-native', '/usr/bin/bash'),
            'external': ('fixture-external', 1501, 1501, '/home/fixture-external', '/usr/bin/bash'),
            'compose': ('compose', 963, 962, '/opt/docker', '/usr/bin/nologin')}


def require_mail_defaults():
    path = Path('/etc/default/useradd')
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused('fixture_useradd_defaults_parent_untrusted')
    raw, info = read_regular(path)
    if info[4] != 0 or info[6] & 0o022 or hashlib.sha256(raw).hexdigest() != DEFAULTS_SHA256:
        raise Refused('fixture_useradd_defaults_changed')
    if command(['/usr/bin/pacman', '-Q', 'shadow']).strip() != b'shadow 4.20.0.arch1-1':
        raise Refused('fixture_shadow_version_changed')


def useradd_arguments(role):
    if role not in ACCOUNTS:
        raise Refused('fixture_account_role_unsupported')
    require_mail_defaults()
    name, uid, gid, home, shell = ACCOUNTS[role]
    return ['/usr/bin/useradd', '--uid', str(uid), '--gid', str(gid), '--groups', 'media',
            '--create-home' if role != 'compose' else '--no-create-home',
            '--home-dir', home, '--shell', shell, '--no-user-group', name]
