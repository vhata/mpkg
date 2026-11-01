#!/usr/bin/env python3
"""Continue only the observed one-group SSH fixture setup failure."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import resource
import secrets
import sqlite3
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_service as native
from account_defaults import require_mail_defaults, useradd_arguments
from core import Journal, Refused, canonical, private_directory, read_regular, require_guest, write_new
from run import command, trusted_install


INSTALLED_NATIVE_SHA256 = '645822526f899506a9f0b6e13c27945003b111ed6d9b065e1df992095acf5961'


def absent(path):
    if path.exists() or path.is_symlink():
        raise Refused('native_recovery_unexpected_path')


def empty_parent(path):
    info = native.trusted_path(path, directory=True)
    if info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o755:
        raise Refused('native_recovery_parent_metadata')
    with os.scandir(path) as entries:
        if next(entries, None) is not None:
            raise Refused('native_recovery_parent_not_empty')


def partial_accounts():
    groups = grp.getgrall()
    for name, gid in (('fixture-native', 1500), ('media', 1001)):
        matches = [group for group in groups if group.gr_name == name or group.gr_gid == gid]
        if len(matches) != 1 or matches[0].gr_name != name or matches[0].gr_gid != gid or matches[0].gr_mem:
            raise Refused('native_recovery_group_state_changed')
    if any(group.gr_name == 'fixture-external' or group.gr_gid == 1501 for group in groups):
        raise Refused('native_recovery_external_group_exists')
    if any(user.pw_name in ('fixture-native', 'fixture-external') or user.pw_uid in (1500, 1501)
           or user.pw_gid in (1001, 1500, 1501) for user in pwd.getpwall()):
        raise Refused('native_recovery_account_state_changed')
    for name in ('fixture-native', 'fixture-external'):
        absent(Path('/home') / name)
        absent(Path('/var/spool/mail') / name)


def original_attempt(root):
    info = native.trusted_path(root, directory=True)
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused('native_recovery_state_permissions')
    names = set()
    with os.scandir(root) as entries:
        for entry in entries:
            names.add(entry.name)
            if len(names) > 3:
                raise Refused('native_recovery_not_exact_partial_stage')
    if names != {'state.sqlite3', 'packaged-sshd_config', 'packaged-sshd.service'}:
        raise Refused('native_recovery_not_exact_partial_stage')
    database = root / 'state.sqlite3'
    info = native.trusted_path(database)
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise Refused('native_recovery_journal_permissions')
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON')
        attempts = connection.execute('SELECT id,terminal FROM attempts').fetchall()
        if (len(attempts) != 1 or attempts[0][1] is not None
                or connection.execute('SELECT attempt,kind FROM events ORDER BY seq').fetchall() != [(attempts[0][0], 'started')]
                or connection.execute('SELECT COUNT(*) FROM protected').fetchone() != (0,)
                or connection.execute('SELECT recovery_required FROM store_guard').fetchall() != [(0,)]):
            raise Refused('native_recovery_original_attempt_changed')
        attempt = str(uuid.UUID(attempts[0][0]))
        if attempt != attempts[0][0]:
            raise Refused('native_recovery_original_identity_changed')
    finally:
        connection.close()
    return attempt, read_regular(database)[0]


def preflight(guest):
    installed = Path(native.__file__).resolve()
    if installed != Path('/opt/mpkg-proofs/native_service.py') or hashlib.sha256(read_regular(installed)[0]).hexdigest() != INSTALLED_NATIVE_SHA256:
        raise Refused('native_recovery_installed_source_changed')
    require_mail_defaults()
    root = native.state_root(guest)
    attempt, database = original_attempt(root)
    absent(root.parent / 'native-service-recovery')
    for path in (native.EXCLUSIVE, native.SHARED, native.EXTERNAL_UNIT, native.MANAGED_DROPINS,
                 native.MANAGED_CONFIG.with_name('sshd_config.mpkg-fixture-new'),
                 Path('/run/mpkg-fixture-native.pid'), Path('/run/mpkg-fixture-external.pid')):
        absent(path)
    for path in (native.PUBLIC, Path('/srv/mpkg-fixture'), Path('/mnt/media')):
        empty_parent(path)
    partial_accounts()
    native.no_listener()
    manager = native.service_properties('sshd.service')
    if (manager.get('ActiveState') != 'inactive' or manager.get('SubState') != 'dead'
            or manager.get('MainPID') != '0' or manager.get('UnitFileState') != 'disabled'
            or manager.get('DropInPaths') != '' or manager.get('FragmentPath') != str(native.PACKAGED_UNIT)):
        raise Refused('native_recovery_service_not_quiescent')
    baseline, packaged_unit, version = native.package_baseline()
    native.trusted_path(native.MANAGED_CONFIG)
    current, metadata = read_regular(native.MANAGED_CONFIG)
    for name in ('packaged-sshd_config', 'packaged-sshd.service'):
        native.trusted_path(root / name)
    if (current != baseline or read_regular(root / 'packaged-sshd_config')[0] != baseline
            or read_regular(root / 'packaged-sshd.service')[0] != packaged_unit):
        raise Refused('native_recovery_package_evidence_changed')
    return root, attempt, database, baseline, metadata, version


def continue_setup(guest, root, baseline, metadata, version, protected):
    # The exact existing native group is the sole accepted partial effect.
    # It is neither removed nor created again; all later effects are fresh.
    for role, (name, number, port, _) in native.ROLES.items():
        if role == 'external':
            command(['/usr/bin/groupadd', '--gid', str(number), name])
        command(useradd_arguments(role))
        command(['/usr/bin/chpasswd'], input_bytes=(name + ':' + secrets.token_hex(32) + '\n').encode())
        native.identity(role)
        for purpose in ('host', 'client'):
            command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                     '-C', 'mpkg-fixture', '-f', str(root / (role + '-' + purpose))])
        path = native.PUBLIC / (name + '.pub')
        write_new(path, native.public_key(root / (role + '-client.pub')) + b'\n', 0o644)
        path.chmod(0o644)
        write_new(root / (role + '-known-hosts'), ('[127.0.0.1]:' + str(port) + ' ').encode() +
                  native.public_key(root / (role + '-host.pub')) + b'\n')
    for path, uid, gid, mode, label in [(native.EXCLUSIVE, 1500, 1500, 0o700, 'exclusive'),
                                        (native.SHARED, 1500, 1001, 0o2770, 'shared')]:
        path.mkdir(mode=0o700)
        os.chown(path, uid, gid)
        path.chmod(mode)
        sentinel = path / 'sentinel'
        write_new(sentinel, ('mpkg fixture ' + guest + ' ' + label + '\n').encode())
        os.chown(sentinel, uid, gid)
        sentinel.chmod(0o600 if label == 'exclusive' else 0o640)
    candidate = native.MANAGED_CONFIG.with_name('sshd_config.mpkg-fixture-new')
    write_new(candidate, native.configuration('native', root))
    command(['/usr/bin/sshd', '-t', '-f', str(candidate)])
    current, now = read_regular(native.MANAGED_CONFIG)
    if current != baseline or now != metadata:
        raise Refused('native_recovery_package_configuration_changed')
    os.replace(candidate, native.MANAGED_CONFIG)
    descriptor = os.open(native.MANAGED_CONFIG.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    write_new(native.PUBLIC / 'external.conf', native.configuration('external', root))
    command(['/usr/bin/sshd', '-t', '-f', str(native.PUBLIC / 'external.conf')])
    write_new(native.EXTERNAL_UNIT, native.external_unit(), 0o644)
    native.EXTERNAL_UNIT.chmod(0o644)
    native.parent_directory(native.MANAGED_DROPINS)
    path = native.MANAGED_DROPINS / '50-mpkg-fixture.conf'
    write_new(path, native.DROPIN, 0o644)
    path.chmod(0o644)
    manifest = {'schema': 1, 'guest_id': guest, 'openssh_version': version,
                'package_config_sha256': hashlib.sha256(baseline).hexdigest(),
                'intended_config_sha256': hashlib.sha256(native.configuration('native', root)).hexdigest(),
                'protected_keys': {}, 'independently_required_package': 'openssh',
                'assembly_continuation': 'native-service-recovery'}
    for role, (name, _, _, _) in native.ROLES.items():
        paths = [root / (role + '-' + purpose) for purpose in ('host', 'client', 'known-hosts')]
        paths.append(native.PUBLIC / (name + '.pub'))
        manifest['protected_keys'][role] = [{'path': str(path), 'reference': protected.capture(path)} for path in paths]
    write_new(root / 'baseline.json', canonical(manifest) + b'\n')
    command(['/usr/bin/systemctl', 'daemon-reload'])
    for _, _, _, unit in native.ROLES.values():
        command(['/usr/bin/systemctl', 'enable', '--now', unit])
    return native.check(guest)


def recover(guest):
    root, original, database, baseline, metadata, version = preflight(guest)
    recovery = root.parent / 'native-service-recovery'
    try:
        recovery.mkdir(mode=0o700)
    except FileExistsError:
        raise Refused('native_recovery_fresh_attempt_required') from None
    descriptor = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    private_directory(recovery)
    write_new(recovery / 'original-state.sqlite3', database)
    write_new(recovery / 'scope.json', canonical({'schema': 1, 'guest_id': guest,
              'original_unknown_attempt': original, 'reused_native_group': 1500,
              'installed_native_sha256': INSTALLED_NATIVE_SHA256,
              'correction': 'Use verified packaged mail defaults instead of unsupported -K key.'}) + b'\n')
    journal = Journal(recovery)
    protected = Journal(root)
    try:
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        result = continue_setup(guest, root, baseline, metadata, version, protected)
        # Do not mark the interrupted original attempt complete. Its private
        # before-copy and unknown event remain separate from this continuation.
        if protected.db.execute('SELECT terminal FROM attempts WHERE id=?', (original,)).fetchone() != (None,):
            raise Refused('native_recovery_original_history_changed')
        result['original_attempt_remains_unknown'] = True
        result['recovery_attempt'] = attempt
        result['product_acceptance'] = False
        write_new(recovery / 'result.json', canonical(result) + b'\n')
        journal.finish(attempt, 'observed-complete')
        return result
    finally:
        protected.close()
        journal.close()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    print(json.dumps(recover(guest), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'native_service_recovery_failed', 'product_acceptance': False}))
        sys.exit(74)
