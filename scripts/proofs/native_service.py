#!/usr/bin/env python3
"""Assemble/check fixed loopback SSH fixtures only in the bound disposable guest."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import resource
import secrets
import socket
import stat
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, private_directory, read_regular, require_guest, write_new
from native_manifest import SOURCE_SHA256, check_archive, trusted_json, validate_acquisition
from run import command, trusted_install
from compose_proof import covering_listeners
from service_environment import verified_environment_files


PUBLIC = Path('/etc/mpkg-fixture-ssh')
MANAGED_CONFIG = Path('/etc/ssh/sshd_config')
EXCLUSIVE = Path('/srv/mpkg-fixture/native-data')
SHARED = Path('/mnt/media/mpkg-fixture-shared')
EXTERNAL_UNIT = Path('/etc/systemd/system/mpkg-fixture-external.service')
MANAGED_DROPINS = Path('/etc/systemd/system/sshd.service.d')
PACKAGED_UNIT = Path('/usr/lib/systemd/system/sshd.service')
DROPIN = b'[Service]\nLimitCORE=0\n'
ROLES = {'native': ('fixture-native', 1500, 22222, 'sshd.service'),
         'external': ('fixture-external', 1501, 22223, EXTERNAL_UNIT.name)}


def state_root(guest):
    return Path('/var/lib/mpkg-proofs') / guest / 'native-service'


def trusted_path(path, directory=False):
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused('fixture_parent_not_trusted')
    info = path.lstat()
    if (info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode)
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))):
        raise Refused('fixture_path_not_trusted')
    return info


def parent_directory(path):
    if not path.exists():
        path.mkdir(mode=0o755)
        path.chmod(0o755)
    trusted_path(path, directory=True)


def identity(role):
    name, number, _, _ = ROLES[role]
    user = pwd.getpwnam(name)
    group = grp.getgrnam(name)
    memberships = sorted(os.getgrouplist(name, user.pw_gid))
    if (user.pw_uid != number or user.pw_gid != number or group.gr_gid != number
            or memberships != sorted([number, 1001])
            or grp.getgrnam('media').gr_gid != 1001):
        raise Refused('fixture_account_identity_drift')
    return {'name': name, 'uid': number, 'gid': number, 'groups': memberships}


def configuration(role, root):
    name, _, port, _ = ROLES[role]
    return ('\n'.join([
        'AddressFamily inet', 'ListenAddress 127.0.0.1', 'Port ' + str(port),
        'HostKey ' + str(root / (role + '-host')),
        'PidFile /run/mpkg-fixture-' + role + '.pid',
        'AuthorizedKeysFile ' + str(PUBLIC / (name + '.pub')),
        'AllowUsers ' + name, 'PermitRootLogin no', 'PubkeyAuthentication yes',
        'AuthenticationMethods publickey', 'PasswordAuthentication no',
        'KbdInteractiveAuthentication no', 'UsePAM yes', 'StrictModes yes',
        'DisableForwarding yes', 'PermitTTY no', 'PermitTunnel no',
        'ForceCommand internal-sftp', 'Subsystem sftp internal-sftp',
        'LogLevel ERROR', 'MaxAuthTries 2', 'LoginGraceTime 15', '',
    ])).encode()


def assert_effective(raw, role, root):
    pairs = [line.partition(' ') for line in raw.decode().splitlines()]
    effective = {}
    for key, separator, value in pairs:
        if separator:
            effective.setdefault(key, []).append(value)
    name, _, port, _ = ROLES[role]
    expected = {'port': str(port), 'addressfamily': 'inet',
                'listenaddress': '127.0.0.1:' + str(port),
                'hostkey': str(root / (role + '-host')),
                'authorizedkeysfile': str(PUBLIC / (name + '.pub')),
                'allowusers': name, 'permitrootlogin': 'no',
                'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
                'authenticationmethods': 'publickey', 'usepam': 'yes',
                'disableforwarding': 'yes', 'permittty': 'no',
                'forcecommand': 'internal-sftp'}
    if any(effective.get(key) != [value] for key, value in expected.items()):
        raise Refused('fixture_effective_configuration_mismatch')
    return expected


def public_key(path):
    raw, _ = read_regular(path)
    fields = raw.strip().split()
    if len(fields) != 3 or fields[0] != b'ssh-ed25519':
        raise Refused('fixture_public_key_shape')
    return b' '.join(fields[:2])


def no_listener():
    for source in ('/proc/net/tcp', '/proc/net/tcp6'):
        for line in Path(source).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A' and int(fields[1].split(':')[1], 16) in (22, 22222, 22223):
                raise Refused('fixture_ssh_port_already_in_use')


def service_properties(unit):
    raw = command(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,SubState,MainPID,UnitFileState,FragmentPath,DropInPaths,LimitCORE,ExecStart,Environment,EnvironmentFiles,PassEnvironment'])
    value = dict(line.split('=', 1) for line in raw.decode().splitlines())
    return verified_environment_files(unit, value)


def external_unit():
    return (
        '[Unit]\nDescription=Disposable unmanaged SFTP consumer\nAfter=network.target\n'
        '[Service]\nType=exec\nExecStart=/usr/bin/sshd -D -e -f ' + str(PUBLIC / 'external.conf') + '\n'
        'Restart=no\nKillMode=control-group\nLimitCORE=0\n'
        'StandardOutput=null\nStandardError=null\n'
        '[Install]\nWantedBy=multi-user.target\n').encode()


def assert_startup(manager, role):
    expected = '/usr/bin/sshd -D'
    if role == 'external':
        expected += ' -e -f ' + str(PUBLIC / 'external.conf')
    invocation = manager.get('ExecStart', '')
    dropins = str(MANAGED_DROPINS / '50-mpkg-fixture.conf') if role == 'native' else ''
    if (manager.get('DropInPaths') != dropins
            or any(manager.get(key) != '' for key in ('Environment', 'EnvironmentFiles', 'PassEnvironment'))
            or not invocation.startswith('{ path=/usr/bin/sshd ; argv[]=' + expected + ' ; ignore_errors=no ;')
            or invocation.count('{') != 1 or invocation.count('}') != 1):
        raise Refused('fixture_service_startup_drift')


def listener_identity(manager, port):
    pid = int(manager['MainPID'])
    process = Path('/proc') / str(pid)
    if os.readlink(process / 'exe') != '/usr/bin/sshd':
        raise Refused('fixture_service_process_mismatch')
    before = (process / 'stat').read_bytes()
    start = before.rsplit(b')', 1)[1].split()[19]
    inodes = covering_listeners(Path('/proc/net/tcp').read_text(), Path('/proc/net/tcp6').read_text(), port)
    owned = {os.readlink(path) for path in (process / 'fd').iterdir()}
    if not inodes or not inodes <= owned:
        raise Refused('fixture_service_listener_unattributed')
    return pid, start, inodes


def package_baseline():
    source, digest = trusted_json('source-inventory.json')
    if digest != SOURCE_SHA256:
        raise Refused('frozen_source_inventory_mismatch')
    planned = next(item for item in source['repository_packages'] if item['name'] == 'openssh')
    records, _ = trusted_json('native-acquisition.json')
    matches = [item for item in records if item['sha256'] == planned['package_sha256_published_in_database']]
    if len(matches) != 1:
        raise Refused('openssh_acquisition_required')
    record = matches[0]
    allowed = {item['url'] for item in source['repository_packages'] +
               source['native_update_target']['repository_packages']
               if item['name'] == 'openssh' and item['version'] == planned['version']
               and item['package_sha256_published_in_database'] == record['sha256']}
    validate_acquisition(record, planned, allowed)
    artifact = check_archive(record, 'repository')
    installed = command(['/usr/bin/pacman', '-Q', 'openssh']).decode().strip()
    if installed != 'openssh ' + planned['version']:
        raise Refused('openssh_installed_version_mismatch')
    baseline = command(['/usr/bin/bsdtar', '-xOf', artifact['path'], 'etc/ssh/sshd_config'])
    if not baseline or len(baseline) > 65536:
        raise Refused('openssh_package_configuration_shape')
    unit = command(['/usr/bin/bsdtar', '-xOf', artifact['path'], 'usr/lib/systemd/system/sshd.service'])
    trusted_path(PACKAGED_UNIT)
    if not unit or len(unit) > 65536 or read_regular(PACKAGED_UNIT)[0] != unit:
        raise Refused('openssh_package_unit_changed')
    return baseline, unit, planned['version']


def preflight(root):
    if (root.exists() or PUBLIC.exists() or EXTERNAL_UNIT.exists() or EXCLUSIVE.exists()
            or SHARED.exists() or MANAGED_DROPINS.exists()):
        raise Refused('fixture_setup_requires_fresh_paths')
    no_listener()
    service = service_properties('sshd.service')
    if (service.get('ActiveState') != 'inactive' or service.get('MainPID') != '0'
            or service.get('UnitFileState') not in ('disabled', 'static')
            or service.get('DropInPaths') or service.get('FragmentPath') != '/usr/lib/systemd/system/sshd.service'):
        raise Refused('fixture_requires_inactive_packaged_sshd')
    for name, number, _, _ in ROLES.values():
        for lookup, value in ((pwd.getpwnam, name), (pwd.getpwuid, number),
                              (grp.getgrnam, name), (grp.getgrgid, number)):
            try:
                lookup(value)
            except KeyError:
                continue
            raise Refused('fixture_account_collision')
        if Path('/home', name).exists():
            raise Refused('fixture_home_collision')
    for lookup, value in ((grp.getgrnam, 'media'), (grp.getgrgid, 1001)):
        try:
            group = lookup(value)
        except KeyError:
            continue
        if group.gr_name != 'media' or group.gr_gid != 1001:
            raise Refused('fixture_media_group_collision')
    trusted_path(MANAGED_CONFIG)
    baseline, unit, version = package_baseline()
    current, metadata = read_regular(MANAGED_CONFIG)
    if current != baseline:
        raise Refused('package_configuration_already_changed')
    return baseline, metadata, unit, version


def data_inventory(external_only=False):
    result = []
    paths = [(SHARED, 1500, 1001, 0o2770), (SHARED / 'sentinel', 1500, 1001, 0o640)]
    if not external_only:
        paths += [(EXCLUSIVE, 1500, 1500, 0o700), (EXCLUSIVE / 'sentinel', 1500, 1500, 0o600)]
    for path, uid, gid, mode in paths:
        info = path.lstat()
        if (info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode
                or stat.S_ISLNK(info.st_mode) or os.listxattr(path)):
            raise Refused('fixture_data_metadata_mismatch')
        result.append({'path': str(path), 'uid': uid, 'gid': gid, 'mode': oct(mode), 'xattrs': []})
    return result


def check(guest, external_only=False):
    root = state_root(guest)
    trusted_path(root, directory=True)
    manifest_raw, _ = read_regular(root / 'baseline.json')
    manifest = json.loads(manifest_raw)
    if manifest.get('guest_id') != guest:
        raise Refused('native_service_manifest_identity')
    directory = root / ('check-' + str(uuid.uuid4()))
    private_directory(directory)
    data = data_inventory(external_only)
    results = []
    for role in (('external',) if external_only else tuple(ROLES)):
        journal = Journal(root)
        try:
            for item in manifest['protected_keys'][role]:
                if not journal.unchanged(item['reference'], Path(item['path'])):
                    raise Refused('fixture_protected_key_drift')
        finally:
            journal.close()
        name, _, port, unit = ROLES[role]
        account = identity(role)
        config = MANAGED_CONFIG if role == 'native' else PUBLIC / 'external.conf'
        current, _ = read_regular(config)
        if current != configuration(role, root):
            raise Refused('fixture_service_configuration_drift')
        command(['/usr/bin/sshd', '-t', '-f', str(config)])
        effective = command(['/usr/bin/sshd', '-T', '-f', str(config)])
        assert_effective(effective, role, root)
        write_new(directory / (role + '-effective.conf'), effective)
        manager = service_properties(unit)
        if (manager.get('ActiveState') != 'active' or manager.get('SubState') != 'running'
                or manager.get('UnitFileState') != 'enabled' or int(manager.get('MainPID', '0')) <= 0
                or manager.get('LimitCORE') != '0'
                or manager.get('FragmentPath') != (str(EXTERNAL_UNIT) if role == 'external'
                                                  else '/usr/lib/systemd/system/sshd.service')):
            raise Refused('fixture_service_not_running_enabled')
        if role == 'native':
            if (read_regular(PACKAGED_UNIT)[0] != read_regular(root / 'packaged-sshd.service')[0]
                    or read_regular(MANAGED_DROPINS / '50-mpkg-fixture.conf')[0] != DROPIN):
                raise Refused('fixture_service_unit_drift')
        elif read_regular(EXTERNAL_UNIT)[0] != external_unit():
            raise Refused('fixture_service_unit_drift')
        assert_startup(manager, role)
        # Type=exec can precede listen(). This read-only readiness wait sends
        # no credential; authenticated SFTP itself is attempted exactly once.
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise Refused('fixture_listener_not_ready') from None
                time.sleep(0.1)
        attributed = listener_identity(manager, port)
        remote = EXCLUSIVE / 'sentinel' if role == 'native' else SHARED / 'sentinel'
        received = directory / (role + '-received')
        batch = directory / (role + '.batch')
        write_new(batch, ('get ' + str(remote) + ' ' + str(received) + '\n').encode())
        command(['/usr/bin/sftp', '-4', '-F', '/dev/null', '-S', '/usr/bin/ssh',
                 '-q', '-b', str(batch), '-i', str(root / (role + '-client')),
                 '-oBatchMode=yes', '-oIdentitiesOnly=yes', '-oStrictHostKeyChecking=yes',
                 '-oUserKnownHostsFile=' + str(root / (role + '-known-hosts')),
                 '-oGlobalKnownHostsFile=/dev/null', '-oProxyCommand=none', '-oProxyJump=none',
                 '-oConnectTimeout=5', '-P', str(port), name + '@127.0.0.1'], timeout=20)
        actual, _ = read_regular(received)
        expected = ('mpkg fixture ' + guest + ' ' + ('exclusive' if role == 'native' else 'shared') + '\n').encode()
        if actual != expected:
            raise Refused('fixture_authenticated_read_mismatch')
        after = service_properties(unit)
        assert_startup(after, role)
        if listener_identity(after, port) != attributed:
            raise Refused('fixture_service_changed_during_check')
        results.append({'role': role, 'account': account, 'unit': unit,
                        'manager': manager, 'authenticated_sftp_read': True,
                        'sentinel_sha256': hashlib.sha256(actual).hexdigest()})
    result = {'schema': 1, 'guest_id': guest, 'status': 'observed',
              'services': results, 'data': data,
              'limits': ['Fixture assembly/check only; not product application or acceptance.',
                         'External check proves separate-service shared-file read at this observation.']}
    write_new(directory / 'result.json', canonical(result) + b'\n')
    return result


def setup(guest):
    root = state_root(guest)
    baseline, metadata, packaged_unit, version = preflight(root)
    private_directory(root)
    journal = Journal(root)
    attempt = str(uuid.uuid4())
    journal.begin(attempt)
    try:
        write_new(root / 'packaged-sshd_config', baseline)
        write_new(root / 'packaged-sshd.service', packaged_unit)
        parent_directory(PUBLIC)
        parent_directory(Path('/srv/mpkg-fixture'))
        parent_directory(Path('/mnt/media'))
        try:
            grp.getgrnam('media')
        except KeyError:
            command(['/usr/bin/groupadd', '--gid', '1001', 'media'])
        for role, (name, number, port, _) in ROLES.items():
            command(['/usr/bin/groupadd', '--gid', str(number), name])
            command(['/usr/bin/useradd', '--uid', str(number), '--gid', str(number),
                     '--groups', 'media', '--create-home', '--home-dir', '/home/' + name,
                     '--shell', '/usr/bin/bash', '--no-user-group', '-K', 'CREATE_MAIL_SPOOL=no', name])
            # Unlock account with an unknown generated password; both servers
            # accept only public keys. Password bytes never enter argv or logs.
            command(['/usr/bin/chpasswd'], input_bytes=(name + ':' + secrets.token_hex(32) + '\n').encode())
            identity(role)
            for purpose in ('host', 'client'):
                command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                         '-C', 'mpkg-fixture', '-f', str(root / (role + '-' + purpose))])
            write_new(PUBLIC / (name + '.pub'), public_key(root / (role + '-client.pub')) + b'\n', 0o644)
            (PUBLIC / (name + '.pub')).chmod(0o644)
            write_new(root / (role + '-known-hosts'),
                      ('[127.0.0.1]:' + str(port) + ' ').encode() +
                      public_key(root / (role + '-host.pub')) + b'\n')
        for path, uid, gid, mode, label in [(EXCLUSIVE, 1500, 1500, 0o700, 'exclusive'),
                                            (SHARED, 1500, 1001, 0o2770, 'shared')]:
            path.mkdir(mode=0o700)
            os.chown(path, uid, gid)
            path.chmod(mode)
            sentinel = path / 'sentinel'
            write_new(sentinel, ('mpkg fixture ' + guest + ' ' + label + '\n').encode())
            os.chown(sentinel, uid, gid)
            sentinel.chmod(0o600 if label == 'exclusive' else 0o640)
        candidate = MANAGED_CONFIG.with_name('sshd_config.mpkg-fixture-new')
        write_new(candidate, configuration('native', root))
        command(['/usr/bin/sshd', '-t', '-f', str(candidate)])
        current, now = read_regular(MANAGED_CONFIG)
        if current != baseline or now != metadata:
            raise Refused('package_configuration_intervening_change')
        os.replace(candidate, MANAGED_CONFIG)
        parent_fd = os.open(MANAGED_CONFIG.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        write_new(PUBLIC / 'external.conf', configuration('external', root))
        command(['/usr/bin/sshd', '-t', '-f', str(PUBLIC / 'external.conf')])
        write_new(EXTERNAL_UNIT, external_unit(), 0o644)
        EXTERNAL_UNIT.chmod(0o644)
        parent_directory(MANAGED_DROPINS)
        write_new(MANAGED_DROPINS / '50-mpkg-fixture.conf', DROPIN, 0o644)
        (MANAGED_DROPINS / '50-mpkg-fixture.conf').chmod(0o644)
        manifest = {'schema': 1, 'guest_id': guest, 'openssh_version': version,
                    'package_config_sha256': hashlib.sha256(baseline).hexdigest(),
                    'intended_config_sha256': hashlib.sha256(configuration('native', root)).hexdigest(),
                    'protected_keys': {},
                    'independently_required_package': 'openssh'}
        for role, (name, _, _, _) in ROLES.items():
            paths = [root / (role + '-' + purpose) for purpose in ('host', 'client', 'known-hosts')]
            paths.append(PUBLIC / (name + '.pub'))
            manifest['protected_keys'][role] = [{'path': str(path), 'reference': journal.capture(path)}
                                                for path in paths]
        write_new(root / 'baseline.json', canonical(manifest) + b'\n')
        command(['/usr/bin/systemctl', 'daemon-reload'])
        for _, _, _, unit in ROLES.values():
            command(['/usr/bin/systemctl', 'enable', '--now', unit])
        result = check(guest)
        journal.finish(attempt, 'observed-complete')
        return result
    finally:
        journal.close()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'check', 'check-external'))
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    result = setup(guest) if args.action == 'setup' else check(guest, args.action == 'check-external')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error)}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'failed', 'code': 'native_service_setup_or_check_failed'}))
        sys.exit(74)
