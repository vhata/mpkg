#!/usr/bin/env python3
"""Start the fixed packaged Docker service only in a fresh bound guest."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import resource
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, private_directory, read_regular, require_guest, write_new
from experiments import fresh
from native_manifest import SOURCE_SHA256, check_archive, trusted_json, validate_acquisition
from native_service import parent_directory, trusted_path
from run import ENV, command, trusted_install


UNITS = {'docker.service': ('docker', '/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock'),
         'docker.socket': ('docker', None),
         'containerd.service': ('containerd', '/usr/bin/containerd')}
DROPIN = b'[Service]\nLimitCORE=0\n'
CONFIGURATION = ('/etc/docker/daemon.json', '/etc/containerd/config.toml')
PROPERTIES = ('LoadState,ActiveState,SubState,MainPID,UnitFileState,FragmentPath,DropInPaths,'
              'ExecStart,Environment,EnvironmentFiles,PassEnvironment,LimitCORE,Listen,SocketMode,SocketUser,SocketGroup')


def properties(unit):
    raw = command(['/usr/bin/systemctl', 'show', unit, '--property=' + PROPERTIES])
    return dict(line.split('=', 1) for line in raw.decode().splitlines())


def assert_unit(unit, value, started=False):
    package, executable = UNITS[unit]
    expected_dropin = '/etc/systemd/system/' + unit + '.d/50-mpkg-fixture.conf' if started and executable else ''
    if (value.get('LoadState') != 'loaded'
            or value.get('FragmentPath') != '/usr/lib/systemd/system/' + unit
            or value.get('DropInPaths') != expected_dropin
            or value.get('UnitFileState') != 'disabled'):
        raise Refused('docker_unit_definition_mismatch')
    if executable:
        execution = value.get('ExecStart', '')
        prefix = '{ path=' + executable.split()[0] + ' ; argv[]=' + executable + ' ; ignore_errors=no ;'
        if (not execution.startswith(prefix) or execution.count('{') != 1 or execution.count('}') != 1
                or any(value.get(key) != '' for key in ('Environment', 'EnvironmentFiles', 'PassEnvironment'))
                or (started and value.get('LimitCORE') != '0')):
            raise Refused('docker_unit_startup_mismatch')
    elif (value.get('Listen') != '/run/docker.sock (Stream)'
          or value.get('SocketMode') != '0660' or value.get('SocketUser') != 'root'
          or value.get('SocketGroup') != 'docker'):
        raise Refused('docker_socket_definition_mismatch')
    if started:
        expected = 'running' if executable else 'listening'
        if (value.get('ActiveState') != 'active' or value.get('SubState') != expected
                or (executable and int(value.get('MainPID', '0')) <= 0)):
            raise Refused('docker_unit_not_ready')
    elif value.get('ActiveState') != 'inactive' or value.get('MainPID', '0') != '0':
        raise Refused('docker_requires_inactive_baseline')


def check_absent_configuration():
    for name in CONFIGURATION:
        path = Path(name)
        if path.exists() or path.is_symlink():
            raise Refused('docker_configuration_not_fresh')
        if path.parent.exists():
            trusted_path(path.parent, directory=True)


def check_empty_directory(path):
    if path.exists() or path.is_symlink():
        trusted_path(path, directory=True)
        with os.scandir(path) as entries:
            if next(entries, None) is not None:
                raise Refused('docker_data_baseline_not_empty')
    else:
        trusted_path(path.parent, directory=True)


def package_units():
    source, digest = trusted_json('source-inventory.json')
    if digest != SOURCE_SHA256:
        raise Refused('frozen_source_inventory_mismatch')
    records, _ = trusted_json('native-acquisition.json')
    result = {}
    for package in ('docker', 'containerd'):
        planned = next(item for item in source['repository_packages'] if item['name'] == package)
        matches = [item for item in records if item['sha256'] == planned['package_sha256_published_in_database']]
        if len(matches) != 1:
            raise Refused('docker_package_acquisition_required')
        record = matches[0]
        allowed = {item['url'] for item in source['repository_packages'] + source['native_update_target']['repository_packages']
                   if item['name'] == package and item['version'] == planned['version']
                   and item['package_sha256_published_in_database'] == record['sha256']}
        validate_acquisition(record, planned, allowed)
        artifact = check_archive(record, 'repository')
        if command(['/usr/bin/pacman', '-Q', package]).decode().strip() != package + ' ' + planned['version']:
            raise Refused('docker_installed_version_mismatch')
        for unit, (owner, _) in UNITS.items():
            if owner != package:
                continue
            member = 'usr/lib/systemd/system/' + unit
            raw = command(['/usr/bin/bsdtar', '-xOf', artifact['path'], member])
            path = Path('/') / member
            trusted_path(path)
            if not raw or len(raw) > 65536 or read_regular(path)[0] != raw:
                raise Refused('docker_packaged_unit_changed')
            result[unit] = {'package': package, 'version': planned['version'],
                            'archive_sha256': record['sha256'],
                            'unit_sha256': hashlib.sha256(raw).hexdigest()}
    return result


def preflight():
    check_absent_configuration()
    for name in ('/var/lib/docker', '/var/lib/containerd', '/run/docker', '/run/containerd'):
        check_empty_directory(Path(name))
    for name in ('/run/docker.sock', '/run/containerd/containerd.sock', '/run/docker.pid'):
        path = Path(name)
        if path.exists() or path.is_symlink():
            raise Refused('docker_socket_or_process_state_exists')
    group = grp.getgrnam('docker')
    if group.gr_mem or any(user.pw_gid == group.gr_gid for user in pwd.getpwall()):
        raise Refused('docker_group_not_empty')
    evidence = package_units()
    for unit in UNITS:
        path = Path('/etc/systemd/system') / (unit + '.d')
        if path.exists() or path.is_symlink():
            raise Refused('docker_dropin_already_exists')
        assert_unit(unit, properties(unit))
    return evidence, group.gr_gid


def process_identity(value, executable):
    pid = int(value['MainPID'])
    process = Path('/proc') / str(pid)
    if os.readlink(process / 'exe') != executable:
        raise Refused('docker_process_executable_mismatch')
    commandline = (process / 'cmdline').read_bytes()
    expected = UNITS['docker.service' if executable.endswith('/dockerd') else 'containerd.service'][1]
    if commandline.rstrip(b'\0').split(b'\0') != [word.encode() for word in expected.split()]:
        raise Refused('docker_process_arguments_mismatch')
    start = (process / 'stat').read_bytes().rsplit(b')', 1)[1].split()[19].decode()
    return {'pid': pid, 'start_ticks': start, 'executable': executable}


def socket_identity(group, docker_process):
    info = Path('/run/docker.sock').lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != group
            or stat.S_IMODE(info.st_mode) != 0o660):
        raise Refused('docker_local_socket_identity')
    rows = [line.split() for line in Path('/proc/net/unix').read_text().splitlines()[1:]]
    listeners = {row[6] for row in rows if len(row) == 8 and row[7] == '/run/docker.sock'
                 and row[3] == '00010000' and row[4] == '0001'}
    owned = {os.readlink(path) for path in Path('/proc', str(docker_process['pid']), 'fd').iterdir()}
    if len(listeners) != 1 or not {'socket:[' + number + ']' for number in listeners} <= owned:
        raise Refused('docker_local_socket_unattributed')
    # The packaged daemon accepts only its systemd-provided Unix socket.
    # Refuse any TCP listener owned by it, including an unexpected metrics API.
    for name in ('/proc/net/tcp', '/proc/net/tcp6'):
        for line in Path(name).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A' and 'socket:[' + fields[9] + ']' in owned:
                raise Refused('docker_unexpected_tcp_listener')
    return {'device': info.st_dev, 'inode': info.st_ino, 'group': group,
            'kernel_socket_inode': next(iter(listeners))}


def validate_engine(value):
    engine = value.get('ID')
    if (not isinstance(engine, str) or not engine or len(engine) > 256
            or value.get('ServerVersion') != '29.9.2'
            or value.get('OSType') != 'linux' or value.get('Architecture') != 'x86_64'
            or value.get('DockerRootDir') != '/var/lib/docker'
            or value.get('Containers') != 0 or value.get('Images') != 0
            or value.get('Swarm', {}).get('LocalNodeState') != 'inactive'):
        raise Refused('docker_engine_baseline_mismatch')
    return engine


def ready(guest):
    provenance, group = preflight()
    root = private_directory(Path('/var/lib/mpkg-proofs') / guest)
    directory = fresh(root, 'docker-readiness')
    client = private_directory(directory / 'docker-client')
    environment = dict(ENV, DOCKER_CONFIG=str(client))
    journal = Journal(directory)
    attempt = str(uuid.uuid4())
    journal.begin(attempt)
    try:
        for unit in ('docker.service', 'containerd.service'):
            dropins = Path('/etc/systemd/system') / (unit + '.d')
            parent_directory(dropins)
            path = dropins / '50-mpkg-fixture.conf'
            write_new(path, DROPIN, 0o644)
            path.chmod(0o644)
        command(['/usr/bin/systemctl', 'daemon-reload'])
        # The one fixed mutation starts the packaged dependencies as declared.
        # A caller timeout leaves this attempt unresolved; no retry/stop follows.
        command(['/usr/bin/systemctl', 'start', 'docker.service'], timeout=90)
        units = {unit: properties(unit) for unit in UNITS}
        for unit, value in units.items():
            assert_unit(unit, value, started=True)
            path = Path('/usr/lib/systemd/system') / unit
            if hashlib.sha256(read_regular(path)[0]).hexdigest() != provenance[unit]['unit_sha256']:
                raise Refused('docker_unit_changed_during_start')
            if UNITS[unit][1] and read_regular(Path('/etc/systemd/system') / (unit + '.d') / '50-mpkg-fixture.conf')[0] != DROPIN:
                raise Refused('docker_dropin_changed_during_start')
        check_absent_configuration()
        processes = {unit: process_identity(units[unit], UNITS[unit][1].split()[0])
                     for unit in ('docker.service', 'containerd.service')}
        socket = socket_identity(group, processes['docker.service'])
        def docker(*arguments):
            return command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments], env=environment)
        value = json.loads(docker('info', '--format', '{{json .}}'))
        engine = validate_engine(value)
        if (docker('container', 'ls', '--all', '--quiet').strip()
                or docker('image', 'ls', '--all', '--quiet').strip()
                or docker('volume', 'ls', '--quiet').strip()):
            raise Refused('docker_engine_objects_not_empty')
        if docker('info', '--format', '{{.ID}}').decode().strip() != engine:
            raise Refused('docker_engine_identity_changed')
        for unit, original in processes.items():
            value = properties(unit)
            assert_unit(unit, value, started=True)
            if process_identity(value, original['executable']) != original:
                raise Refused('docker_process_changed_during_check')
        if socket_identity(group, processes['docker.service']) != socket:
            raise Refused('docker_socket_changed_during_check')
        result = {'schema': 1, 'guest_id': guest, 'status': 'observed',
                  'engine_id': engine, 'server_version': '29.9.2', 'platform': 'linux/x86_64',
                  'socket': socket, 'processes': processes, 'packages_and_units': provenance,
                  'containers': 0, 'images': 0, 'volumes': 0, 'enabled_services': False,
                  'product_acceptance': False,
                  'limits': ['Fixed guest daemon startup initializes engine, storage and default network state.',
                             'No pull, build, image import or container lifecycle was requested.',
                             'Image-store compatibility and digest associations remain unverified.']}
        write_new(directory / 'result.json', canonical(result) + b'\n')
        journal.finish(attempt, 'observed-complete')
        return result
    finally:
        journal.close()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    print(json.dumps(ready(guest), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'docker_readiness_failed', 'product_acceptance': False}))
        sys.exit(74)
