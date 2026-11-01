#!/usr/bin/env python3
"""Observe the fixed gitstatus build and export without changing guest state."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, identity, read_regular, require_guest
from native_manifest import SOURCE_SHA256, validate_build
from native_service import trusted_path
from run import ENV, command, trusted_install

STATE = Path('/var/lib/mpkg-fixture/aur-gitstatus')
INPUTS = Path('/opt/mpkg-proof-inputs')
OUTPUT = Path('/run/mpkg-build-output')
UNIT = 'mpkg-fixture-aur-gitstatus.service'
DEPENDENCIES = {'cmake', 'cppdap', 'hicolor-icon-theme', 'jsoncpp', 'libuv', 'rhash', 'zsh'}
WORKER_SHA256 = '3d9f248e83939bb2236098acfe2dafd6f3c4c29e1946d3f25cca88ea1138c45c'


def small(path, maximum=65536):
    trusted_path(path)
    info = path.stat()
    if info.st_size > maximum:
        raise Refused('gitstatus_diagnostic_file_bound')
    raw, _ = read_regular(path)
    return raw


def expected_inventory(source):
    names = set(source['resolutions']['native_change']['resolved_package_names']) | DEPENDENCIES
    expected = {item['name']: item['version'] for item in source['repository_packages'] if item['name'] in names}
    expected.update({item['package_base']: item['srcinfo_version'] for item in source['aur_packages']
                     if item['package_base'] in {'ack', 'perl-file-next'}})
    if len(expected) != 216 or not DEPENDENCIES <= expected.keys() or 'gitstatus' in expected:
        raise Refused('gitstatus_diagnostic_expected_scope')
    return expected


def artifact_digest(path, artifact):
    trusted_path(path)
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (before.st_size != artifact['size'] or not 0 < before.st_size <= 64*1024**2
                or before.st_uid != 0 or before.st_gid != 0 or before.st_mode & 0o022):
            raise Refused('gitstatus_diagnostic_artifact_shape')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != artifact['sha256'] or identity(before) != identity(os.fstat(stream.fileno())):
            raise Refused('gitstatus_diagnostic_artifact_changed')
    return {'sha256': digest, 'bytes': before.st_size}


def process_observations():
    cgroup = Path('/sys/fs/cgroup/system.slice')/UNIT
    group = {'present': cgroup.exists(), 'pids': [], 'events': {}}
    if group['present']:
        with (cgroup/'cgroup.procs').open() as stream:
            raw = stream.read(4097)
        if len(raw) > 4096 or any(not pid.isdecimal() for pid in raw.splitlines()):
            raise Refused('gitstatus_diagnostic_cgroup_bound')
        group['pids'] = [int(pid) for pid in raw.splitlines()]
        with (cgroup/'cgroup.events').open() as stream:
            raw = stream.read(1025)
        if len(raw) > 1024:
            raise Refused('gitstatus_diagnostic_cgroup_events_bound')
        group['events'] = dict(line.split() for line in raw.splitlines())
    builders = []
    processes = list(Path('/proc').iterdir())
    if len(processes) > 8192:
        raise Refused('gitstatus_diagnostic_process_bound')
    for path in processes:
        if not path.name.isdecimal():
            continue
        try:
            if path.stat().st_uid != 1502:
                continue
            with (path/'comm').open() as stream:
                comm = stream.read(65).strip()
            builders.append({'pid': int(path.name), 'comm': comm})
        except (FileNotFoundError, ProcessLookupError):
            continue
    if len(builders) > 64:
        raise Refused('gitstatus_diagnostic_builder_bound')
    return group, builders


def complete(manager, group, builders, markers, guest, inventory_matches, exported):
    return (manager.get('ActiveState') == 'inactive' and manager.get('SubState') == 'dead'
            and manager.get('Result') == 'success' and manager.get('ExecMainStatus') == '0'
            and manager.get('MainPID') == '0' and manager.get('ControlPID') == '0'
            and not group['pids'] and (not group['present'] or group['events'].get('populated') == '0')
            and not builders and markers == {'started': guest, 'complete': guest, 'exit': '0'}
            and inventory_matches and exported)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    trusted_install()
    source_raw = small(INPUTS/'source-inventory.json', 1048576)
    if hashlib.sha256(source_raw).hexdigest() != SOURCE_SHA256:
        raise Refused('gitstatus_diagnostic_source_changed')
    source = json.loads(source_raw)
    worker_hash = hashlib.sha256(small(Path('/opt/mpkg-fixture/guest_aur.py'))).hexdigest()
    if worker_hash != WORKER_SHA256:
        raise Refused('gitstatus_diagnostic_worker_changed')
    raw = command(['/usr/bin/systemctl', '--no-pager', '--plain', 'show', UNIT,
                   '--property=ActiveState,SubState,Result,ExecMainStatus,MainPID,ControlPID,ControlGroup,TasksCurrent'])
    manager = dict(line.split('=', 1) for line in raw.decode().splitlines())
    if manager.get('ControlGroup') not in ('', '/system.slice/'+UNIT):
        raise Refused('gitstatus_diagnostic_unexpected_cgroup')
    group, builders = process_observations()
    markers = {name: small(STATE/name, 128).decode().strip() if (STATE/name).exists() else 'absent'
               for name in ('started', 'exit', 'complete')}
    inventory_raw = command(['/usr/bin/pacman', '-Q'])
    inventory = dict(line.split() for line in inventory_raw.decode().splitlines())
    expected = expected_inventory(source)
    explicit_raw = command(['/usr/bin/pacman', '-Qqe'])
    explicit = set(explicit_raw.decode().splitlines())
    build = {'present': False}
    export = {'present': False}
    record_path = INPUTS/'gitstatus-build.json'
    if record_path.exists():
        record_raw = small(record_path)
        record = json.loads(record_raw)
        artifact = validate_build(record, source, guest)
        if record.get('worker_sha256') != WORKER_SHA256 or record.get('build_uid') != 1502:
            raise Refused('gitstatus_diagnostic_build_provenance_changed')
        archived = artifact_digest(INPUTS/'artifacts'/(artifact['sha256']+'.pkg.tar.zst'), artifact)
        build = {'present': True, 'record_sha256': hashlib.sha256(record_raw).hexdigest(),
                 'record': record, 'artifact': archived}
        if OUTPUT.exists():
            serial = Path('/sys/class/block/vdd/serial').read_text().strip()
            device = tuple(int(value) for value in Path('/sys/class/block/vdd/dev').read_text().strip().split(':'))
            actual = OUTPUT.stat().st_dev
            if (serial != 'mpkgout'+guest.replace('-', '')[:13]
                    or int(Path('/sys/class/block/vdd/size').read_text())*512 != 128*1024**2
                    or Path('/sys/class/block/vdd/ro').read_text().strip() != '0'
                    or (os.major(actual), os.minor(actual)) != device):
                raise Refused('gitstatus_diagnostic_output_disk_changed')
            authorization_raw = small(OUTPUT/'authorization.json', 4096)
            authorization = json.loads(authorization_raw)
            if (authorization.get('schema') != 1 or authorization.get('guest_id') != guest
                    or authorization.get('checkpoint') != 'native-change'
                    or not re.fullmatch(r'[0-9a-f]{64}', str(authorization.get('checkpoint_record_sha256', '')))):
                raise Refused('gitstatus_diagnostic_checkpoint_changed')
            if (OUTPUT/'gitstatus-build.json').exists() and (OUTPUT/'gitstatus.pkg.tar.zst').exists():
                if small(OUTPUT/'gitstatus-build.json') != record_raw:
                    raise Refused('gitstatus_diagnostic_export_record_changed')
                exported = artifact_digest(OUTPUT/'gitstatus.pkg.tar.zst', artifact)
                export = {'present': True, 'record_sha256': hashlib.sha256(record_raw).hexdigest(),
                          'artifact': exported, 'authorization': authorization,
                          'authorization_sha256': hashlib.sha256(authorization_raw).hexdigest()}
    log_path = STATE/'build.log'
    trusted_path(log_path)
    with log_path.open('rb') as stream:
        stream.seek(max(0, stream.seek(0, os.SEEK_END)-4096))
        log_tail = stream.read(4096).decode(errors='replace').splitlines()[-12:]
    observed_complete = complete(manager, group, builders, markers, guest, inventory == expected, export['present'])
    result = {'schema': 1, 'guest_id': guest, 'read_only': True,
              'source_inventory_sha256': SOURCE_SHA256, 'worker_sha256': worker_hash,
              'status': 'observed-complete' if observed_complete else 'incomplete',
              'manager': manager, 'cgroup': group, 'builder_processes_pid_comm': builders,
              'markers': markers, 'installed_package_count': len(inventory),
              'installed_inventory_sha256': hashlib.sha256(inventory_raw).hexdigest(),
              'installed_explicit_names_sha256': hashlib.sha256(explicit_raw).hexdigest(),
              'expected_216_package_inventory_matches': inventory == expected,
              'missing_expected_packages': sorted(expected.keys()-inventory.keys()),
              'unexpected_packages': sorted(inventory.keys()-expected.keys()),
              'changed_expected_versions': {n: inventory[n] for n in expected.keys() & inventory.keys() if expected[n] != inventory[n]},
              'build_dependency_reasons': {n: 'explicit' if n in explicit else 'dependency' for n in DEPENDENCIES if n in inventory},
              'build': build, 'export': export, 'build_log_tail': log_tail,
              'limits': ['gitstatus recipe defines no check function; source/build/export checks are separate.',
                         'No package installation, service action, artifact publication or output mount was requested.',
                         'Read-only observations are not a stopped snapshot; harvest still requires the VM stopped.']}
    output = json.dumps(result, sort_keys=True)
    if len(output.encode()) > 15000:
        raise Refused('gitstatus_diagnostic_output_bound')
    print(output)


if __name__ == '__main__':
    main()
