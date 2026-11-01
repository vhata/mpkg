#!/usr/bin/env python3
"""Observe only the native adoption and update-before assembly jobs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import signal
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
import native_service as native
from core import Refused, canonical, read_regular, require_guest
from native_manifest import SOURCE_SHA256
from run import command, trusted_install

STATES = {
    'native-adoption': ('guest_native_adoption.py', '255765f55a16bdb18d025b433b1adeddae7455161672e7eecb7ca272eec47628', 212),
    'native-update-before': ('guest_native_update_before.py', '9a8947c6d54ad41c96c9a1ece2cc4b53e979145cbcde847df50580bee273a2da', 220),
}
NATIVE_SHA256 = 'd4183fa9a7251b1b0b97d5f09701bfeb1cbd52819aba143896de9eb14918e675'
CLI_SHA256 = 'd2eebd174ab2dfc1a9a5323ca960311c8c1f0be279557a29f6221058c1d88032'
CLI = ('ack', 'bash-completion', 'fzf', 'jless', 'less', 'man-pages', 'ripgrep', 'tmux', 'tree', 'yq')
CLI_ADD = {'libutempter', 'ripgrep', 'tmux'}
BUILD_ADD = {'cmake', 'cppdap', 'hicolor-icon-theme', 'jsoncpp', 'libuv', 'rhash', 'zsh'}
INPUTS = Path('/opt/mpkg-proof-inputs')
BASE = Path('/var/lib/mpkg-fixture')


def small(path, maximum=131072):
    native.trusted_path(path)
    if path.stat().st_size > maximum:
        raise Refused('native_assembly_diagnostic_file_bound')
    return read_regular(path)[0]


def wanted_versions(source, state):
    if state not in STATES:
        raise Refused('native_assembly_diagnostic_state_not_allowed')
    names = set(source['resolutions']['native_change' if state == 'native-adoption' else 'native_applied']['resolved_package_names'])
    if state == 'native-adoption':
        names |= CLI_ADD
    result = {p['name']: p['version'] for p in source['repository_packages'] if p['name'] in names}
    result.update({p['package_base']: p['srcinfo_version'] for p in source['aur_packages']
                   if state == 'native-update-before' or p['package_base'] in {'ack', 'perl-file-next'}})
    if len(result) != STATES[state][2] or result.get('gnupg') != '2.4.9-3':
        raise Refused('native_assembly_diagnostic_frozen_scope')
    return result


def valid_service_result(value, guest):
    if value.get('schema') != 1 or value.get('guest_id') != guest or value.get('status') != 'observed':
        return False
    services = value.get('services', [])
    if len(services) != 2 or {p.get('role') for p in services} != {'native', 'external'}:
        return False
    for item in services:
        role = item['role']
        content = 'mpkg fixture '+guest+' '+('exclusive' if role == 'native' else 'shared')+'\n'
        if item.get('authenticated_sftp_read') is not True or item.get('sentinel_sha256') != hashlib.sha256(content.encode()).hexdigest():
            return False
    return True


def validate_record(record, source, state, guest, checkpoint, adoption=None, adoption_hash=None, builds=None):
    wanted = wanted_versions(source, state)
    before, after = record.get('installed_before', {}), record.get('installed_after', {})
    for inventory in (before, after):
        if any(set(value) != {'version', 'reason'} or value['reason'] not in {'explicit', 'dependency'}
               or not isinstance(value['version'], str) for value in inventory.values()):
            raise Refused('native_assembly_diagnostic_record_inventory_shape')
    if ({n: p['version'] for n, p in after.items()} != wanted
            or any(after.get(n) != value for n, value in before.items())
            or record.get('schema') != 1 or record.get('guest_id') != guest
            or record.get('fixture_state') != state or record.get('source_inventory_sha256') != SOURCE_SHA256
            or record.get('native_change_checkpoint') != checkpoint
            or record.get('existing_installation_reasons_preserved') is not True
            or record.get('product_state_observed_absent') is not True
            or record.get('product_adoption_or_attempt_created') is not False
            or not all(valid_service_result(record.get(key, {}), guest)
                       for key in ('native_service_before', 'native_service_after'))):
        raise Refused('native_assembly_diagnostic_result_binding')
    if state == 'native-adoption':
        baseline = {n: version for n, version in wanted.items() if n not in CLI_ADD}
        if (len(before) != 209 or {n: p['version'] for n, p in before.items()} != baseline
                or record.get('collection') != 'vhata-cli' or record.get('collection_pkgbuild_sha256') != CLI_SHA256
                or record.get('declared_requests') != list(CLI)
                or record.get('request_versions') != {n: wanted[n] for n in CLI}
                or record.get('added_packages') != sorted(CLI_ADD)
                or record.get('product_application_claimed') is not False
                or {n: after[n]['reason'] for n in CLI_ADD} != {
                    'tmux': 'explicit', 'ripgrep': 'explicit', 'libutempter': 'dependency'}):
            raise Refused('native_assembly_diagnostic_adoption_delta')
    else:
        if (adoption is None or before != adoption['installed_after']
                or record.get('native_adoption_result_sha256') != adoption_hash
                or record.get('repository_snapshot_date') != '2026-10-30'
                or record.get('repository_package_count') != 217 or record.get('built_aur_package_count') != 3
                or record.get('installed_package_count') != 220 or record.get('bootstrap_only') is not True
                or record.get('product_native_applied_state_claimed') is not False
                or record.get('new_dependency_reasons') != sorted(BUILD_ADD)
                or record.get('new_explicit_requests') != ['gitstatus']
                or set(after)-set(before) != BUILD_ADD | {'gitstatus'}
                or any(after[n]['reason'] != 'dependency' for n in BUILD_ADD)
                or after['gitstatus']['reason'] != 'explicit'
                or record.get('built_aur_inputs') != builds
                or record.get('gitstatus_build_record_sha256') != builds['gitstatus']['build_record_sha256']
                or record.get('gitstatus_artifact_sha256') != builds['gitstatus']['artifact_sha256']):
            raise Refused('native_assembly_diagnostic_update_delta')
    return after


def manager_observation(unit):
    raw = command(['/usr/bin/systemctl', '--no-pager', '--plain', 'show', unit,
                   '--property=ActiveState,SubState,Result,ExecMainStatus,MainPID,ControlPID,ControlGroup,TasksCurrent'])
    values = dict(line.split('=', 1) for line in raw.decode().splitlines())
    if values.get('ControlGroup') not in ('', '/system.slice/'+unit):
        raise Refused('native_assembly_diagnostic_unexpected_cgroup')
    path = Path('/sys/fs/cgroup/system.slice')/unit
    group = {'present': path.exists(), 'pids': [], 'events': {}}
    if group['present']:
        for filename, limit in (('cgroup.procs', 4096), ('cgroup.events', 1024)):
            with (path/filename).open() as stream:
                text = stream.read(limit+1)
            if len(text) > limit:
                raise Refused('native_assembly_diagnostic_cgroup_bound')
            if filename == 'cgroup.procs':
                if any(not value.isdecimal() for value in text.splitlines()):
                    raise Refused('native_assembly_diagnostic_cgroup_shape')
                group['pids'] = [int(value) for value in text.splitlines()]
            else:
                group['events'] = dict(line.split() for line in text.splitlines())
    return values, group


def complete(manager, group, markers, guest, record_matches, current_matches):
    return (manager.get('ActiveState') == 'inactive' and manager.get('SubState') == 'dead'
            and manager.get('Result') == 'success' and manager.get('ExecMainStatus') == '0'
            and manager.get('MainPID') == '0' and manager.get('ControlPID') == '0'
            and not group['pids'] and (not group['present'] or group['events'].get('populated') == '0')
            and markers == {'started': guest, 'complete': guest, 'exit': '0'}
            and record_matches and current_matches)


def service_observations(guest):
    if hashlib.sha256(small(Path(native.__file__).resolve())).hexdigest() != NATIVE_SHA256:
        raise Refused('native_assembly_diagnostic_service_helper_changed')
    root = native.state_root(guest)
    data = native.data_inventory()
    services = []
    for role, (_, _, port, unit) in native.ROLES.items():
        account = native.identity(role)
        config = native.MANAGED_CONFIG if role == 'native' else native.PUBLIC/'external.conf'
        raw = small(config)
        if raw != native.configuration(role, root):
            raise Refused('native_assembly_diagnostic_service_config_changed')
        manager = native.service_properties(unit)
        native.assert_startup(manager, role)
        fragment = native.PACKAGED_UNIT if role == 'native' else native.EXTERNAL_UNIT
        if manager.get('FragmentPath') != str(fragment):
            raise Refused('native_assembly_diagnostic_service_fragment_changed')
        if role == 'native':
            if (small(native.PACKAGED_UNIT) != small(root/'packaged-sshd.service')
                    or small(native.MANAGED_DROPINS/'50-mpkg-fixture.conf') != native.DROPIN):
                raise Refused('native_assembly_diagnostic_service_unit_changed')
        elif small(native.EXTERNAL_UNIT) != native.external_unit():
            raise Refused('native_assembly_diagnostic_service_unit_changed')
        if (manager.get('ActiveState') != 'active' or manager.get('SubState') != 'running'
                or manager.get('UnitFileState') != 'enabled' or manager.get('LimitCORE') != '0'):
            raise Refused('native_assembly_diagnostic_service_not_ready')
        pid, start, inodes = native.listener_identity(manager, port)
        services.append({'role': role, 'unit': unit, 'account': account, 'port': port,
                         'manager': {k: manager.get(k) for k in ('ActiveState', 'SubState', 'MainPID', 'UnitFileState', 'LimitCORE')},
                         'process_start_ticks': int(start), 'listener_inodes': sorted(inodes),
                         'configuration_sha256': hashlib.sha256(raw).hexdigest()})
    return {'services': services, 'data': data, 'authenticated_checks_rerun': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', choices=tuple(STATES), action='append')
    args = parser.parse_args()
    selected = args.state or list(STATES)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    trusted_install()
    def expired(*_):
        raise Refused('native_assembly_diagnostic_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(120)
    source_raw = small(INPUTS/'source-inventory.json', 1048576)
    if hashlib.sha256(source_raw).hexdigest() != SOURCE_SHA256:
        raise Refused('native_assembly_diagnostic_source_changed')
    source = json.loads(source_raw)
    checkpoint_raw = small(INPUTS/'native-change-checkpoint.json', 4096)
    checkpoint = json.loads(checkpoint_raw)
    if (checkpoint.get('schema') != 1 or checkpoint.get('guest_id') != guest
            or checkpoint.get('checkpoint') != 'native-change'
            or not re.fullmatch('[0-9a-f]{64}', str(checkpoint.get('checkpoint_record_sha256', '')))):
        raise Refused('native_assembly_diagnostic_checkpoint_changed')
    version_raw = command(['/usr/bin/pacman', '-Q'])
    versions = dict(line.split() for line in version_raw.decode().splitlines())
    explicit_raw = command(['/usr/bin/pacman', '-Qqe'])
    explicit = set(explicit_raw.decode().splitlines())
    if not explicit <= versions.keys():
        raise Refused('native_assembly_diagnostic_inventory_changed')
    current = {n: {'version': v, 'reason': 'explicit' if n in explicit else 'dependency'} for n, v in versions.items()}
    product = Path('/var/lib/mpkg')
    product_absent = not product.exists() and not product.is_symlink()
    records, raw_records, expected = {}, {}, {}
    for state in STATES:
        path = BASE/state/'result.json'
        if not path.exists():
            continue
        worker_name, worker_sha, _ = STATES[state]
        if hashlib.sha256(small(Path('/opt/mpkg-fixture')/worker_name)).hexdigest() != worker_sha:
            raise Refused('native_assembly_diagnostic_worker_changed')
        raw_records[state] = small(path)
        records[state] = json.loads(raw_records[state])
        builds = None
        if state == 'native-update-before':
            builds = {}
            for name in ('ack', 'perl-file-next', 'gitstatus'):
                raw = small(INPUTS/(name+'-build.json'))
                built = json.loads(raw)['artifact']
                builds[name] = {'build_record_sha256': hashlib.sha256(raw).hexdigest(),
                                'artifact_sha256': built['sha256'], 'version': built['version']}
        expected[state] = validate_record(records[state], source, state, guest, checkpoint,
            records.get('native-adoption'), hashlib.sha256(raw_records.get('native-adoption', b'')).hexdigest(), builds)
        if state == 'native-adoption' and records[state].get('native_change_checkpoint_input_sha256') != hashlib.sha256(checkpoint_raw).hexdigest():
            raise Refused('native_assembly_diagnostic_checkpoint_input_changed')
    observations = []
    for state in selected:
        path = BASE/state
        worker_name, worker_sha, _ = STATES[state]
        worker_path = Path('/opt/mpkg-fixture')/worker_name
        actual_worker = hashlib.sha256(small(worker_path)).hexdigest() if worker_path.exists() or worker_path.is_symlink() else None
        if actual_worker is not None and actual_worker != worker_sha:
            raise Refused('native_assembly_diagnostic_worker_changed')
        wanted = wanted_versions(source, state)
        manager, group = manager_observation('mpkg-fixture-'+state+'.service')
        markers = {n: small(path/n, 128).decode().strip() if (path/n).exists() else 'absent'
                   for n in ('started', 'complete', 'exit')}
        observed = complete(manager, group, markers, guest, state in records and product_absent,
                            current == expected.get(state))
        record = records.get(state)
        observations.append({'fixture_state': state, 'status': 'observed-complete' if observed else 'incomplete',
            'expected_package_count': STATES[state][2], 'worker_sha256': actual_worker, 'manager': manager, 'cgroup': group, 'markers': markers,
            'result_present': record is not None, 'result_sha256': hashlib.sha256(raw_records[state]).hexdigest() if record else None,
            'result_source_and_reason_bindings_valid': record is not None,
            'current_inventory_and_reasons_match_result': current == expected.get(state),
            'current_versions_match_frozen_scope': versions == wanted,
            'missing_expected_packages': sorted(wanted.keys()-versions.keys()),
            'unexpected_packages': sorted(versions.keys()-wanted.keys()),
            'changed_expected_versions': {n: versions[n] for n in wanted.keys() & versions.keys() if versions[n] != wanted[n]},
            'new_package_reasons': {n: current[n]['reason'] for n in (CLI_ADD if state == 'native-adoption' else BUILD_ADD | {'gitstatus'}) if n in current},
            'recorded_authenticated_reads_before_and_after': record is not None})
    services = service_observations(guest)
    if command(['/usr/bin/pacman', '-Q']) != version_raw or command(['/usr/bin/pacman', '-Qqe']) != explicit_raw:
        raise Refused('native_assembly_diagnostic_inventory_changed_during_observation')
    if any(small(BASE/state/'result.json') != raw for state, raw in raw_records.items()):
        raise Refused('native_assembly_diagnostic_result_changed_during_observation')
    result = {'schema': 1, 'guest_id': guest, 'read_only': True, 'product_acceptance': False,
              'source_inventory_sha256': SOURCE_SHA256, 'native_change_checkpoint': checkpoint,
              'installed_package_count': len(current), 'gnupg': current.get('gnupg'),
              'installed_inventory_sha256': hashlib.sha256(version_raw).hexdigest(),
              'installed_explicit_names_sha256': hashlib.sha256(explicit_raw).hexdigest(),
              'installed_versions_and_reasons_sha256': hashlib.sha256(canonical(current)).hexdigest(),
              'product_state_observed_absent': product_absent, 'observations': observations,
              'native_service_observations': services,
              'limits': ['No packages, services, journals or credential files were changed.',
                         'Current service observations are metadata and listener checks, not new authenticated reads.',
                         'Completed jobs bind their own authenticated before/after checks and original reason records.',
                         'A stopped VM checkpoint is still required; this is a live read-only observation.']}
    output = json.dumps(result, sort_keys=True)
    if len(output.encode()) > 15000:
        raise Refused('native_assembly_diagnostic_output_bound')
    print(output)


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'read_only': True}))
        sys.exit(73)
