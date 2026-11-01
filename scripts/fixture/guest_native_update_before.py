#!/usr/bin/env python3
"""Prepare the October 30 update baseline without claiming product application."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import subprocess
import sys

sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, require_guest, write_new
from native_manifest import validate_build
from native_service import check as check_native_service, trusted_path

PYTHON = '/opt/mpkg-python/3.12.16/bin/python3.12'
INSTALLED = Path('/opt/mpkg-fixture/guest_native_update_before.py')
STATE = Path('/var/lib/mpkg-fixture/native-update-before')
INPUTS = Path('/opt/mpkg-proof-inputs')
UNIT = 'mpkg-fixture-native-update-before.service'
BUILD_DEPENDENCIES = {'cmake', 'cppdap', 'hicolor-icon-theme', 'jsoncpp', 'libuv', 'rhash', 'zsh'}
ENV = {'PATH': '/usr/bin', 'LC_ALL': 'C', 'HOME': '/root',
       'SYSTEMD_PAGER': 'cat', 'SYSTEMD_COLORS': '0'}


def command(arguments, timeout=30):
    result = subprocess.run(arguments, env=ENV, timeout=timeout, capture_output=True)
    if result.returncode:
        print(json.dumps({'command': arguments[0], 'exit_code': result.returncode,
                          'stdout_tail': result.stdout[-4096:].decode(errors='replace'),
                          'stderr_tail': result.stderr[-4096:].decode(errors='replace')}), file=sys.stderr)
        raise Refused('fixture_command_failed')
    return result.stdout


def plan(source, before):
    names = set(source['resolutions']['native_applied']['resolved_package_names'])
    repository = {p['name']: p for p in source['repository_packages'] if p['name'] in names}
    aur = {p['package_base']: p['srcinfo_version'] for p in source['aur_packages']}
    if (len(names) != 217 or set(repository) != names or set(aur) != {'ack', 'perl-file-next', 'gitstatus'}
            or repository['gnupg']['version'] != '2.4.9-3'):
        raise Refused('frozen_october30_complete_contents_required')
    adoption_names = set(source['resolutions']['native_change']['resolved_package_names']) | {'tmux', 'ripgrep', 'libutempter'}
    starting_versions = {name: repository[name]['version'] for name in adoption_names}
    starting_versions.update({name: aur[name] for name in ('ack', 'perl-file-next')})
    if len(starting_versions) != 212 or {n: p['version'] for n, p in before.items()} != starting_versions:
        raise Refused('exact_native_adoption_starting_contents_required')
    if names - before.keys() != BUILD_DEPENDENCIES:
        raise Refused('unexpected_update_baseline_dependency_delta')
    expected = dict(before)
    expected.update({name: {'version': repository[name]['version'], 'reason': 'dependency'}
                     for name in BUILD_DEPENDENCIES})
    expected['gitstatus'] = {'version': aur['gitstatus'], 'reason': 'explicit'}
    if len(expected) != 220 or set(expected) != names | aur.keys():
        raise Refused('complete_update_baseline_contents_mismatch')
    return [repository[name] for name in sorted(BUILD_DEPENDENCIES)], expected


def aur_provenance(record, source, name, guest):
    recipe = next(p for p in source['aur_packages'] if p['package_base'] == name)
    files = {filename: value['sha256_computed'] for filename, value in recipe['recipe_files'].items()}
    sources = sorted((s['filename'], algorithm, digest) for s in recipe['sources']
                     for algorithm, digest in s['digests_published_in_recipe'].items())
    observed = sorted((s['filename'], s['algorithm'], s['digest']) for s in record['sources'] if s.get('verified') is True)
    artifact = record['artifact']
    metadata_matches = record.get('generated_metadata_matches') is True and 'metadata_reconciliation' not in record
    if name == 'ack':
        # The producer accepts only the reviewed pair of metadata byte hashes
        # and one homepage URL difference; this does not claim literal equality.
        from guest_aur import ACK_RECIPE_COMMIT, ACK_URL_RECONCILIATION
        metadata_matches = (record.get('generated_metadata_matches') is False
                            and recipe['recipe_commit'] == ACK_RECIPE_COMMIT
                            and record.get('metadata_reconciliation') == ACK_URL_RECONCILIATION)
    if (record.get('schema') != 1 or record.get('guest_id') != guest or record.get('package_base') != name
            or record.get('recipe_commit') != recipe['recipe_commit'] or record.get('recipe_files') != files
            or observed != sources or len(record['sources']) != len(sources)
            or type(record.get('build_uid')) is not int or record['build_uid'] <= 0
            or record.get('source_verification_exit_code') != 0 or record.get('build_exit_code') != 0
            or not metadata_matches
            or record.get('check_status') != ('not-defined' if name == 'gitstatus' else 'passed')
            or artifact.get('name') != name or artifact.get('version') != recipe['srcinfo_version']
            or not re.fullmatch('[0-9a-f]{64}', artifact.get('sha256', ''))
            or type(artifact.get('size')) is not int or not 0 < artifact['size'] <= 64*1024**2):
        raise Refused('actual_pinned_aur_build_required')
    return artifact


def worker(guest):
    sys.path.insert(0, '/opt/mpkg-fixture')
    from guest_aur import checked_file, SOURCE_SHA
    from guest_native_adoption import package_state
    product = Path('/var/lib/mpkg')
    if product.exists() or product.is_symlink():
        raise Refused('product_state_must_be_absent')
    adoption = Path('/var/lib/mpkg-fixture/native-adoption')
    if checked_file(adoption/'complete').decode().strip() != guest or checked_file(adoption/'exit') != b'0\n':
        raise Refused('successful_native_adoption_required')
    adoption_bytes = checked_file(adoption/'result.json')
    adoption_record = json.loads(adoption_bytes)
    source_bytes = checked_file(INPUTS/'source-inventory.json', SOURCE_SHA)
    source = json.loads(source_bytes)
    before = package_state()
    if (adoption_record.get('guest_id') != guest or adoption_record.get('fixture_state') != 'native-adoption'
            or adoption_record.get('product_application_claimed') is not False
            or adoption_record.get('installed_after') != before):
        raise Refused('native_adoption_versions_or_reasons_changed')
    selected, expected = plan(source, before)
    checkpoint_bytes = checked_file(INPUTS/'native-change-checkpoint.json')
    if hashlib.sha256(checkpoint_bytes).hexdigest() != adoption_record['native_change_checkpoint_input_sha256']:
        raise Refused('preserved_native_change_binding_changed')
    build_bytes = checked_file(INPUTS/'gitstatus-build.json')
    if checked_file(Path('/var/lib/mpkg-fixture/gitstatus-artifact-imported')) != (guest+'\n').encode():
        raise Refused('completed_gitstatus_import_required')
    built = validate_build(json.loads(build_bytes), source, guest)
    artifact = INPUTS/'artifacts'/(built['sha256']+'.pkg.tar.zst')
    if len(checked_file(artifact, built['sha256'])) != built['size']:
        raise Refused('verified_gitstatus_artifact_size_changed')
    aur_inputs = {}
    for name in ('ack', 'perl-file-next', 'gitstatus'):
        raw = checked_file(INPUTS/(name+'-build.json'))
        produced = aur_provenance(json.loads(raw), source, name, guest)
        path = INPUTS/'artifacts'/(produced['sha256']+'.pkg.tar.zst')
        if len(checked_file(path, produced['sha256'])) != produced['size']:
            raise Refused('actual_aur_artifact_size_changed')
        aur_inputs[name] = {'build_record_sha256': hashlib.sha256(raw).hexdigest(),
                            'artifact_sha256': produced['sha256'], 'version': produced['version']}
    acquired = json.loads(checked_file(INPUTS/'native-acquisition.json'))
    signatures = {p['sha256']: p['signature_sha256'] for p in acquired}
    archives = []
    for package in selected:
        digest = package['package_sha256_published_in_database']
        path = INPUTS/'artifacts'/(digest+'.pkg.tar.zst')
        checked_file(path, digest)
        checked_file(Path(str(path)+'.sig'), signatures[digest])
        archives.append(str(path))
    service_before = check_native_service(guest)
    signed_config = STATE/'signed-local-pacman.conf'
    build_config = STATE/'fixture-build-pacman.conf'
    common = b'[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\n'
    write_new(signed_config, common+b'LocalFileSigLevel = Required\n')
    write_new(build_config, common+b'LocalFileSigLevel = Never\n')
    # Repository archives require signatures. The separate unsigned policy is
    # used only for the one imported provenance/hash-verified fixture build.
    command(['/usr/bin/pacman', '--config', str(signed_config), '-U', '--noconfirm', *archives], timeout=800)
    command(['/usr/bin/pacman', '-D', '--asdeps', *sorted(BUILD_DEPENDENCIES)])
    command(['/usr/bin/pacman', '--config', str(build_config), '-U', '--noconfirm', str(artifact)], timeout=800)
    after = package_state()
    if after != expected or after['gnupg']['version'] != '2.4.9-3':
        raise Refused('update_baseline_versions_or_reasons_mismatch')
    service_after = check_native_service(guest)
    if product.exists() or product.is_symlink():
        raise Refused('unexpected_product_state')
    result = {'schema': 1, 'guest_id': guest, 'fixture_state': 'native-update-before',
              'repository_snapshot_date': '2026-10-30', 'repository_package_count': 217,
              'built_aur_package_count': 3, 'installed_package_count': 220,
              'source_inventory_sha256': hashlib.sha256(source_bytes).hexdigest(),
              'native_adoption_result_sha256': hashlib.sha256(adoption_bytes).hexdigest(),
              'native_change_checkpoint': json.loads(checkpoint_bytes),
              'gitstatus_build_record_sha256': hashlib.sha256(build_bytes).hexdigest(),
              'gitstatus_artifact_sha256': built['sha256'],
              'built_aur_inputs': aur_inputs,
              'installed_before': before, 'installed_after': after,
              'new_dependency_reasons': sorted(BUILD_DEPENDENCIES), 'new_explicit_requests': ['gitstatus'],
              'existing_installation_reasons_preserved': True,
              'native_service_before': service_before, 'native_service_after': service_after,
              'bootstrap_only': True, 'product_state_observed_absent': True,
              'product_native_applied_state_claimed': False,
              'product_adoption_or_attempt_created': False}
    raw = (json.dumps(result, sort_keys=True, indent=2)+'\n').encode()
    write_new(STATE/'result.json', raw)
    write_new(STATE/'complete', (guest+'\n').encode())
    print(json.dumps({'status': 'prepared', 'fixture_state': 'native-update-before',
                      'installed_packages': 220, 'gnupg': after['gnupg']['version'],
                      'result_sha256': hashlib.sha256(raw).hexdigest(), 'bootstrap_only': True}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', default=os.environ.get('MPKG_GUEST_ID'))
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    trusted_path(INSTALLED.parent, directory=True)
    trusted_path(STATE.parent, directory=True)
    if args.worker:
        code = 1
        try:
            worker(guest)
            code = 0
        finally:
            write_new(STATE/'exit', (str(code)+'\n').encode())
        return
    sys.path.insert(0, '/opt/mpkg-fixture')
    from guest_aur import checked_file, require_idle_unit
    for unit in ('mpkg-fixture-python-build.service', 'mpkg-fixture-aur-ack.service',
                 'mpkg-fixture-aur-gitstatus.service', 'mpkg-fixture-native-adoption.service'):
        raw = command(['/usr/bin/systemctl', 'show', '--property=ActiveState,SubState,MainPID,ControlPID,ExecMainStatus,Result,ControlGroup', unit])
        status = dict(line.split('=', 1) for line in raw.decode().splitlines())
        require_idle_unit(status)
        if status.get('ControlGroup'):
            if status['ControlGroup'] != '/system.slice/'+unit:
                raise Refused('unexpected_build_control_group')
            events = dict(line.split() for line in (Path('/sys/fs/cgroup')/status['ControlGroup'].lstrip('/')/'cgroup.events').read_text().splitlines())
            if events.get('populated') != '0':
                raise Refused('build_descendants_still_running')
    STATE.mkdir(mode=0o700)
    write_new(INSTALLED, checked_file(Path(__file__).resolve()))
    content = ('[Unit]\nDescription=Prepare October30 native update fixture\n'
               '[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=900\nTimeoutStopSec=15\n'
               'KillMode=control-group\nLimitCORE=0\nStandardOutput=append:'+str(STATE/'build.log')+'\n'
               'StandardError=inherit\nExecStart='+PYTHON+' -I '+str(INSTALLED)+' --worker --guest-id '+guest+'\n')
    write_new(Path('/etc/systemd/system')/UNIT, content.encode())
    write_new(STATE/'started', (guest+'\n').encode())
    command(['/usr/bin/systemctl', 'daemon-reload'])
    command(['/usr/bin/systemctl', 'start', '--no-block', UNIT])
    print(json.dumps({'status': 'started', 'unit': UNIT, 'guest_id': guest}))


if __name__ == '__main__':
    main()
