#!/usr/bin/env python3
"""Prepare a separate native adoption baseline without product application."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys

sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, require_guest, write_new
from native_service import check as check_native_service, trusted_path

PYTHON = '/opt/mpkg-python/3.12.16/bin/python3.12'
INSTALLED = Path('/opt/mpkg-fixture/guest_native_adoption.py')
STATE = Path('/var/lib/mpkg-fixture/native-adoption')
INPUTS = Path('/opt/mpkg-proof-inputs')
UNIT = 'mpkg-fixture-native-adoption.service'
CLI_REQUESTS = ('ack', 'bash-completion', 'fzf', 'jless', 'less', 'man-pages',
                'ripgrep', 'tmux', 'tree', 'yq')
CLI_RECIPE_SHA256 = 'd2eebd174ab2dfc1a9a5323ca960311c8c1f0be279557a29f6221058c1d88032'
ADDITIONS = {'libutempter', 'ripgrep', 'tmux'}
ENV = {'PATH': '/usr/bin', 'LC_ALL': 'C', 'HOME': '/root',
       'SYSTEMD_PAGER': 'cat', 'SYSTEMD_COLORS': '0'}


def command(arguments, timeout=30):
    return subprocess.run(arguments, env=ENV, check=True, timeout=timeout,
                          capture_output=True).stdout


def package_state():
    versions = dict(line.split() for line in command(['/usr/bin/pacman', '-Q']).decode().splitlines())
    explicit = set(command(['/usr/bin/pacman', '-Qqe']).decode().splitlines())
    if not explicit <= versions.keys():
        raise Refused('installed_reasons_changed_during_query')
    return {name: {'version': version, 'reason': 'explicit' if name in explicit else 'dependency'}
            for name, version in versions.items()}


def verify_result(before, after, selected):
    expected = dict(before)
    expected.update({p['name']: {'version': p['version'],
                     'reason': 'dependency' if p['name'] == 'libutempter' else 'explicit'}
                     for p in selected})
    if len(selected)!=3 or {item['name'] for item in selected} != ADDITIONS or ADDITIONS & before.keys():
        raise Refused('adoption_delta_is_not_the_missing_cli_closure')
    if after != expected or not set(CLI_REQUESTS) <= after.keys():
        raise Refused('adoption_changed_existing_versions_or_reasons')


def worker(guest):
    sys.path.insert(0, '/opt/mpkg-fixture')
    from guest_aur import checked_file, verify_baseline, SOURCE_SHA
    if Path('/var/lib/mpkg').exists() or Path('/var/lib/mpkg').is_symlink():
        raise Refused('product_state_must_be_absent')
    source_bytes = checked_file(INPUTS/'source-inventory.json', SOURCE_SHA)
    source = json.loads(source_bytes)
    checkpoint_bytes = checked_file(INPUTS/'native-change-checkpoint.json')
    checkpoint = json.loads(checkpoint_bytes)
    if (checkpoint.get('schema') != 1 or checkpoint.get('guest_id') != guest
            or checkpoint.get('checkpoint') != 'native-change'
            or not re.fullmatch('[0-9a-f]{64}', checkpoint.get('checkpoint_record_sha256', ''))):
        raise Refused('preserved_native_change_checkpoint_required')
    verify_baseline(source, with_ack=True)
    before = package_state()
    service_before = check_native_service(guest)
    selected = [p for p in source['repository_packages'] if p['name'] in ADDITIONS]
    if len(selected) != 3 or ADDITIONS & before.keys():
        raise Refused('unexpected_native_adoption_starting_state')
    acquired = json.loads(checked_file(INPUTS/'native-acquisition.json'))
    signatures = {p['sha256']: p['signature_sha256'] for p in acquired}
    archives = []
    for package in selected:
        digest = package['package_sha256_published_in_database']
        archive = INPUTS/'artifacts'/(digest+'.pkg.tar.zst')
        checked_file(archive, digest)
        checked_file(Path(str(archive)+'.sig'), signatures[digest])
        archives.append(str(archive))
    # No repository sections: this transaction can only use the bound local
    # artifacts, and signatures remain mandatory under the guest Arch keyring.
    config = STATE/'signed-local-pacman.conf'
    write_new(config, b'[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Required\n')
    command(['/usr/bin/pacman', '--config', str(config), '-U', '--noconfirm', *archives], timeout=850)
    command(['/usr/bin/pacman', '-D', '--asdeps', 'libutempter'])
    after = package_state()
    verify_result(before, after, selected)
    service_after = check_native_service(guest)
    if Path('/var/lib/mpkg').exists() or Path('/var/lib/mpkg').is_symlink():
        raise Refused('unexpected_product_state')
    result = {'schema': 1, 'guest_id': guest, 'fixture_state': 'native-adoption',
              'collection': 'vhata-cli', 'collection_pkgbuild_sha256': CLI_RECIPE_SHA256,
              'declared_requests': list(CLI_REQUESTS), 'request_versions': {n: after[n]['version'] for n in CLI_REQUESTS},
              'source_inventory_sha256': hashlib.sha256(source_bytes).hexdigest(),
              'native_change_checkpoint': checkpoint,
              'native_change_checkpoint_input_sha256': hashlib.sha256(checkpoint_bytes).hexdigest(),
              'installed_before': before, 'installed_after': after,
              'added_packages': sorted(ADDITIONS), 'existing_installation_reasons_preserved': True,
              'native_service_before': service_before, 'native_service_after': service_after,
              'product_state_observed_absent': True, 'product_application_claimed': False,
              'product_adoption_or_attempt_created': False}
    raw = (json.dumps(result, sort_keys=True, indent=2)+'\n').encode()
    write_new(STATE/'result.json', raw)
    write_new(STATE/'complete', (guest+'\n').encode())
    print(json.dumps({'status': 'prepared', 'fixture_state': 'native-adoption',
                      'installed_packages': len(after), 'result_sha256': hashlib.sha256(raw).hexdigest(),
                      'product_application_claimed': False}), flush=True)


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
                 'mpkg-fixture-aur-gitstatus.service'):
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
    content = ('[Unit]\nDescription=Prepare separate native adoption fixture\n'
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
