#!/usr/bin/env bash
# Inspect only fixed SSH fixture stages; no service action or authentication.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I - <<'PY'
import grp
import json
import os
from pathlib import Path
import pwd
import re
import resource
import selectors
import sqlite3
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, read_regular, require_guest
from native_service import (DROPIN, EXCLUSIVE, EXTERNAL_UNIT, MANAGED_CONFIG,
                            MANAGED_DROPINS, PUBLIC, ROLES, SHARED, configuration,
                            external_unit, state_root, trusted_path)
from run import ENV, command, trusted_install
from service_environment import verified_environment_files


def metadata(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'present': False}
    return {'present': True, 'regular': stat.S_ISREG(info.st_mode),
            'directory': stat.S_ISDIR(info.st_mode), 'symlink': stat.S_ISLNK(info.st_mode),
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode))}


def effective_summary(raw, expected):
    observed = {}
    normalized = {}
    for line in raw.decode().splitlines():
        key, separator, value = line.partition(' ')
        if separator and key in expected:
            observed.setdefault(key, []).append(value)
        pieces = line.split(None, 1)
        if len(pieces) == 2 and pieces[0] in expected:
            normalized.setdefault(pieces[0], []).append(pieces[1])
    return {key: {'occurrences': len(observed.get(key, [])),
                  'exact_match': observed.get(key) == [value],
                  'strip_match': [item.strip() for item in observed.get(key, [])] == [value],
                  'normalized_separator_match': [item.strip() for item in normalized.get(key, [])] == [value],
                  'value_lengths': [len(item) for item in observed.get(key, [])],
                  'leading_whitespace': [item != item.lstrip() for item in observed.get(key, [])],
                  'trailing_whitespace': [item != item.rstrip() for item in observed.get(key, [])]}
            for key, value in expected.items()}


def effective_config(path, role, root):
    if not path.exists():
        return {'present': False}
    trusted_path(path)
    if read_regular(path)[0] != configuration(role, root):
        return {'present': True, 'matches_fixed_generated_config': False, 'query_attempted': False}
    name, _, port, _ = ROLES[role]
    expected = {'port': str(port), 'addressfamily': 'inet', 'listenaddress': '127.0.0.1:' + str(port),
                'hostkey': str(root / (role + '-host')), 'authorizedkeysfile': str(PUBLIC / (name + '.pub')),
                'allowusers': name, 'permitrootlogin': 'no', 'passwordauthentication': 'no',
                'kbdinteractiveauthentication': 'no', 'authenticationmethods': 'publickey',
                'usepam': 'yes', 'disableforwarding': 'yes', 'permittty': 'no', 'forcecommand': 'internal-sftp'}
    try:
        raw = command(['/usr/bin/sshd', '-T', '-f', str(path)], timeout=15)
    except Refused:
        return {'present': True, 'matches_fixed_generated_config': True, 'query_succeeded': False}
    if len(raw) > 65536:
        raise Refused('diagnostic_effective_output_bound')
    return {'present': True, 'matches_fixed_generated_config': True, 'query_succeeded': True,
            'fields': effective_summary(raw, expected)}


def journal_state(directory):
    journal = {'present': (directory / 'state.sqlite3').exists()}
    if not journal['present']:
        return journal
    trusted_path(directory, directory=True)
    trusted_path(directory / 'state.sqlite3')
    database = sqlite3.connect((directory / 'state.sqlite3').as_uri() + '?mode=ro', uri=True, timeout=1)
    try:
        database.execute('PRAGMA query_only=ON')
        rows = database.execute('SELECT terminal,COUNT(*) FROM attempts GROUP BY terminal').fetchall()
        events = database.execute('SELECT kind,COUNT(*) FROM events GROUP BY kind').fetchall()
        if any(value not in (None, 'observed-complete', 'failed', 'unverified') for value, count in rows) or any(
                value not in ('started', 'observed-complete', 'failed', 'unverified') for value, count in events):
            raise Refused('diagnostic_unexpected_journal_state')
        journal.update(attempt_counts={value or 'unknown': count for value, count in rows},
                       event_counts=dict(events), protected_count=database.execute('SELECT COUNT(*) FROM protected').fetchone()[0])
    finally:
        database.close()
    return journal


def validate_config(path, expected):
    if not path.exists():
        return {'present': False}
    trusted_path(path)
    raw, _ = read_regular(path)
    if raw != expected:
        return {'present': True, 'matches_fixed_generated_config': False, 'validation_attempted': False}
    child = subprocess.Popen(['/usr/bin/sshd', '-t', '-f', str(path)], env=ENV,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr = bytearray()
    total = 0
    deadline = time.monotonic() + 15
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, False)
            selector.register(child.stderr, selectors.EVENT_READ, True)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise Refused('diagnostic_validation_timeout')
                for key, _ in selector.select(0.2):
                    part = os.read(key.fileobj.fileno(), 4096)
                    if not part:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(part)
                    if total > 65536:
                        raise Refused('diagnostic_validation_output_bound')
                    if key.data:
                        stderr.extend(part)
        code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        return {'present': True, 'matches_fixed_generated_config': True,
                'validation_attempted': True, 'exit_code': code,
                'missing_run_sshd_directory': b'Missing privilege separation directory: /run/sshd' in stderr,
                'no_hostkeys_available': b'no hostkeys available' in stderr,
                'bad_configuration_option': b'Bad configuration option' in stderr,
                'hostkey_permission_failure': b'UNPROTECTED PRIVATE KEY FILE' in stderr,
                'diagnostic_output_present': total > 0}
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
guest = require_guest(os.environ['MPKG_GUEST_ID'])
trusted_install()
root = state_root(guest)
recovery = root.parent / 'native-service-recovery'
paths = [root, root / 'state.sqlite3', root / 'baseline.json',
         root / 'packaged-sshd_config', root / 'packaged-sshd.service',
         PUBLIC, MANAGED_CONFIG, MANAGED_CONFIG.with_name('sshd_config.mpkg-fixture-new'),
         PUBLIC / 'external.conf', EXTERNAL_UNIT, MANAGED_DROPINS,
         MANAGED_DROPINS / '50-mpkg-fixture.conf', EXCLUSIVE, EXCLUSIVE / 'sentinel',
         SHARED, SHARED / 'sentinel', Path('/run/sshd')]
paths.extend([recovery, recovery / 'state.sqlite3', recovery / 'original-state.sqlite3',
              recovery / 'scope.json', recovery / 'result.json'])
for role, (name, _, _, _) in ROLES.items():
    paths.extend(root / (role + '-' + purpose + suffix) for purpose in ('host', 'client') for suffix in ('', '.pub'))
    paths.extend([root / (role + '-known-hosts'), PUBLIC / (name + '.pub'), Path('/home') / name])
files = {str(path): metadata(path) for path in paths}
accounts = {}
for role, (name, number, _, _) in ROLES.items():
    value = {}
    try:
        account = pwd.getpwnam(name)
        value.update(present=True, uid=account.pw_uid, gid=account.pw_gid,
                     supplementary_groups=sorted(os.getgrouplist(name, account.pw_gid)),
                     expected_home=account.pw_dir == '/home/' + name,
                     expected_shell=account.pw_shell == '/usr/bin/bash')
    except KeyError:
        value['present'] = False
    try:
        value['group_gid'] = grp.getgrnam(name).gr_gid
    except KeyError:
        value['group_present'] = False
    accounts[role] = value

units = {}
for unit in ('sshd.service', 'mpkg-fixture-external.service', 'sshdgenkeys.service'):
    raw = command(['/usr/bin/systemctl', 'show', unit, '--property=LoadState,ActiveState,SubState,MainPID,ControlPID,UnitFileState,Result,ExecMainStatus,ExecStart,FragmentPath,DropInPaths,Environment,EnvironmentFiles,PassEnvironment,LimitCORE'])
    observed = dict(line.split('=', 1) for line in raw.decode().splitlines())
    view = {}
    allowed = {'LoadState': {'loaded', 'not-found', 'masked', 'error'},
               'ActiveState': {'active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'},
               'SubState': {'dead', 'running', 'failed', 'exited', 'start', 'start-pre', 'start-post', 'stop', 'stop-sigterm', 'auto-restart'},
               'UnitFileState': {'enabled', 'disabled', 'static', 'indirect', 'masked', 'not-found'},
               'Result': {'success', 'exit-code', 'signal', 'core-dump', 'timeout', 'resources', 'start-limit-hit', 'protocol'}}
    for key, choices in allowed.items():
        value = observed.get(key)
        view[key] = value if value is None or value in choices else '<unexpected>'
    for key in ('MainPID', 'ControlPID', 'ExecMainStatus', 'LimitCORE'):
        value = observed.get(key)
        view[key] = value if value is None or re.fullmatch(r'[0-9]{1,20}|infinity', value) else '<unexpected>'
    for key in ('Environment', 'EnvironmentFiles', 'PassEnvironment'):
        view[key] = {'present': key in observed, 'empty': observed.get(key) == ''}
    if unit in ('sshd.service', 'mpkg-fixture-external.service') and observed.get('LoadState') == 'loaded':
        try:
            verified_environment_files(unit, observed)
            view['typed_environment_files_empty'] = True
        except Refused:
            view['typed_environment_files_empty'] = False
        role = 'native' if unit == 'sshd.service' else 'external'
        expected = '/usr/bin/sshd -D' + ('' if role == 'native' else ' -e -f ' + str(PUBLIC / 'external.conf'))
        view['fixed_ExecStart_prefix'] = observed.get('ExecStart', '').startswith(
            '{ path=/usr/bin/sshd ; argv[]=' + expected + ' ; ignore_errors=no ;')
        view['expected_fragment'] = observed.get('FragmentPath') == (
            '/usr/lib/systemd/system/sshd.service' if role == 'native' else str(EXTERNAL_UNIT))
        view['expected_dropins'] = observed.get('DropInPaths') == (
            str(MANAGED_DROPINS / '50-mpkg-fixture.conf') if role == 'native' else '')
    units[unit] = view

journal = journal_state(root)
recovery_journal = journal_state(recovery)
checks = []
if root.is_dir():
    with os.scandir(root) as entries:
        for index, entry in enumerate(entries):
            if index >= 128:
                raise Refused('diagnostic_fixture_directory_bound')
            if re.fullmatch(r'check-[0-9a-f-]{36}', entry.name) and entry.is_dir(follow_symlinks=False):
                path = Path(entry.path)
                trusted_path(path, directory=True)
                checks.append({name: metadata(path / name) for name in (
                    'native-effective.conf', 'native.batch', 'native-received',
                    'external-effective.conf', 'external.batch', 'external-received', 'result.json')})
validation = {
    'native_candidate': validate_config(MANAGED_CONFIG.with_name('sshd_config.mpkg-fixture-new'), configuration('native', root)),
    'native_active': validate_config(MANAGED_CONFIG, configuration('native', root)),
    'external': validate_config(PUBLIC / 'external.conf', configuration('external', root)),
}
effective = {'native': effective_config(MANAGED_CONFIG, 'native', root),
             'external': effective_config(PUBLIC / 'external.conf', 'external', root)}
print(json.dumps({'schema': 1, 'guest_id': guest, 'diagnostic_only': True,
                  'fixed_paths': files, 'accounts': accounts, 'units': units,
                  'journal': journal, 'check_stages': checks, 'config_validation': validation,
                  'recovery_journal': recovery_journal, 'effective_configuration': effective,
                  'service_mutation': False, 'authenticated_requests': False}, sort_keys=True))
PY
