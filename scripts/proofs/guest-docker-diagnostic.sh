#!/usr/bin/env bash
# Read only fixed unit/process/state facts; never contact the Docker socket.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sqlite3
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, read_regular, require_guest
from docker_ready import PROPERTIES, UNITS, assert_unit
from run import command, trusted_install

def safe_execution(execution, expected):
    prefix = ('{ path=' + expected.split()[0] + ' ; argv[]=' + expected + ' ; ') if expected else ''
    known = {'path', 'argv[]', 'ignore_errors', 'flags', 'start_time', 'stop_time', 'pid', 'code', 'status'}
    fields = re.findall(r'(?:^|[;{])\s*([A-Za-z_]+(?:\[\])?)=', execution)
    return {
        'ExecStart_expected_path_and_argv': bool(prefix and execution.startswith(prefix)),
        'ExecStart_original_prefix_matches': bool(prefix and execution.startswith(prefix + 'ignore_errors=no ;')),
        'ExecStart_field_names': [name if name in known else '<unknown>' for name in fields],
        'ExecStart': prefix + '<manager fields omitted>' if prefix and execution.startswith(prefix) else '<redacted-or-absent>',
    }

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
guest = require_guest(os.environ['MPKG_GUEST_ID'])
trusted_install()
hashes = {
    'docker.service': 'a12d90fd03761bf79659a185c4a2c40e08934d7ada9e05130e64bd5eb4d634aa',
    'docker.socket': '96cd0d89474816ddfb03893b44c36e7d744254aed1bf6d30eca65ff396114656',
    'containerd.service': '7522a4e33c633f22fc0049d3c075b552f7df30cd978acd0175b972bdebc922ea',
}
units = {}
for unit, (_, expected) in UNITS.items():
    unit_path = Path('/usr/lib/systemd/system') / unit
    raw, evidence = read_regular(unit_path)
    if evidence[4] != 0 or evidence[6] & 0o022 or hashlib.sha256(raw).hexdigest() != hashes[unit]:
        raise Refused('diagnostic_packaged_unit_changed')
    observations = {}
    for include_empty in (False, True):
        argv = ['/usr/bin/systemctl', '--no-pager', '--plain', 'show', unit,
                '--property=' + PROPERTIES + ',ControlPID,ControlGroup,Result,ExecMainStatus,TasksCurrent']
        if include_empty:
            argv.append('--all')
        raw = command(argv)
        values = dict(line.split('=', 1) for line in raw.decode().splitlines())
        view = {}
        for key in ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'Result',
                    'MainPID', 'ControlPID', 'ExecMainStatus', 'TasksCurrent', 'LimitCORE'):
            value = values.get(key)
            view[key] = value if value is None or re.fullmatch(r'[a-z0-9-]{0,40}', value) else '<unexpected>'
        for key in ('Environment', 'EnvironmentFiles', 'PassEnvironment'):
            view[key] = {'present': key in values, 'empty': values.get(key) == ''}
        allowed_paths = {'FragmentPath': str(unit_path),
                         'DropInPaths': '/etc/systemd/system/' + unit + '.d/50-mpkg-fixture.conf',
                         'ControlGroup': '/system.slice/' + unit}
        for key, allowed in allowed_paths.items():
            value = values.get(key)
            view[key] = value if value in (None, '', allowed) else '<unexpected>'
        execution = values.get('ExecStart', '')
        view['ExecStart_present'] = 'ExecStart' in values
        # Only the fixed known command may be displayed; no arbitrary tail,
        # unexpected argument or unknown field name is exported.
        view.update(safe_execution(execution, expected))
        try:
            assert_unit(unit, values)
            view['preflight_assertion'] = 'accepted'
        except Refused as error:
            view['preflight_assertion'] = str(error)
        observations['show_all' if include_empty else 'show_default'] = view
    units[unit] = observations

state = Path('/var/lib/mpkg-proofs') / guest / 'docker-readiness'
paths = [state, state / 'state.sqlite3', state / 'result.json',
         Path('/etc/systemd/system/docker.service.d/50-mpkg-fixture.conf'),
         Path('/etc/systemd/system/containerd.service.d/50-mpkg-fixture.conf'),
         Path('/run/docker.sock'), Path('/run/containerd/containerd.sock'),
         Path('/run/docker.pid'), Path('/var/lib/docker'), Path('/var/lib/containerd')]
files = []
for path in paths:
    try:
        info = path.lstat()
    except FileNotFoundError:
        files.append({'path': str(path), 'present': False})
        continue
    kind = ('directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode)
            else 'socket' if stat.S_ISSOCK(info.st_mode) else 'other')
    item = {'path': str(path), 'present': True, 'kind': kind, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode))}
    if kind == 'directory':
        with os.scandir(path) as entries:
            item['empty'] = next(entries, None) is None
    files.append(item)
journal = {'present': (state / 'state.sqlite3').exists()}
if journal['present']:
    info = (state / 'state.sqlite3').lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise Refused('diagnostic_journal_not_private')
    try:
        database = sqlite3.connect((state / 'state.sqlite3').as_uri() + '?mode=ro', uri=True, timeout=1)
        try:
            database.execute('PRAGMA query_only=ON')
            rows = database.execute('SELECT terminal, COUNT(*) FROM attempts GROUP BY terminal').fetchall()
            if len(rows) > 4 or any(value not in (None, 'observed-complete', 'failed', 'unverified') for value, count in rows):
                raise Refused('diagnostic_journal_states_unknown')
            journal['attempt_counts'] = {value or 'unknown': count for value, count in rows}
        finally:
            database.close()
    except sqlite3.Error:
        journal['readable'] = False
processes = []
for process in Path('/proc').iterdir():
    if not process.name.isdigit():
        continue
    try:
        name = (process / 'comm').read_text().strip()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        continue
    if name in ('dockerd', 'containerd', 'containerd-shim', 'runc', 'docker'):
        processes.append({'pid': int(process.name), 'comm': name})
    if len(processes) > 128:
        raise Refused('diagnostic_process_bound')
print(json.dumps({'schema': 1, 'guest_id': guest, 'diagnostic_only': True,
                  'units': units, 'fixed_paths': files, 'journal': journal,
                  'processes': processes, 'docker_api_contacted': False}, sort_keys=True))
PY
