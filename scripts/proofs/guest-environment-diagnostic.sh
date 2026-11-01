#!/usr/bin/env bash
# Read typed environment-file counts from fixed local systemd service objects.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I - <<'PY'
import json
import os
import re
import resource
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, require_guest
from run import command, trusted_install

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
guest = require_guest(os.environ['MPKG_GUEST_ID'])
trusted_install()
units = {'docker.service': 'docker_2eservice', 'containerd.service': 'containerd_2eservice',
         'sshd.service': 'sshd_2eservice'}
results = {}
for unit, object_name in units.items():
    loaded = command(['/usr/bin/systemctl', 'show', unit, '--property=LoadState', '--value']).strip()
    if loaded != b'loaded':
        results[unit] = {'loaded': False, 'query_attempted': False}
        continue
    try:
        raw = command(['/usr/bin/busctl', '--system', '--no-pager', '--timeout=10s', 'get-property',
                       'org.freedesktop.systemd1', '/org/freedesktop/systemd1/unit/' + object_name,
                       'org.freedesktop.systemd1.Service', 'EnvironmentFiles'], timeout=15).strip()
    except Refused:
        results[unit] = {'loaded': True, 'query_succeeded': False}
        continue
    match = re.match(rb'^a\(sb\) ([0-9]+)(?:\s|$)', raw)
    results[unit] = {'loaded': True, 'query_succeeded': True,
                     'expected_type': match is not None,
                     'declared_count': int(match[1]) if match is not None else None,
                     'exact_empty_response': raw == b'a(sb) 0'}
print(json.dumps({'schema': 1, 'guest_id': guest, 'diagnostic_only': True,
                  'environment_files': results, 'service_mutation': False}, sort_keys=True))
PY
