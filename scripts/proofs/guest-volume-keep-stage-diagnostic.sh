#!/usr/bin/env bash
# Read-only phase observations for the corrected, failed volume-keep attempt.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I - "$MPKG_GUEST_ID" <<'PY'
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import signal
import sqlite3
import stat
import sys
import time

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, read_regular, require_guest
from docker_baseline import SHARED, SENTINEL, read_as_application
from docker_diagnostic_resume import ENGINE
from docker_variant_plan import VOLUME, variant_plan
from docker_variants import Variant
from image_import import validate_acquisition
from native_manifest import trusted_json
from native_service import trusted_path
from run import ENV, command, trusted_install

VARIANT_SHA = '3e1f6aae53a17fc86fcb4ca8a1a2a351a5a3eb6c0c4fc4b13b4a25699ef95af8'
FORMAT = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
          '"Project":{{json (index .Config.Labels "com.docker.compose.project")}},'
          '"Service":{{json (index .Config.Labels "com.docker.compose.service")}},'
          '"Status":{{json .State.Status}},"Running":{{json .State.Running}},'
          '"Pid":{{json .State.Pid}},"ExitCode":{{json .State.ExitCode}},'
          '"StartedAt":{{json .State.StartedAt}}}')
SAFE_TYPES = ('FileNotFoundError', 'PermissionError', 'ProcessLookupError', 'OSError',
              'KeyError', 'TypeError', 'ValueError', 'IndexError', 'AttributeError',
              'JSONDecodeError', 'OperationalError', 'Refused')
SAFE_FILES = ('docker_variants.py', 'docker_baseline.py', 'core.py', 'run.py',
              'docker_ready.py', 'service_environment.py', 'native_service.py')


def error_view(error):
    kind = type(error).__name__
    result = {'exception_type': kind if kind in SAFE_TYPES else 'other',
              'errno': error.errno if isinstance(error, OSError) and type(error.errno) is int else None}
    frames, frame = [], error.__traceback__
    while frame is not None:
        code = frame.tb_frame.f_code
        path = Path(code.co_filename)
        if (str(path.parent) == '/opt/mpkg-proofs' and path.name in SAFE_FILES
                and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', code.co_name)):
            frames.append({'source': path.name, 'function': code.co_name, 'line': frame.tb_lineno})
        frame = frame.tb_next
    result['fixed_source_frames'] = frames[-12:]
    return result


def metadata(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'present': False}
    return {'present': True, 'regular': stat.S_ISREG(info.st_mode),
            'directory': stat.S_ISDIR(info.st_mode), 'symlink': stat.S_ISLNK(info.st_mode),
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode)),
            'bytes': info.st_size}


def main():
    guest = require_guest(sys.argv[1])
    trusted_install()
    source, _ = read_regular(Path('/opt/mpkg-proofs/docker_variants.py'))
    if hashlib.sha256(source).hexdigest() != VARIANT_SHA:
        raise Refused('stage_diagnostic_source_mismatch')
    deadline = time.monotonic() + 120
    def expired(*unused):
        raise TimeoutError()
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(120)
    root = Path('/var/lib/mpkg-proofs') / guest / 'docker-variant-volume-keep'
    trusted_path(root, directory=True)
    trusted_path(root / 'docker-client', directory=True)
    environment = dict(ENV, DOCKER_CONFIG=str(root / 'docker-client'))
    def docker(*arguments):
        return command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments],
                       env=environment, timeout=15)
    if docker('info', '--format', '{{.ID}}').decode().strip() != ENGINE:
        raise Refused('stage_diagnostic_engine_mismatch')
    snapshots, files = {}, {}
    for name in ('state.sqlite3', 'baseline.json', 'sonarr-rendered.json', 'radarr-rendered.json',
                 'sonarr-assembled.xml', 'radarr-assembled.xml', 'sonarr-seed', 'radarr-seed'):
        path = root / name
        files[name] = metadata(path)
        if name in ('state.sqlite3', 'baseline.json') and files[name]['present']:
            trusted_path(path)
            raw, _ = read_regular(path)
            snapshots[path] = raw
            files[name]['sha256'] = hashlib.sha256(raw).hexdigest()
    database = root / 'state.sqlite3'
    if any(Path(str(database) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')):
        raise Refused('stage_diagnostic_journal_sidecar')
    connection = sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON')
        attempts = connection.execute('SELECT terminal,COUNT(*) FROM attempts GROUP BY terminal').fetchall()
        events = connection.execute('SELECT kind,COUNT(*) FROM events GROUP BY kind').fetchall()
        if any(name not in (None, 'observed-complete', 'failed', 'unverified') for name, _ in attempts) or any(
                name not in ('started', 'observed-complete', 'failed', 'unverified') for name, _ in events):
            raise Refused('stage_diagnostic_journal_shape')
        journal = {'attempts': {name or 'unknown': count for name, count in attempts}, 'events': dict(events),
                   'protected_count': connection.execute('SELECT COUNT(*) FROM protected').fetchone()[0],
                   'sha256': files['state.sqlite3']['sha256']}
    finally:
        connection.close()
    baseline = json.loads(snapshots[root / 'baseline.json']) if root / 'baseline.json' in snapshots else None
    if baseline is not None and (baseline.get('guest_id') != guest or baseline.get('schema') != 1
                                or baseline.get('plan') != variant_plan('volume-keep')):
        raise Refused('stage_diagnostic_baseline_shape')
    accounts = {}
    for name in ('compose', 'media'):
        try:
            group = grp.getgrnam(name)
            accounts[name + '_group'] = {'present': True, 'gid': group.gr_gid}
        except KeyError:
            accounts[name + '_group'] = {'present': False}
    try:
        user = pwd.getpwnam('compose')
        accounts['compose_user'] = {'present': True, 'uid': user.pw_uid, 'gid': user.pw_gid,
                                    'home_matches': user.pw_dir == '/opt/docker'}
    except KeyError:
        accounts['compose_user'] = {'present': False}
    for role in ('sonarr', 'radarr'):
        for name in ('', 'compose.yaml', '.env', 'config', 'config/config.xml'):
            files[role + '/' + name] = metadata(Path('/opt/docker') / role / name)
    enabled = command(['/usr/bin/systemctl', 'show', '--property=UnitFileState', '--value',
                       'docker.service'], env=ENV).strip()
    if enabled not in (b'enabled', b'disabled'):
        raise Refused('stage_diagnostic_enablement_shape')
    # Construct only a read-only method receiver, never Variant/Journal __init__.
    fixture = object.__new__(Variant)
    fixture.guest, fixture.root, fixture.plan = guest, root, variant_plan('volume-keep')
    fixture.specs, fixture.environment = fixture.plan['applications'], environment
    fixture.client, fixture.enabled = root / 'docker-client', enabled == b'enabled'
    fixture.image_manifest, _ = trusted_json('compose.json')
    acquired, _ = trusted_json('acquisition.json')
    validate_acquisition(acquired)
    fixture.acquired = {item['repository'] + '@' + item['index_digest']: item for item in acquired['images']}
    fixture.network_id, fixture.image_ids = None, {}
    stages = {}
    def probe(name, operation):
        try:
            value = operation()
            stages[name] = {'query_succeeded': True}
            return value
        except Exception as error:
            if time.monotonic() >= deadline:
                raise
            stages[name] = {'query_succeeded': False, **error_view(error)}
            return None
    probe('engine_and_units', lambda: fixture.engine(enabled=fixture.enabled))
    images = probe('images', fixture.images)
    if images is not None:
        fixture.image_ids = images
    identifiers = docker('ps', '--all', '--quiet', '--no-trunc').decode().splitlines()
    if len(identifiers) > 3 or any(re.fullmatch('[0-9a-f]{64}', item) is None for item in identifiers):
        raise Refused('stage_diagnostic_container_bound')
    expected = {'/' + 'mpkg-fixture-volume-keep-volume-init': 'initializer'}
    containers = []
    for identifier in identifiers:
        value = json.loads(docker('inspect', '--format', FORMAT, identifier))
        role = next((role for role, spec in fixture.specs.items()
                     if value['Project'] == spec['project'] and value['Service'] == role), None)
        if role is None:
            role = expected.get(value['Name'])
        if role is None:
            raise Refused('stage_diagnostic_container_outside_scope')
        containers.append({key: value[key] for key in ('Id', 'Image', 'Status', 'Running', 'Pid', 'ExitCode', 'StartedAt')} | {'role': role})
        if role == 'initializer':
            raw = docker('logs', identifier)
            stages['initializer_metadata_stdout'] = {'exact_expected': raw == b'963:1001:2770\n', 'bytes': len(raw)}
    for role in fixture.specs:
        if images is None:
            break
        container = probe(role + '_container', lambda: fixture.container(role))
        if container is None or not container['State']['Running']:
            continue
        credentials = probe(role + '_attribution', lambda: fixture.attribution(role))
        if credentials is None:
            continue
        stages[role + '_attribution']['credentials'] = {key: credentials[key] for key in ('uid_slots', 'gid_slots', 'groups')}
        probe(role + '_config_access', lambda: fixture.config_access(role))
        probe(role + '_shared_sentinel', lambda: read_as_application(SHARED / 'sentinel',
              ('mpkg fixture ' + guest + ' shared\n').encode(), credentials))
        probe(role + '_media_sentinel', lambda: read_as_application(SENTINEL / 'sentinel',
              ('mpkg fixture ' + guest + ' media\n').encode(), credentials))
        probe(role + '_attribution_recheck', lambda: fixture.attribution(role))
    resources = probe('resource_inventory', fixture.objects) if images is not None else None
    if resources is not None and baseline is not None:
        stages['resource_inventory']['matches_recorded'] = resources == baseline['resources']
    if (docker('info', '--format', '{{.ID}}').decode().strip() != ENGINE
            or any(read_regular(path)[0] != raw for path, raw in snapshots.items())):
        raise Refused('stage_diagnostic_prior_records_changed')
    signal.alarm(0)
    print(json.dumps({'schema': 1, 'guest_id': guest, 'status': 'observed', 'diagnostic_only': True,
                      'engine_id': ENGINE, 'source_sha256': VARIANT_SHA, 'journal': journal,
                      'files': files, 'accounts': accounts, 'containers': containers,
                      'docker_enabled': enabled == b'enabled', 'stages': stages,
                      'prior_records_unchanged': True, 'application_requests': False,
                      'xml_contents_read': False, 'product_acceptance': False,
                      'limits': ['Current read-only predicates cannot reconstruct a lost exception.',
                                 'No setup/check replay, state repair or old-attempt completion.']}, sort_keys=True))


try:
    main()
except Exception as error:
    print(json.dumps({'status': 'unverified', 'code': 'volume_stage_diagnostic_failed',
                      'error': error_view(error), 'product_acceptance': False}, sort_keys=True))
    sys.exit(73)
PY
