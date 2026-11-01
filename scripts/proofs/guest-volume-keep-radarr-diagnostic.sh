#!/usr/bin/env bash
# Fixed read-only Radarr phase observation; never repeats root registration.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I - "$MPKG_GUEST_ID" <<'PY'
import hashlib
import hmac
import json
import os
from pathlib import Path
import resource
import signal
import sqlite3
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, canonical, read_regular, require_guest
from docker_baseline import RADARR_ROOT, preserve_initial_values, xml_values
from docker_diagnostic_resume import ENGINE
from docker_variant_plan import variant_plan
from docker_variants import Variant
from image_import import validate_acquisition
from native_manifest import trusted_json
from native_service import trusted_path
from run import ENV, trusted_install

SOURCE = '3e1f6aae53a17fc86fcb4ca8a1a2a351a5a3eb6c0c4fc4b13b4a25699ef95af8'
JOURNAL = '45444ade45e2cf2e39c43012382c4759001a6022b0623cb3ccdfc200d8abb46f'
ROUTES = (('naming', '/api/v3/config/naming'), ('rootfolders', '/api/v3/rootfolder'))


def response_view(kind, code, raw):
    """Project fixed predicates only, never an application value or body."""
    result = {'http_status': code}
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return result | {'json_type': 'unparseable'}
    shapes = {dict: 'object', list: 'array', str: 'string', int: 'number',
              float: 'number', bool: 'boolean', type(None): 'null'}
    result['json_type'] = shapes.get(type(value), 'other')
    if kind == 'naming' and type(value) is dict:
        result['expected_movie_folder_format'] = value.get('movieFolderFormat') == '{Movie Title} ({Release Year})'
    if kind == 'rootfolders' and type(value) is list:
        if len(value) > 32:
            raise Refused('radarr_diagnostic_list_bound')
        result['count'] = len(value)
        result['all_entries_objects'] = all(type(item) is dict for item in value)
        matching = [item for item in value if type(item) is dict and item.get('path') == str(RADARR_ROOT)]
        result['expected_path_count'] = len(matching)
        result['expected_path_id_positive'] = len(matching) == 1 and type(matching[0].get('id')) is int and matching[0]['id'] > 0
        result['expected_path_accessible'] = len(matching) == 1 and matching[0].get('accessible') is True
    return result


def error_view(error):
    kinds = ('FileNotFoundError', 'PermissionError', 'ProcessLookupError', 'OSError',
             'KeyError', 'TypeError', 'ValueError', 'IndexError', 'AttributeError',
             'JSONDecodeError', 'OperationalError', 'Refused', 'TimeoutError')
    return {'exception_type': type(error).__name__ if type(error).__name__ in kinds else 'other',
            'errno': error.errno if isinstance(error, OSError) and type(error.errno) is int else None}


def main():
    guest = require_guest(sys.argv[1])
    trusted_install()
    if hashlib.sha256(read_regular(Path('/opt/mpkg-proofs/docker_variants.py'))[0]).hexdigest() != SOURCE:
        raise Refused('radarr_diagnostic_source_mismatch')
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
    signal.alarm(120)
    root = Path('/var/lib/mpkg-proofs') / guest / 'docker-variant-volume-keep'
    trusted_path(root, directory=True)
    trusted_path(root / 'docker-client', directory=True)
    if (root / 'baseline.json').exists() or (root / 'baseline.json').is_symlink():
        raise Refused('radarr_diagnostic_partial_state_changed')
    database = root / 'state.sqlite3'
    trusted_path(database)
    raw_database, _ = read_regular(database)
    if (hashlib.sha256(raw_database).hexdigest() != JOURNAL
            or any(Path(str(database) + suffix).exists() for suffix in ('-wal', '-shm', '-journal'))):
        raise Refused('radarr_diagnostic_history_changed')
    protected = root / 'radarr-assembled.xml'
    trusted_path(protected)
    captured_xml, captured_identity = read_regular(protected)
    connection = sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON')
        if (connection.execute('SELECT terminal FROM attempts').fetchall() != [(None,)]
                or connection.execute('SELECT kind FROM events').fetchall() != [('started',)]
                or connection.execute('SELECT COUNT(*) FROM protected').fetchone()[0] != 10):
            raise Refused('radarr_diagnostic_attempt_shape')
        rows = connection.execute('SELECT token FROM protected WHERE bytes=? AND identity=?',
                                  (captured_xml, canonical(captured_identity))).fetchall()
        keys = connection.execute('SELECT key FROM private_key').fetchall()
        if len(rows) != 1 or len(keys) != 1 or not hmac.compare_digest(
                rows[0][0], hmac.digest(keys[0][0], canonical(captured_identity) + captured_xml, 'sha256')):
            raise Refused('radarr_diagnostic_private_input_binding')
    finally:
        connection.close()
    fixture = object.__new__(Variant)
    fixture.guest, fixture.root, fixture.plan = guest, root, variant_plan('volume-keep')
    fixture.specs = fixture.plan['applications']
    fixture.client, fixture.enabled = root / 'docker-client', False
    fixture.environment = dict(ENV, DOCKER_CONFIG=str(fixture.client))
    fixture.image_manifest, _ = trusted_json('compose.json')
    if fixture.image_manifest.get('guest_id') != guest or fixture.image_manifest.get('engine_id') != ENGINE:
        raise Refused('radarr_diagnostic_engine_binding')
    acquired, _ = trusted_json('acquisition.json')
    validate_acquisition(acquired)
    fixture.acquired = {item['repository'] + '@' + item['index_digest']: item for item in acquired['images']}
    fixture.network_id, fixture.image_ids = None, {}
    engine = fixture.engine(enabled=False)
    fixture.image_ids = fixture.images()
    before = fixture.attribution('radarr')
    current_xml, _ = fixture.config_file('radarr', 'config.xml')
    preserve_initial_values(captured_xml, current_xml)
    key = xml_values(captured_xml)['ApiKey']
    if fixture.attribution('radarr') != before:
        raise Refused('radarr_diagnostic_attribution_changed_before_key')
    observations = {}
    for kind, route in ROUTES:
        # No body argument: these two calls are strictly GET observations.
        code, raw = fixture.request('radarr', route, key=key)
        observations[kind] = response_view(kind, code, raw)
        if fixture.attribution('radarr') != before:
            raise Refused('radarr_diagnostic_attribution_changed_after_response')
    if (fixture.engine(enabled=False) != engine or read_regular(database)[0] != raw_database
            or read_regular(protected) != (captured_xml, captured_identity)
            or (root / 'baseline.json').exists() or (root / 'baseline.json').is_symlink()):
        raise Refused('radarr_diagnostic_prior_state_changed')
    signal.alarm(0)
    return {'schema': 1, 'guest_id': guest, 'status': 'observed', 'diagnostic_only': True,
            'source_sha256': SOURCE, 'journal_sha256': JOURNAL, 'engine_id': ENGINE,
            'observations': observations, 'protected_key_bound': True,
            'attribution_unchanged': True, 'prior_records_unchanged': True,
            'requests': 'two-fixed-GETs-only', 'product_acceptance': False,
            'limits': ['Current GET results do not reconstruct the lost original POST response.',
                       'No root-folder registration, setup replay, history repair or completion.']}


try:
    print(json.dumps(main(), sort_keys=True))
except Exception as error:
    print(json.dumps({'status': 'unverified', 'code': 'volume_radarr_diagnostic_failed',
                      'error': error_view(error), 'product_acceptance': False}, sort_keys=True))
    sys.exit(73)
PY
