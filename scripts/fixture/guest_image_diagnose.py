#!/usr/bin/env python3
"""Read bounded local image identities without importing, tagging or pulling."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sqlite3
import stat
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, read_regular, require_guest
from native_service import trusted_path
from oci_acquire import IMAGES
from run import ENV, command, trusted_install

FORMAT = ('{"Id":{{json .Id}},"RepoTags":{{json .RepoTags}},'
          '"RepoDigests":{{json .RepoDigests}},"Os":{{json .Os}},'
          '"Architecture":{{json .Architecture}}}')


def identity_view(value):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', str(value.get('Id', ''))):
        raise Refused('image_diagnostic_id_shape')
    result = {'Id': value['Id']}
    for key in ('RepoTags', 'RepoDigests'):
        entries = value.get(key) or []
        if (not isinstance(entries, list) or len(entries) > 16
                or any(not isinstance(item, str) or len(item) > 256
                       or not re.fullmatch(r'[A-Za-z0-9_./:@-]+', item) for item in entries)):
            raise Refused('image_diagnostic_reference_shape')
        result[key] = entries
    for key in ('Os', 'Architecture'):
        if not isinstance(value.get(key), str) or not re.fullmatch(r'[a-z0-9_-]{1,32}', value[key]):
            raise Refused('image_diagnostic_platform_shape')
        result[key] = value[key]
    return result


def expected_queries():
    return [{'fixture_name': name, 'kind': kind, 'reference': reference}
            for name, repository, index, _, config, _ in IMAGES
            for kind, reference in (('repository-index', 'lscr.io/' + repository + '@sha256:' + index),
                                    ('config-digest', 'sha256:' + config))]


def completed_record(path, guest, allowed_status):
    trusted_path(path)
    raw, _ = read_regular(path)
    if len(raw) > 65536:
        raise Refused('image_diagnostic_record_bound')
    value = json.loads(raw)
    if (value.get('schema') != 1 or value.get('guest_id') != guest
            or value.get('status') not in allowed_status):
        raise Refused('image_diagnostic_record_binding')
    return value, hashlib.sha256(raw).hexdigest()


def preparation_evidence(root, guest):
    directory = root/'image-index-preparation'
    if not directory.exists():
        return {'present': False}
    trusted_path(directory, directory=True)
    result = {'present': True, 'fixed_command_stderr_retained': False, 'records': {}}
    allowed = ('schema', 'guest_id', 'engine_id', 'source_archive_sha256',
               'prepared_archive_sha256', 'prepared_archive_bytes', 'original_root_index_sha256',
               'prepared_root_index_sha256', 'platform', 'status', 'load_command_completed',
               'prior_import_result_sha256', 'prior_import_database_sha256')
    for name in ('started.json', 'prepared.json', 'result.json'):
        path = directory/name
        if not path.exists():
            result['records'][name] = {'present': False}
            continue
        trusted_path(path)
        raw, _ = read_regular(path)
        value = json.loads(raw)
        if len(raw) > 65536 or value.get('schema') != 1 or value.get('guest_id') != guest:
            raise Refused('image_diagnostic_preparation_record_binding')
        result['records'][name] = {'present': True, 'sha256': hashlib.sha256(raw).hexdigest(),
                                   'fields': {key: value[key] for key in allowed if key in value}}
    database = directory/'state.sqlite3'
    trusted_path(database)
    connection = sqlite3.connect(database.as_uri()+'?mode=ro', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON')
        result['journal'] = {
            'attempt_counts': dict(connection.execute("SELECT COALESCE(terminal,'unknown'),COUNT(*) FROM attempts GROUP BY terminal")),
            'event_counts': dict(connection.execute('SELECT kind,COUNT(*) FROM events GROUP BY kind')),
            'protected_count': connection.execute('SELECT COUNT(*) FROM protected').fetchone()[0],
            'recovery_required': [row[0] for row in connection.execute('SELECT recovery_required FROM store_guard')],
        }
    finally:
        connection.close()
    return result


def daemon_error_summary(raw):
    if len(raw) > 65536:
        raise Refused('image_diagnostic_daemon_journal_bound')
    matches = []
    for line in raw.splitlines():
        entry = json.loads(line)
        message = entry.get('MESSAGE', '')
        if not isinstance(message, str):
            continue
        lower = message.lower()
        codes = []
        for code, words in (
            ('missing_content_digest', ('content digest', 'not found')),
            ('import_failure', ('failed to import',)),
            ('missing_requested_platform', ('requested platform', 'not found')),
            ('missing_path', ('no such file or directory',)),
            ('permission_denied', ('permission denied',)),
            ('unexpected_eof', ('unexpected eof',)),
            ('invalid_argument', ('invalid argument',)),
        ):
            if all(word in lower for word in words):
                codes.append(code)
        if codes:
            matches.append({'categories': codes,
                'content_digest_candidates': sorted(set(re.findall(r'\bsha256:[0-9a-f]{64}\b', message)))[:3],
                'realtime_microseconds': entry.get('__REALTIME_TIMESTAMP')
                if str(entry.get('__REALTIME_TIMESTAMP', '')).isdecimal() else None})
    return {'status': 'observed', 'matching_events': len(matches), 'events': matches[-8:],
            'raw_messages_emitted': False, 'matching_events_omitted': max(0, len(matches)-8)}


def docker_client_processes():
    result = []
    seen = 0
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        seen += 1
        if seen > 4096:
            raise Refused('image_diagnostic_process_scan_bound')
        try:
            with (process/'comm').open() as stream:
                comm = stream.read(65).strip()
            if comm == 'docker':
                result.append({'pid': int(process.name), 'comm': comm})
        except (FileNotFoundError, ProcessLookupError):
            continue
    if len(result) > 32:
        raise Refused('image_diagnostic_client_process_bound')
    return result


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    trusted_install()
    root = Path('/var/lib/mpkg-proofs') / guest
    readiness, ready_sha = completed_record(root/'docker-readiness/result.json', guest, {'observed'})
    imported, import_sha = completed_record(root/'image-import/result.json', guest, {'observed', 'unverified'})
    client = root/'image-import/docker-client'
    trusted_path(client, directory=True)
    if stat.S_IMODE(client.stat().st_mode) != 0o700 or next(client.iterdir(), None) is not None:
        raise Refused('image_diagnostic_requires_existing_empty_client')
    environment = dict(ENV, DOCKER_CONFIG=str(client))
    preparation = preparation_evidence(root, guest)
    clients = docker_client_processes()
    try:
        daemon = daemon_error_summary(command(['/usr/bin/journalctl', '--unit=docker.service',
            '--no-pager', '--output=json', '--lines=60'], env=ENV, timeout=15))
    except Refused:
        daemon = {'status': 'unavailable', 'raw_messages_emitted': False}
    deadline = time.monotonic() + 120

    def docker(*arguments):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refused('image_diagnostic_deadline')
        raw = command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments],
                      env=environment, timeout=min(10, remaining))
        if len(raw) > 65536:
            raise Refused('image_diagnostic_output_bound')
        return raw

    engine = docker('info', '--format', '{{.ID}}').decode().strip()
    if (not re.fullmatch(r'[a-zA-Z0-9:-]{1,256}', engine)
            or readiness.get('engine_id') != engine or imported.get('engine_id') != engine):
        raise Refused('image_diagnostic_engine_mismatch')
    ids = sorted(set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().splitlines()))
    if len(ids) > 16 or any(not re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in ids):
        raise Refused('image_diagnostic_inventory_bound')
    observations = []
    for query in ([{'kind': 'listed-id', 'reference': value} for value in ids] + expected_queries()):
        try:
            raw = docker('image', 'inspect', '--format', FORMAT, query['reference'])
        except Refused as error:
            if str(error) != 'fixed_tool_failed':
                raise
            observations.append(dict(query, status='missing-or-uninspectable'))
            continue
        observations.append(dict(query, status='observed', image=identity_view(json.loads(raw))))
    if docker('info', '--format', '{{.ID}}').decode().strip() != engine:
        raise Refused('image_diagnostic_engine_changed')
    result = {'schema': 1, 'guest_id': guest, 'engine_id': engine,
              'diagnostic_only': True, 'read_only': True, 'listed_image_ids': ids,
              'readiness_sha256': ready_sha, 'import_result_sha256': import_sha,
              'import_status': imported['status'], 'observations': observations,
              'index_preparation': preparation, 'docker_client_processes': clients,
              'recent_daemon_error_categories': daemon,
              'limits': ['Only local image identity/list/association reads were requested.',
                         'No image configuration, environment, labels or raw tool errors are emitted.',
                         'No import, pull, tag, container or association repair was requested.',
                         'The preparation command helper discarded stderr; this cannot recover the original tool error.',
                         'Daemon categories summarize recent messages without attributing them to a specific load.',
                         'Absent client processes do not prove daemon work stopped.']}
    output = json.dumps(result, sort_keys=True)
    if len(output.encode()) > 15000:
        raise Refused('image_diagnostic_combined_output_bound')
    print(output)


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'diagnostic_only': True}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'failed', 'code': 'image_diagnostic_failed', 'diagnostic_only': True}))
        sys.exit(74)
