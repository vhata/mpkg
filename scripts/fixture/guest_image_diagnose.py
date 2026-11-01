#!/usr/bin/env python3
"""Read bounded local image identities without importing, tagging or pulling."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
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
              'limits': ['Only local image identity/list/association reads were requested.',
                         'No image configuration, environment, labels or raw tool errors are emitted.',
                         'No import, pull, tag, container or association repair was requested.']}
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
