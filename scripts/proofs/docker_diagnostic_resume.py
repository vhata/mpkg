#!/usr/bin/env python3
"""Activate only the retained incomplete image-preparation guest for diagnosis."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import resource
import sqlite3
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, identity, private_directory, read_regular, require_guest, write_new
from docker_ready import UNITS, package_units, process_identity, socket_identity
from docker_resume import completed_result, no_application_state, quiescent, units, verify_engine
from image_import import validate_acquisition
from native_manifest import trusted_json
from native_service import trusted_path
from oci_acquire import IMAGES
from run import ENV, command, trusted_install


ENGINE = 'bb861e7c-3db2-4b9a-a865-6a2e04af426c'
HASHES = {
    'docker-readiness/result.json': '0a142cace78c678c7a9245c5999d3390f46d9402499d37e796773055c2b2ede3',
    'image-import/result.json': 'bf0dd66235c422b0d942ac5f252cb1ef2a1a057991a4cc61b43106ba66ce22ad',
    'image-import/state.sqlite3': 'ea72fabbf006297db200ef07cab24100710639dd76a6fa6ff744b062c48a5c92',
    'image-index-preparation/started.json': '4ecd77b7b55776f50b5911734cfa6da3964f159c44f0da8e89164eecba516eb9',
    'image-index-preparation/prepared.json': 'c6c8018060341ce5fd38ab13b6f461315a9fcab66a2daa8e21f15e2b3b2a7bfb',
}
PREPARED_SHA256 = '828001d7783098d69a87f84851883dc101da4023050a23c3d084614ca3a19bd3'
SOURCE_SHA256 = 'b7971f3427b643acb69dbe1e792dd105b3e01b4aa6f2e46ec3d7b474a2423aa1'
ARCHIVE_BYTES = 265943040
INSPECT = ('{"Id":{{json .Id}},"RepoTags":{{json .RepoTags}},'
           '"RepoDigests":{{json .RepoDigests}},"Os":{{json .Os}},'
           '"Architecture":{{json .Architecture}}}')


def journal_bytes(directory, terminal):
    path = directory / 'state.sqlite3'
    trusted_path(directory, directory=True)
    info = trusted_path(path)
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise Refused('docker_diagnostic_history_permissions')
    database = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1)
    try:
        database.execute('PRAGMA query_only=ON')
        attempts = database.execute('SELECT id,terminal FROM attempts').fetchall()
        if len(attempts) != 1 or attempts[0][1] != terminal or str(uuid.UUID(attempts[0][0])) != attempts[0][0]:
            raise Refused('docker_diagnostic_prior_history_changed')
        events = [(attempts[0][0], 'started')] + ([(attempts[0][0], terminal)] if terminal else [])
        if (database.execute('SELECT attempt,kind FROM events ORDER BY seq').fetchall() != events
                or database.execute('SELECT COUNT(*) FROM protected').fetchone() != (0,)
                or database.execute('SELECT recovery_required FROM store_guard').fetchall() != [(0,)]):
            raise Refused('docker_diagnostic_prior_history_changed')
    finally:
        database.close()
    return read_regular(path)[0]


def archive_digest(path, wanted):
    trusted_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if before.st_size != ARCHIVE_BYTES or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise Refused('docker_diagnostic_archive_shape')
        if (hashlib.file_digest(stream, 'sha256').hexdigest() != wanted
                or identity(before) != identity(os.fstat(stream.fileno()))):
            raise Refused('docker_diagnostic_archive_changed')


def retained_state(guest):
    root = Path('/var/lib/mpkg-proofs') / guest
    no_application_state(root)
    for path in (Path('/opt/mpkg-proof-inputs/compose.json'), root / 'image-index-preparation/result.json',
                 root / 'docker-diagnostic-activation'):
        if path.exists() or path.is_symlink():
            raise Refused('docker_diagnostic_requires_incomplete_checkpoint')
    evidence = {}
    for relative, expected in HASHES.items():
        trusted_path(root / relative)
        raw = read_regular(root / relative)[0]
        if hashlib.sha256(raw).hexdigest() != expected:
            raise Refused('docker_diagnostic_retained_record_changed')
        evidence[relative] = raw
    ready, ready_hash = completed_result(root / 'docker-readiness', guest)
    if ready_hash != HASHES['docker-readiness/result.json'] or ready.get('engine_id') != ENGINE:
        raise Refused('docker_diagnostic_engine_binding_changed')
    prior = json.loads(evidence['image-import/result.json'])
    expected_refs = ['lscr.io/' + repository + '@sha256:' + index for _, repository, index, _, _, _ in IMAGES]
    if (prior.get('status') != 'unverified' or prior.get('engine_id') != ENGINE
            or prior.get('guest_id') != guest or prior.get('load_command_completed') is not True
            or prior.get('verified_associations') != [] or prior.get('unverified_associations') != expected_refs):
        raise Refused('docker_diagnostic_prior_import_changed')
    imported = journal_bytes(root / 'image-import', 'unverified')
    if imported != evidence['image-import/state.sqlite3']:
        raise Refused('docker_diagnostic_prior_import_database_changed')
    preparation = journal_bytes(root / 'image-index-preparation', None)
    acquired, acquisition_hash = trusted_json('acquisition.json')
    archive = validate_acquisition(acquired)
    if archive['sha256'] != SOURCE_SHA256 or archive['bytes'] != ARCHIVE_BYTES:
        raise Refused('docker_diagnostic_source_archive_changed')
    for relative in ('image-index-preparation/started.json', 'image-index-preparation/prepared.json'):
        record = json.loads(evidence[relative])
        if any(record.get(key) != value for key, value in {
            'schema': 1, 'guest_id': guest, 'engine_id': ENGINE, 'source_archive_sha256': SOURCE_SHA256,
            'acquisition_sha256': acquisition_hash, 'platform': 'linux/amd64',
            'prior_import_result_sha256': HASHES['image-import/result.json'],
            'prior_import_database_sha256': HASHES['image-import/state.sqlite3'],
            'readiness_result_sha256': ready_hash,
        }.items()):
            raise Refused('docker_diagnostic_preparation_binding_changed')
    prepared = json.loads(evidence['image-index-preparation/prepared.json'])
    if prepared.get('prepared_archive_sha256') != PREPARED_SHA256 or prepared.get('prepared_archive_bytes') != ARCHIVE_BYTES:
        raise Refused('docker_diagnostic_prepared_archive_binding_changed')
    archive_digest(Path('/opt/mpkg-proof-inputs/images.oci.tar'), SOURCE_SHA256)
    archive_digest(root / 'image-index-preparation/images.original-indexes.oci.tar', PREPARED_SHA256)
    evidence['image-index-preparation/state.sqlite3'] = preparation
    return root, ready['packages_and_units'], evidence


def validate_child(value, name, repository, child):
    if value != {'Id': 'sha256:' + child, 'Os': 'linux', 'Architecture': 'amd64',
                 'RepoTags': ['lscr.io/' + repository + ':mpkg-fixture-' + name],
                 'RepoDigests': ['lscr.io/' + repository + '@sha256:' + child]}:
        raise Refused('docker_diagnostic_child_inventory_changed')


def activate(guest):
    root, provenance, evidence = retained_state(guest)
    if package_units() != provenance:
        raise Refused('docker_diagnostic_package_units_changed')
    group = grp.getgrnam('docker')
    if group.gr_mem or any(user.pw_gid == group.gr_gid for user in pwd.getpwall()):
        raise Refused('docker_diagnostic_group_not_empty')
    units(provenance, active=False)
    quiescent()
    directory = root / 'docker-diagnostic-activation'
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise Refused('docker_diagnostic_fresh_attempt_required') from None
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    private_directory(directory)
    environment = dict(ENV, DOCKER_CONFIG=str(private_directory(directory / 'docker-client')))
    journal = Journal(directory)
    try:
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        command(['/usr/bin/systemctl', 'start', 'docker.service'], timeout=90)
        observed = units(provenance, active=True)
        processes = {unit: process_identity(observed[unit], UNITS[unit][1].split()[0])
                     for unit in ('docker.service', 'containerd.service')}
        socket = socket_identity(group.gr_gid, processes['docker.service'])

        def docker(*arguments):
            return command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments], env=environment)

        bindings = {name: 'sha256:' + child for name, _, _, child, _, _ in IMAGES}
        verify_engine(json.loads(docker('info', '--format', '{{json .}}')), ENGINE, bindings)
        if docker('container', 'ls', '--all', '--quiet').strip() or docker('volume', 'ls', '--quiet').strip():
            raise Refused('docker_diagnostic_requires_image_only_engine')
        if set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().splitlines()) != set(bindings.values()):
            raise Refused('docker_diagnostic_image_scope_changed')
        images = []
        for name, repository, index, child, _, _ in IMAGES:
            value = json.loads(docker('image', 'inspect', '--format', INSPECT, 'sha256:' + child))
            validate_child(value, name, repository, child)
            try:
                docker('image', 'inspect', '--format', INSPECT, 'lscr.io/' + repository + '@sha256:' + index)
            except Refused as error:
                if str(error) != 'fixed_tool_failed':
                    raise
            else:
                raise Refused('docker_diagnostic_index_state_changed')
            images.append(value)
        networks = [json.loads(line) for line in docker('network', 'ls', '--format', '{{json .}}').splitlines()]
        if len(networks) != 3 or {(item.get('Name'), item.get('Driver'), item.get('Scope')) for item in networks} != {
                ('bridge', 'bridge', 'local'), ('host', 'host', 'local'), ('none', 'null', 'local')}:
            raise Refused('docker_diagnostic_network_scope_changed')
        observed = units(provenance, active=True)
        for unit, original in processes.items():
            if process_identity(observed[unit], original['executable']) != original:
                raise Refused('docker_diagnostic_process_changed')
        if socket_identity(group.gr_gid, processes['docker.service']) != socket:
            raise Refused('docker_diagnostic_socket_changed')
        verify_engine(json.loads(docker('info', '--format', '{{json .}}')), ENGINE, bindings)
        if any(read_regular(root / relative)[0] != raw for relative, raw in evidence.items()):
            raise Refused('docker_diagnostic_retained_history_changed')
        result = {'schema': 1, 'guest_id': guest, 'status': 'unverified', 'diagnostic_status': 'observed',
                  'diagnostic_only': True, 'engine_id': ENGINE, 'child_images': images,
                  'original_index_associations': 'unverified', 'prior_import_remains_unverified': True,
                  'preparation_attempt_remains_unknown': True, 'prior_records_unchanged': True,
                  'prior_record_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in evidence.items()},
                  'source_archive_sha256': SOURCE_SHA256, 'prepared_archive_sha256': PREPARED_SHA256,
                  'containers': 0, 'volumes': 0, 'enabled_services': False, 'processes': processes,
                  'socket': socket, 'product_acceptance': False,
                  'limits': ['Cold diagnostic activation only; no import, repack, pull, tag or retry.',
                             'Original index references remain missing or uninspectable.',
                             'Neither prior attempt is completed by this observation.']}
        write_new(directory / 'result.json', canonical(result) + b'\n')
        journal.finish(attempt, 'observed-complete')
        return result
    finally:
        journal.close()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    print(json.dumps(activate(guest), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'diagnostic_only': True}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'docker_diagnostic_activation_failed', 'diagnostic_only': True}))
        sys.exit(74)
