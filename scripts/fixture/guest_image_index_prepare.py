#!/usr/bin/env python3
"""Prepare original OCI index associations from the already acquired guest bytes."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import signal
import sqlite3
import stat
import sys
import tarfile
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Journal, Refused, canonical, identity, read_regular, require_guest, write_new
from docker_ready import (DROPIN, UNITS, assert_unit, check_absent_configuration, package_units,
                          process_identity, properties, socket_identity)
from image_import import validate_acquisition
from native_service import trusted_path
from oci_acquire import IMAGES, LAYERS
from run import ENV, command, trusted_install

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
INPUTS = Path('/opt/mpkg-proof-inputs')
INSPECT = ('{"Id":{{json .Id}},"RepoTags":{{json .RepoTags}},'
           '"RepoDigests":{{json .RepoDigests}},"Os":{{json .Os}},'
           '"Architecture":{{json .Architecture}}}')


def members(tar):
    result = {}
    total = 0
    for member in tar:
        if (len(result) >= 256 or member.name in result or not member.isfile()
                or member.issparse() or member.pax_headers or member.linkname
                or not re.fullmatch(r'(?:index\.json|oci-layout|blobs/sha256/[0-9a-f]{64})', member.name)
                or not 0 <= member.size <= 512*1024**2):
            raise Refused('index_preparation_archive_member_shape')
        total += member.size
        if total > 3*1024**3 + 1048576:
            raise Refused('index_preparation_archive_total_bound')
        result[member.name] = member
    return result


def metadata(tar, entries, name, expected=None):
    entry = entries.get(name)
    if entry is None or entry.size > 1048576:
        raise Refused('index_preparation_metadata_bound')
    with tar.extractfile(entry) as stream:
        raw = stream.read(1048577)
    if len(raw) != entry.size or (expected and hashlib.sha256(raw).hexdigest() != expected):
        raise Refused('index_preparation_metadata_digest')
    return raw, json.loads(raw)


def descriptor(value, media_types):
    if (value.get('mediaType') not in media_types
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(value.get('digest', '')))
            or type(value.get('size')) is not int or not 0 < value['size'] <= 512*1024**2):
        raise Refused('index_preparation_descriptor_shape')
    return 'blobs/sha256/' + value['digest'][7:], value['size']


def plan(tar, entries, acquired, images=IMAGES):
    layout_raw, layout = metadata(tar, entries, 'oci-layout')
    if layout != {'imageLayoutVersion': '1.0.0'}:
        raise Refused('index_preparation_layout_changed')
    old_raw, old = metadata(tar, entries, 'index.json')
    expected_old = []
    selected_indexes = []
    required = {'oci-layout': len(layout_raw), 'index.json': len(old_raw)}
    by_name = {item['fixture_name']: item for item in acquired['images']}
    for name, repository, index_hex, child_hex, config_hex, version in images:
        index_name = 'blobs/sha256/' + index_hex
        index_raw, index = metadata(tar, entries, index_name, index_hex)
        if index.get('schemaVersion') != 2 or index.get('mediaType') != INDEX:
            raise Refused('index_preparation_original_index_shape')
        choices = [item for item in index.get('manifests', [])
                   if item.get('platform', {}).get('os') == 'linux'
                   and item.get('platform', {}).get('architecture') == 'amd64']
        if len(choices) != 1 or choices[0].get('digest') != 'sha256:' + child_hex:
            raise Refused('index_preparation_platform_selection_changed')
        child_name, child_size = descriptor(choices[0], {MANIFEST})
        child_raw, child = metadata(tar, entries, child_name, child_hex)
        if (len(child_raw) != child_size or child.get('schemaVersion') != 2
                or child.get('mediaType') != MANIFEST or len(child.get('layers', [])) > 64):
            raise Refused('index_preparation_child_manifest_shape')
        config_name, config_size = descriptor(child['config'], {CONFIG})
        if config_name != 'blobs/sha256/' + config_hex:
            raise Refused('index_preparation_configuration_identity')
        config_raw, config = metadata(tar, entries, config_name, config_hex)
        if (len(config_raw) != config_size or config.get('os') != 'linux'
                or config.get('architecture') != 'amd64'
                or config.get('config', {}).get('Labels', {}).get('org.opencontainers.image.version') != version):
            raise Refused('index_preparation_platform_or_version')
        records = [child['config'], *child['layers']]
        declared = [{'digest': item['digest'], 'size': item['size'], 'media_type': item['mediaType']}
                    for item in records]
        if by_name[name]['blobs'] != declared:
            raise Refused('index_preparation_acquisition_closure_changed')
        for item in records:
            path, size = descriptor(item, LAYERS | {CONFIG})
            if path in required and required[path] != size:
                raise Refused('index_preparation_conflicting_blob_size')
            required[path] = size
        required[index_name] = len(index_raw)
        required[child_name] = child_size
        annotations = {'org.opencontainers.image.ref.name': 'lscr.io/' + repository + ':mpkg-fixture-' + name,
                       'io.mpkg.source.index.digest': 'sha256:' + index_hex}
        expected_old.append(dict(choices[0], annotations=annotations))
        selected_indexes.append({'mediaType': INDEX, 'digest': 'sha256:' + index_hex,
                                 'size': len(index_raw), 'annotations': annotations})
    expected = {'schemaVersion': 2, 'mediaType': INDEX, 'manifests': expected_old}
    if old != expected or set(entries) != set(required) or any(entries[n].size != size for n, size in required.items()):
        raise Refused('index_preparation_input_scope_changed')
    new_raw = canonical(dict(expected, manifests=selected_indexes))
    return new_raw, {'original_root_index_sha256': hashlib.sha256(old_raw).hexdigest(),
                     'prepared_root_index_sha256': hashlib.sha256(new_raw).hexdigest(),
                     'blob_count': len(required)-2, 'blob_bytes_unchanged': True,
                     'platform': 'linux/amd64', 'original_indexes': selected_indexes}


class HashReader:
    def __init__(self, stream):
        self.stream, self.hash = stream, hashlib.sha256()

    def read(self, size):
        raw = self.stream.read(size)
        self.hash.update(raw)
        return raw


def repack(tar, entries, new_root, output):
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as target:
        for name, member in entries.items():
            entry = tarfile.TarInfo(name)
            entry.mode, entry.uid, entry.gid, entry.mtime = 0o644, 0, 0, 0
            entry.size = len(new_root) if name == 'index.json' else member.size
            if name == 'index.json':
                target.addfile(entry, io.BytesIO(new_root))
                continue
            with tar.extractfile(member) as stream:
                hashed = HashReader(stream)
                target.addfile(entry, hashed)
            if name.startswith('blobs/') and hashed.hash.hexdigest() != name.rsplit('/', 1)[1]:
                raise Refused('index_preparation_blob_digest_changed')


def trusted_json(path):
    trusted_path(path)
    raw, metadata_identity = read_regular(path)
    if len(raw) > 1048576:
        raise Refused('index_preparation_json_bound')
    return json.loads(raw), hashlib.sha256(raw).hexdigest(), metadata_identity


def completed_history(directory, guest, terminal):
    value, digest, _ = trusted_json(directory/'result.json')
    database = directory/'state.sqlite3'
    trusted_path(database)
    database_raw, _ = read_regular(database)
    connection = sqlite3.connect(database.as_uri()+'?mode=ro', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON')
        if (connection.execute('SELECT terminal FROM attempts').fetchall() != [(terminal,)]
                or connection.execute('SELECT kind FROM events ORDER BY seq').fetchall() != [('started',), (terminal,)]
                or connection.execute('SELECT recovery_required FROM store_guard').fetchall() != [(0,)]):
            raise Refused('index_preparation_prior_attempt_not_terminal')
    finally:
        connection.close()
    if value.get('schema') != 1 or value.get('guest_id') != guest:
        raise Refused('index_preparation_prior_identity_changed')
    return value, digest, hashlib.sha256(database_raw).hexdigest()


def main():
    import grp
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    trusted_install()
    os.umask(0o077)
    def expired(*_):
        raise Refused('index_preparation_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(1800)
    root = Path('/var/lib/mpkg-proofs')/guest
    ready, ready_hash, _ = completed_history(root/'docker-readiness', guest, 'observed-complete')
    prior, prior_hash, prior_database_hash = completed_history(root/'image-import', guest, 'unverified')
    acquired, acquisition_hash, _ = trusted_json(INPUTS/'acquisition.json')
    archive = validate_acquisition(acquired)
    expected_refs = ['lscr.io/'+repository+'@sha256:'+index for _, repository, index, _, _, _ in IMAGES]
    if (ready.get('status') != 'observed' or ready.get('enabled_services') is not False
            or prior.get('status') != 'unverified' or prior.get('load_command_completed') is not True
            or prior.get('archive_sha256') != archive['sha256'] or prior.get('verified_associations') != []
            or prior.get('unverified_associations') != expected_refs or prior.get('engine_id') != ready.get('engine_id')):
        raise Refused('index_preparation_prior_load_scope_changed')
    for name in ('compose', 'daemon', 'docker-baseline', 'image-index-preparation'):
        path = root/name
        if path.exists() or path.is_symlink():
            raise Refused('index_preparation_requires_separate_unused_state')
    for path in (INPUTS/'compose.json', Path('/opt/docker')):
        if path.exists() or path.is_symlink():
            raise Refused('index_preparation_application_or_binding_exists')
    client = root/'image-import/docker-client'
    trusted_path(client, directory=True)
    if stat.S_IMODE(client.stat().st_mode) != 0o700 or next(client.iterdir(), None) is not None:
        raise Refused('index_preparation_existing_empty_client_required')
    environment = dict(ENV, DOCKER_CONFIG=str(client))

    def docker(*arguments, timeout=30, pass_fds=()):
        return command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments],
                       env=environment, timeout=timeout, pass_fds=pass_fds)

    engine = docker('info', '--format', '{{.ID}}').decode().strip()
    if engine != ready['engine_id']:
        raise Refused('index_preparation_engine_changed')
    if package_units() != ready['packages_and_units']:
        raise Refused('index_preparation_packaged_units_changed')
    check_absent_configuration()
    observed_units = {unit: properties(unit) for unit in UNITS}
    for unit, observed in observed_units.items():
        assert_unit(unit, observed, started=True)
        if UNITS[unit][1]:
            dropin = Path('/etc/systemd/system')/(unit+'.d')/'50-mpkg-fixture.conf'
            trusted_path(dropin)
            if read_regular(dropin)[0] != DROPIN:
                raise Refused('index_preparation_dropin_changed')
    processes = {unit: process_identity(observed_units[unit], UNITS[unit][1].split()[0])
                 for unit in ('docker.service', 'containerd.service')}
    docker_gid = grp.getgrnam('docker').gr_gid
    bound_socket = socket_identity(docker_gid, processes['docker.service'])
    for operation in (('container', 'ls', '--all', '--quiet'), ('volume', 'ls', '--quiet')):
        if docker(*operation).strip():
            raise Refused('index_preparation_requires_image_only_engine')
    children = {'sha256:'+child for _, _, _, child, _, _ in IMAGES}
    before_ids = set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().splitlines())
    if before_ids != children:
        raise Refused('index_preparation_observed_child_inventory_changed')
    for name, repository, _, child, _, _ in IMAGES:
        image = json.loads(docker('image', 'inspect', '--format', INSPECT, 'sha256:'+child))
        if (image.get('Id') != 'sha256:'+child or image.get('Os') != 'linux' or image.get('Architecture') != 'amd64'
                or image.get('RepoTags') != ['lscr.io/'+repository+':mpkg-fixture-'+name]
                or image.get('RepoDigests') != ['lscr.io/'+repository+'@sha256:'+child]):
            raise Refused('index_preparation_child_associations_changed')
    descriptor_fd = os.open(INPUTS/'images.oci.tar', os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor_fd, 'rb') as original:
        before = os.fstat(original.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size != archive['bytes']):
            raise Refused('index_preparation_source_shape')
        if hashlib.file_digest(original, 'sha256').hexdigest() != archive['sha256']:
            raise Refused('index_preparation_source_digest')
        original.seek(0)
        with tarfile.open(fileobj=original, mode='r:') as tar:
            entries = members(tar)
            new_root, planning = plan(tar, entries, acquired)
            directory = root/'image-index-preparation'
            directory.mkdir(mode=0o700)
            parent_fd = os.open(root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            journal = Journal(directory)
            try:
                attempt = str(uuid.uuid4())
                journal.begin(attempt)
                write_new(directory/'prior-import-result.json', canonical(prior)+b'\n')
                record = dict(planning, schema=1, guest_id=guest, engine_id=engine,
                              source_archive_sha256=archive['sha256'], acquisition_sha256=acquisition_hash,
                              prior_import_result_sha256=prior_hash, prior_import_database_sha256=prior_database_hash,
                              readiness_result_sha256=ready_hash)
                write_new(directory/'started.json', canonical(record)+b'\n')
                output_path = directory/'images.original-indexes.oci.tar'
                fd = os.open(output_path, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w+b') as output:
                    repack(tar, entries, new_root, output)
                    output.flush();os.fsync(output.fileno())
                    output.seek(0)
                    prepared_hash = hashlib.file_digest(output, 'sha256').hexdigest()
                    prepared_size = output.seek(0, os.SEEK_END)
                    output.seek(0)
                    if identity(before) != identity(os.fstat(original.fileno())):
                        raise Refused('index_preparation_source_changed')
                    record.update(prepared_archive_sha256=prepared_hash, prepared_archive_bytes=prepared_size)
                    write_new(directory/'prepared.json', canonical(record)+b'\n')
                    print(json.dumps({'phase':'prepared','sha256':prepared_hash,'bytes':prepared_size}),flush=True)
                    prepared_identity = identity(os.fstat(output.fileno()))
                    load_fd = os.open(output_path, os.O_RDONLY|os.O_NOFOLLOW)
                    try:
                        if identity(os.fstat(load_fd)) != prepared_identity:
                            raise Refused('index_preparation_load_input_changed')
                        docker('image', 'load', '--quiet', '--platform', 'linux/amd64', '--input',
                               '/proc/self/fd/'+str(load_fd), timeout=600, pass_fds=(load_fd,))
                        if identity(os.fstat(load_fd)) != prepared_identity:
                            raise Refused('index_preparation_changed_during_load')
                    finally:
                        os.close(load_fd)
                verified, missing = [], []
                for reference, (_, _, index, _, _, _) in zip(expected_refs, IMAGES):
                    try:
                        image = json.loads(docker('image', 'inspect', '--format', INSPECT, reference))
                    except Refused as error:
                        if str(error) != 'fixed_tool_failed':raise
                        missing.append(reference);continue
                    if (reference not in (image.get('RepoDigests') or []) or image.get('Id') != 'sha256:'+index
                            or image.get('Os') != 'linux' or image.get('Architecture') != 'amd64'):
                        missing.append(reference)
                    else:
                        verified.append({'reference':reference,'image_id':image['Id']})
                after_ids = set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().splitlines())
                indexes = {'sha256:'+index for _, _, index, _, _, _ in IMAGES}
                if (not after_ids <= children|indexes or (not missing and not indexes <= after_ids)
                        or docker('info','--format','{{.ID}}').decode().strip() != engine):
                    raise Refused('index_preparation_unexpected_image_or_engine_drift')
                for unit, original_process in processes.items():
                    observed = properties(unit)
                    assert_unit(unit, observed, started=True)
                    if process_identity(observed, original_process['executable']) != original_process:
                        raise Refused('index_preparation_daemon_changed')
                if socket_identity(docker_gid, processes['docker.service']) != bound_socket:
                    raise Refused('index_preparation_socket_changed')
                for operation in (('container', 'ls', '--all', '--quiet'), ('volume', 'ls', '--quiet')):
                    if docker(*operation).strip():
                        raise Refused('index_preparation_application_state_appeared')
                if identity(before) != identity(os.fstat(original.fileno())):
                    raise Refused('index_preparation_original_archive_changed')
                _, unchanged_hash, unchanged_db = completed_history(root/'image-import', guest, 'unverified')
                if unchanged_hash != prior_hash or unchanged_db != prior_database_hash:
                    raise Refused('index_preparation_original_history_changed')
                result = dict(record, status='unverified' if missing else 'observed',
                              load_command_completed=True, verified_associations=verified,
                              unverified_associations=missing, remaining_original_child_ids=sorted(after_ids & children),
                              observed_image_ids=sorted(after_ids), prior_unverified_import_preserved=True,
                              product_acceptance=False, network_acquisition=False, explicit_tag_operations=False)
                journal.finish(attempt,'unverified' if missing else 'observed-complete')
                write_new(directory/'result.json', canonical(result)+b'\n')
                print(json.dumps(result,sort_keys=True))
                return 75 if missing else 0
            finally:
                journal.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Refused as error:
        print(json.dumps({'status':'refused','code':str(error),'product_acceptance':False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status':'unverified','code':'image_index_preparation_failed','product_acceptance':False}))
        sys.exit(74)
