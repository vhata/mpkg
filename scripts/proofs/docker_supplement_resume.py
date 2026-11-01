#!/usr/bin/env python3
"""Resume a separately observed, supplemented image-only guest checkpoint."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import stat
import sys
import tarfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, identity, private_directory, read_regular, require_guest, write_new
from docker_diagnostic_resume import (ARCHIVE_BYTES, ENGINE, HASHES, INSPECT, PREPARED_SHA256,
                                      SOURCE_SHA256, journal_bytes)
from docker_ready import UNITS, package_units, process_identity, socket_identity
from docker_resume import completed_result, no_application_state, quiescent, units, verify_engine
from image_import import validate_acquisition
from native_manifest import trusted_json
from native_service import trusted_path
from oci_acquire import IMAGES
from run import ENV, command, trusted_install


# These pins can be filled only from the coordinator's successful observed
# preparation and subsequent original image_manifest output. No CLI/env bypass.
OBSERVED = None
PREPARATION = 'image-attestation-preparation'
ROOT_INDEX_SHA256 = '5d7f4116edc95dbdfbda27b9961228b26b4a8bd2fc4b7dc5dcba5404cedfc4b0'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIGS = {'application/vnd.oci.image.config.v1+json', 'application/vnd.oci.empty.v1+json'}
ATTESTATION = 'application/vnd.in-toto+json'
MAX_AUXILIARY = 32 * 1024 ** 2
HISTORIES = {'docker-readiness': 'observed-complete', 'image-import': 'unverified',
             'image-index-preparation': None, 'docker-diagnostic-activation': 'observed-complete',
             'image-index-load-diagnostic': 'unverified'}
PRIOR_FILES = ({name + '/state.sqlite3' for name in HISTORIES}
               | {name + '/result.json' for name in HISTORIES if name != 'image-index-preparation'}
               | {'image-index-preparation/started.json', 'image-index-preparation/prepared.json'}
               | {'image-index-load-diagnostic/' + name for name in
                  ('started.json', 'capture.json', 'stdout.private', 'stderr.private')})
PREPARATION_FILES = ('started.json', 'prepared.json', 'capture.json', 'result.json',
                     'state.sqlite3', 'stdout.private', 'stderr.private')


def actual_pins():
    if (not isinstance(OBSERVED, dict) or set(OBSERVED) != {'result', 'journal', 'compose'}
            or any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) for value in OBSERVED.values())):
        raise Refused('docker_supplement_successful_runtime_evidence_pending')
    return OBSERVED


def descriptor(value, media_types, limit):
    if (not isinstance(value, dict) or value.get('mediaType') not in media_types
            or not re.fullmatch('sha256:[0-9a-f]{64}', value.get('digest', ''))
            or type(value.get('size')) is not int or not 0 < value['size'] <= limit):
        raise Refused('docker_supplement_descriptor_shape')
    return {'digest': value['digest'], 'size': value['size'], 'mediaType': value['mediaType']}


def supplement_records(report):
    if (report.get('schema') != 1 or report.get('source_archive_sha256') != SOURCE_SHA256
            or report.get('source_archive_bytes') != ARCHIVE_BYTES
            or report.get('docker_or_runtime_operations') is not False
            or report.get('registry_signatures_verified') is not False):
        raise Refused('docker_supplement_acquisition_source_changed')
    images = report.get('images', [])
    by_name = {item.get('fixture_name'): item for item in images}
    if len(images) != len(IMAGES) or set(by_name) != {item[0] for item in IMAGES}:
        raise Refused('docker_supplement_acquisition_image_scope')
    records, total = {}, 0
    for name, repository, index, child, _, _ in IMAGES:
        image = by_name[name]
        attestation = image.get('attestation_descriptor')
        selected = descriptor(attestation, {MANIFEST}, 65536)
        if (image.get('repository') != repository or image.get('original_index_digest') != 'sha256:' + index
                or image.get('selected_child_digest') != 'sha256:' + child
                or attestation.get('platform') != {'architecture': 'unknown', 'os': 'unknown'}
                or attestation.get('annotations', {}).get('vnd.docker.reference.type') != 'attestation-manifest'
                or attestation.get('annotations', {}).get('vnd.docker.reference.digest') != 'sha256:' + child):
            raise Refused('docker_supplement_selected_attestation_changed')
        blobs = image.get('blobs', [])
        if not 3 <= len(blobs) <= 10 or blobs[0] != selected:
            raise Refused('docker_supplement_auxiliary_closure_shape')
        for position, blob in enumerate(blobs):
            allowed = {MANIFEST} if position == 0 else CONFIGS if position == 1 else {ATTESTATION}
            bound = 65536 if position <= 1 else 16 * 1024 ** 2
            clean = descriptor(blob, allowed, bound)
            if clean != blob or (clean['digest'] in records and records[clean['digest']] != clean):
                raise Refused('docker_supplement_auxiliary_descriptor_conflict')
            records[clean['digest']] = clean
            total += clean['size']
    if total != report.get('descriptor_bytes_total') or total > MAX_AUXILIARY:
        raise Refused('docker_supplement_auxiliary_total_changed')
    return by_name, records


def bound_file(path, expected_digest, expected_size):
    trusted_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != expected_size
                or not 0 < expected_size <= ARCHIVE_BYTES + MAX_AUXILIARY + 1048576
                or not re.fullmatch('[0-9a-f]{64}', expected_digest)):
            raise Refused('docker_supplement_file_shape')
        if (hashlib.file_digest(stream, 'sha256').hexdigest() != expected_digest
                or identity(before) != identity(os.fstat(stream.fileno()))):
            raise Refused('docker_supplement_file_changed')
    return identity(before)


def archive_members(path, *, expected=None, metadata_names=()):
    """Hash regular members without extracting or decompressing image layers."""
    members, metadata = {}, {}
    with tarfile.open(path, 'r:') as archive:
        for member in archive:
            if (len(members) >= 512 or member.name in members or not member.isfile() or member.issparse()
                    or member.pax_headers or member.linkname or not 0 < member.size <= 3 * 1024 ** 3
                    or (member.name not in ('index.json', 'oci-layout')
                        and not re.fullmatch('blobs/sha256/[0-9a-f]{64}', member.name))):
                raise Refused('docker_supplement_archive_member_scope')
            if expected is not None and expected.get(member.name) != member.size:
                raise Refused('docker_supplement_archive_extra_or_resized_member')
            digest = hashlib.sha256()
            pieces = []
            with archive.extractfile(member) as stream:
                remaining = member.size
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise Refused('docker_supplement_archive_short_member')
                    remaining -= len(chunk)
                    digest.update(chunk)
                    if member.name in metadata_names:
                        if member.size > 65536:
                            raise Refused('docker_supplement_archive_metadata_bound')
                        pieces.append(chunk)
            if member.name.startswith('blobs/') and digest.hexdigest() != member.name.rsplit('/', 1)[1]:
                raise Refused('docker_supplement_archive_blob_digest_changed')
            members[member.name] = member.size
            if member.name in metadata_names:
                metadata[member.name] = b''.join(pieces)
        if expected is not None and members != expected:
            raise Refused('docker_supplement_archive_missing_member')
    return members, metadata


def verify_archive_provenance(root, result, report):
    by_name, records = supplement_records(report)
    source = Path('/opt/mpkg-proof-inputs/images.oci.tar')
    prior = root / 'image-index-preparation/images.original-indexes.oci.tar'
    supplemented = root / PREPARATION / 'images.attestations.oci.tar'
    large = {source: bound_file(source, SOURCE_SHA256, ARCHIVE_BYTES),
             prior: bound_file(prior, PREPARED_SHA256, ARCHIVE_BYTES),
             supplemented: bound_file(supplemented, result['supplemented_archive_sha256'], result['supplemented_archive_bytes'])}
    original, _ = archive_members(prior)
    expected = dict(original)
    for digest, record in records.items():
        path = 'blobs/sha256/' + digest[7:]
        if path in expected and expected[path] != record['size']:
            raise Refused('docker_supplement_existing_blob_size_changed')
        expected[path] = record['size']
    selected = {'index.json', 'oci-layout'} | {'blobs/sha256/' + image[2] for image in IMAGES}
    selected |= {'blobs/sha256/' + image['attestation_descriptor']['digest'][7:] for image in by_name.values()}
    _, contents = archive_members(supplemented, expected=expected, metadata_names=selected)
    if (hashlib.sha256(contents['index.json']).hexdigest() != ROOT_INDEX_SHA256
            or json.loads(contents['oci-layout']) != {'imageLayoutVersion': '1.0.0'}):
        raise Refused('docker_supplement_original_index_layout_changed')
    for name, _, index, child, _, _ in IMAGES:
        original_index = json.loads(contents['blobs/sha256/' + index])
        matches = [item for item in original_index['manifests']
                   if item.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest'
                   and item.get('annotations', {}).get('vnd.docker.reference.digest') == 'sha256:' + child]
        item = by_name[name]
        if matches != [item['attestation_descriptor']]:
            raise Refused('docker_supplement_index_derived_attestation_changed')
        manifest = json.loads(contents['blobs/sha256/' + matches[0]['digest'][7:]])
        if manifest.get('schemaVersion') != 2 or manifest.get('mediaType') != MANIFEST:
            raise Refused('docker_supplement_attestation_manifest_shape')
        actual = [descriptor(manifest.get('config'), CONFIGS, 65536)]
        if manifest['config']['mediaType'] == 'application/vnd.oci.empty.v1+json':
            config = manifest['config']
            if (manifest.get('artifactType') != 'application/vnd.docker.attestation.manifest.v1+json'
                    or config.get('digest') != 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'
                    or config.get('size') != 2 or config.get('data') != 'e30='):
                raise Refused('docker_supplement_embedded_empty_config_changed')
        actual += [descriptor(layer, {ATTESTATION}, 16 * 1024 ** 2) for layer in manifest.get('layers', [])]
        if actual != item['blobs'][1:]:
            raise Refused('docker_supplement_attestation_closure_changed')
    if any(identity(path.lstat()) != before for path, before in large.items()):
        raise Refused('docker_supplement_archives_changed_during_validation')
    return large


def image_inventory(result):
    indexes = {'sha256:' + index for _, _, index, _, _, _ in IMAGES}
    children = {'sha256:' + child for _, _, _, child, _, _ in IMAGES}
    views = result.get('observed_index_images', []) + result.get('retained_child_images', [])
    by_id = {item.get('Id'): item for item in views}
    if (len(by_id) != len(views) or set(by_id) != set(result.get('observed_image_ids', []))
            or len(result.get('observed_image_ids', [])) != len(by_id)
            or not indexes <= set(by_id) <= indexes | children
            or {item.get('Id') for item in result.get('observed_index_images', [])} != indexes
            or not {item.get('Id') for item in result.get('retained_child_images', [])} <= children):
        raise Refused('docker_supplement_observed_inventory_scope')
    identities = {'sha256:' + digest: ('lscr.io/' + repository + ':mpkg-fixture-' + name,
                                      'lscr.io/' + repository + '@sha256:' + digest)
                  for name, repository, index, child, _, _ in IMAGES for digest in (index, child)}
    seen_tags = set()
    for value in views:
        tag, digest = identities[value['Id']]
        if (set(value) != {'Id', 'RepoTags', 'RepoDigests', 'Os', 'Architecture'}
                or value['Os'] != 'linux' or value['Architecture'] != 'amd64'
                or not isinstance(value['RepoTags'], (list, type(None)))
                or not isinstance(value['RepoDigests'], (list, type(None)))
                or not set(value['RepoTags'] or []) <= {tag}
                or not set(value['RepoDigests'] or []) <= {digest}
                or seen_tags.intersection(value['RepoTags'] or [])):
            raise Refused('docker_supplement_inventory_identity_shape')
        seen_tags.update(value['RepoTags'] or [])
    associations = result.get('verified_associations', [])
    expected = []
    for name, repository, index, child, config, version in IMAGES:
        reference = 'lscr.io/' + repository + '@sha256:' + index
        expected.append({'reference': reference, 'image_id': 'sha256:' + index,
                         'index_digest': 'sha256:' + index, 'manifest_digest': 'sha256:' + child,
                         'config_digest': 'sha256:' + config, 'platform': 'linux/amd64', 'version_label': version})
        if reference not in (by_id['sha256:' + index]['RepoDigests'] or []):
            raise Refused('docker_supplement_original_association_missing')
    if associations != expected or result.get('unverified_associations') != []:
        raise Refused('docker_supplement_verified_associations_changed')
    return by_id


def preparation_evidence(guest):
    pins = actual_pins()
    root = Path('/var/lib/mpkg-proofs') / guest
    no_application_state(root)
    if ((root / 'image-index-preparation/result.json').exists()
            or (root / 'image-index-preparation/result.json').is_symlink()
            or any(root.glob('docker-variant-*')) or any(root.glob('docker-experiment-*'))
            or any(root.glob('docker-retirement-*'))):
        raise Refused('docker_supplement_requires_image_only_history')
    directory = root / 'docker-supplement-resume'
    if directory.exists() or directory.is_symlink():
        raise Refused('docker_supplement_fresh_resume_required')
    result, result_digest = completed_result(root / PREPARATION, guest)
    database = journal_bytes(root / PREPARATION, 'observed-complete')
    if result_digest != pins['result'] or hashlib.sha256(database).hexdigest() != pins['journal']:
        raise Refused('docker_supplement_unaccepted_runtime_result')
    if (result.get('engine_id') != ENGINE or result.get('load_command_completed') is not True
            or result.get('original_source_archive_sha256') != SOURCE_SHA256
            or result.get('prior_prepared_archive_sha256') != PREPARED_SHA256
            or result.get('filesystem_layers_acquired') is not False
            or result.get('guest_metadata_acquired_and_verified') is not True
            or result.get('explicit_tag_operations') is not False):
        raise Refused('docker_supplement_successful_preparation_required')
    captured = result.get('capture', {})
    if (captured.get('capture_status') != 'exited' or captured.get('command_completed') is not True
            or captured.get('client_exit_code') != 0):
        raise Refused('docker_supplement_load_completion_unverified')
    evidence = {}
    prior = result.get('prior_record_sha256', {})
    if set(prior) != PRIOR_FILES or any(prior.get(path) != digest for path, digest in HASHES.items()):
        raise Refused('docker_supplement_prior_record_scope_changed')
    for path in sorted(PRIOR_FILES):
        trusted_path(root / path)
        raw = read_regular(root / path)[0]
        if hashlib.sha256(raw).hexdigest() != prior[path]:
            raise Refused('docker_supplement_prior_record_changed')
        evidence[root / path] = raw
    for name, terminal in HISTORIES.items():
        if journal_bytes(root / name, terminal) != evidence[root / name / 'state.sqlite3']:
            raise Refused('docker_supplement_prior_database_changed')
    for filename in PREPARATION_FILES:
        path = root / PREPARATION / filename
        trusted_path(path)
        evidence[path] = read_regular(path)[0]
    if json.loads(evidence[root / PREPARATION / 'capture.json']) != captured:
        raise Refused('docker_supplement_capture_changed')
    for stream in ('stdout', 'stderr'):
        record = captured.get('output', {}).get(stream, {})
        raw = evidence[root / PREPARATION / (stream + '.private')]
        if (record.get('file') != stream + '.private' or record.get('bytes') != len(raw)
                or record.get('sha256') != hashlib.sha256(raw).hexdigest()):
            raise Refused('docker_supplement_capture_bytes_changed')
    readiness = json.loads(evidence[root / 'docker-readiness/result.json'])
    if (readiness.get('status') != 'observed' or readiness.get('engine_id') != ENGINE
            or readiness.get('enabled_services') is not False or readiness.get('guest_id') != guest):
        raise Refused('docker_supplement_readiness_binding_changed')
    acquisition, acquisition_digest = trusted_json('acquisition.json')
    validate_acquisition(acquisition)
    if acquisition_digest != result.get('original_acquisition_sha256'):
        raise Refused('docker_supplement_original_acquisition_changed')
    supplement_path = Path('/opt/mpkg-proof-inputs/oci-supplement/acquisition.json')
    trusted_path(supplement_path)
    supplement_raw = read_regular(supplement_path)[0]
    if hashlib.sha256(supplement_raw).hexdigest() != result.get('supplement_acquisition_sha256'):
        raise Refused('docker_supplement_acquisition_changed')
    evidence[supplement_path] = supplement_raw
    evidence[Path('/opt/mpkg-proof-inputs/acquisition.json')] = read_regular(Path('/opt/mpkg-proof-inputs/acquisition.json'))[0]
    images = image_inventory(result)
    large = verify_archive_provenance(root, result, json.loads(supplement_raw))
    compose, compose_digest = trusted_json('compose.json')
    expected = [{'reference': 'lscr.io/' + repository + '@sha256:' + index, 'image_id': 'sha256:' + index,
                 'platform': 'linux/amd64'} for name, repository, index, _, _, _ in IMAGES if name != 'sonarr-older']
    if (compose_digest != pins['compose'] or compose != {'schema': 1, 'guest_id': guest, 'engine_id': ENGINE, 'images': expected}):
        raise Refused('docker_supplement_compose_manifest_changed')
    evidence[Path('/opt/mpkg-proof-inputs/compose.json')] = read_regular(Path('/opt/mpkg-proof-inputs/compose.json'))[0]
    return root, readiness['packages_and_units'], images, evidence, large


def resume(guest):
    root, provenance, inventory, evidence, large = preparation_evidence(guest)
    if package_units() != provenance:
        raise Refused('docker_supplement_packaged_units_changed')
    group = grp.getgrnam('docker')
    if group.gr_mem or any(user.pw_gid == group.gr_gid for user in pwd.getpwall()):
        raise Refused('docker_supplement_docker_group_not_empty')
    units(provenance, active=False)
    quiescent()
    evidence_unchanged(evidence, large)
    directory = root / 'docker-supplement-resume'
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise Refused('docker_supplement_fresh_resume_required') from None
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

        bindings = {key: key for key in inventory}
        verify_engine(json.loads(docker('info', '--format', '{{json .}}')), ENGINE, bindings)
        if (docker('container', 'ls', '--all', '--quiet').strip() or docker('volume', 'ls', '--quiet').strip()
                or set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().splitlines()) != set(inventory)):
            raise Refused('docker_supplement_image_only_inventory_changed')
        for identifier, expected in inventory.items():
            value = json.loads(docker('image', 'inspect', '--format', INSPECT, identifier))
            if value != expected:
                raise Refused('docker_supplement_recorded_image_identity_changed')
        for _, repository, index, _, _, version in IMAGES:
            reference = 'lscr.io/' + repository + '@sha256:' + index
            value = json.loads(docker('image', 'inspect', '--format', INSPECT, reference))
            if value != inventory['sha256:' + index]:
                raise Refused('docker_supplement_original_index_association_changed')
            label = docker('image', 'inspect', '--format', '{{json (index .Config.Labels "org.opencontainers.image.version")}}', reference)
            if json.loads(label) != version:
                raise Refused('docker_supplement_image_version_changed')
        networks = [json.loads(line) for line in docker('network', 'ls', '--format', '{{json .}}').splitlines()]
        if len(networks) != 3 or {(item.get('Name'), item.get('Driver'), item.get('Scope')) for item in networks} != {
                ('bridge', 'bridge', 'local'), ('host', 'host', 'local'), ('none', 'null', 'local')}:
            raise Refused('docker_supplement_default_networks_changed')
        observed = units(provenance, active=True)
        for unit, original in processes.items():
            if process_identity(observed[unit], original['executable']) != original:
                raise Refused('docker_supplement_daemon_changed_during_resume')
        if socket_identity(group.gr_gid, processes['docker.service']) != socket:
            raise Refused('docker_supplement_socket_changed_during_resume')
        verify_engine(json.loads(docker('info', '--format', '{{json .}}')), ENGINE, bindings)
        evidence_unchanged(evidence, large)
        result = {'schema': 1, 'guest_id': guest, 'status': 'observed', 'engine_id': ENGINE,
                  'image_inventory': inventory, 'enabled_services': False, 'containers': 0, 'volumes': 0,
                  'default_networks_only': True, 'processes': processes, 'socket': socket,
                  'prior_record_sha256': {str(path): hashlib.sha256(raw).hexdigest() for path, raw in evidence.items()},
                  'prior_records_unchanged': True, 'product_acceptance': False,
                  'limits': ['Resume of the accepted supplemented image-only checkpoint only.',
                             'No load, pull, retag, removal, application startup or repair.',
                             'Earlier UNKNOWN/unverified histories remain unchanged.',
                             'Any uncertain startup blocks repeat invocation; no cleanup or retry.']}
        write_new(directory / 'result.json', canonical(result) + b'\n')
        journal.finish(attempt, 'observed-complete')
        return result
    finally:
        journal.close()


def evidence_unchanged(evidence, large):
    if (any(read_regular(path)[0] != raw for path, raw in evidence.items())
            or any(identity(path.lstat()) != before for path, before in large.items())):
        raise Refused('docker_supplement_prior_evidence_changed')


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    print(json.dumps(resume(guest), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'docker_supplement_resume_failed', 'product_acceptance': False}))
        sys.exit(74)
