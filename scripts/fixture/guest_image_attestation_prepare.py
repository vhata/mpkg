#!/usr/bin/env python3
"""Add exact attestation metadata to a separate OCI archive and preparation."""
import base64
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
import tarfile
import time
import types
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Journal, Refused, canonical, identity, private_directory, read_regular, require_guest, write_new
from docker_diagnostic_resume import INSPECT, journal_bytes
from native_service import trusted_path
from oci_acquire import IMAGES, Registry, descriptor, publish_bytes
from run import trusted_install

REPORT_BASE64 = None  # Filled only by the fixed reviewed host transport.
REPORT_SHA256 = None
DIAGNOSTIC_BASE64 = None
DIAGNOSTIC_SHA256 = '544abfde7e82e03b75625a28a1d868b2ebf04c088d9ce1faf8a6c72a6ffb4e36'
PREPARED_SHA256 = '828001d7783098d69a87f84851883dc101da4023050a23c3d084614ca3a19bd3'
ROOT_INDEX_SHA256 = '5d7f4116edc95dbdfbda27b9961228b26b4a8bd2fc4b7dc5dcba5404cedfc4b0'
ERROR_SHA256 = '3c15efd23ab2fa788fd8aa890f35ea386e0118fb267e7abdbae7042099979350'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
EMPTY = 'application/vnd.oci.empty.v1+json'
ATTESTATION = 'application/vnd.in-toto+json'
INPUTS = Path('/opt/mpkg-proof-inputs')
SUPPLEMENT = INPUTS/'oci-supplement'
MAX_TOTAL = 32*1024**2
DEADLINE = 0
STAGE = 'not-started'


def remaining():
    seconds = DEADLINE-time.monotonic()
    if seconds <= 0:
        raise Refused('attestation_preparation_deadline')
    return seconds


def expired(*_):
    raise Refused('attestation_preparation_deadline')


class BoundedRegistry(Registry):
    def transfer(self, url, headers, sink, limit, seconds):
        try:
            return super().transfer(url, headers, sink, limit, min(seconds, remaining()))
        finally:
            signal.signal(signal.SIGALRM, expired)
            signal.alarm(max(1, math.ceil(remaining())))


def bound_diagnostic():
    raw = base64.b64decode(DIAGNOSTIC_BASE64, validate=True)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != DIAGNOSTIC_SHA256:
        raise Refused('attestation_preparation_diagnostic_module_changed')
    module = types.ModuleType('bound_image_load_diagnostic')
    exec(compile(raw, '<reviewed-image-load-diagnostic>', 'exec'), module.__dict__)
    return module


def report_scope(raw):
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != REPORT_SHA256:
        raise Refused('attestation_preparation_report_digest')
    report = json.loads(raw)
    if (report.get('schema') != 1 or report.get('source_archive_sha256') !=
            'b7971f3427b643acb69dbe1e792dd105b3e01b4aa6f2e46ec3d7b474a2423aa1'
            or report.get('source_archive_bytes') != 265943040
            or report.get('docker_or_runtime_operations') is not False
            or len(report.get('images', [])) != len(IMAGES)):
        raise Refused('attestation_preparation_report_scope')
    total, expected = 0, {}
    for record, (name, repository, index, child, _, _) in zip(report['images'], IMAGES):
        if any(record.get(key) != value for key, value in {
            'fixture_name': name, 'repository': repository,
            'original_index_digest': 'sha256:'+index, 'selected_child_digest': 'sha256:'+child,
        }.items()):
            raise Refused('attestation_preparation_image_binding')
        attestation = record['attestation_descriptor']
        manifest_digest, manifest_size = descriptor(attestation, {MANIFEST}, 65536)
        if (attestation.get('platform') != {'architecture': 'unknown', 'os': 'unknown'}
                or attestation.get('annotations', {}).get('vnd.docker.reference.type') != 'attestation-manifest'
                or attestation.get('annotations', {}).get('vnd.docker.reference.digest') != 'sha256:'+child
                or not 3 <= len(record.get('blobs', [])) <= 10
                or record['blobs'][0] != {'digest': manifest_digest, 'size': manifest_size, 'mediaType': MANIFEST}):
            raise Refused('attestation_preparation_auxiliary_scope')
        for number, blob in enumerate(record['blobs']):
            media = {MANIFEST} if number == 0 else {CONFIG, EMPTY} if number == 1 else {ATTESTATION}
            digest, size = descriptor(blob, media, 65536 if number <= 1 else 16*1024**2)
            total += size
            if digest in expected and expected[digest] != blob:
                raise Refused('attestation_preparation_conflicting_descriptor')
            expected[digest] = blob
    if total > MAX_TOTAL or report.get('descriptor_bytes_total') != total:
        raise Refused('attestation_preparation_metadata_size_bound')
    return report, expected


def manifest_matches(raw, record):
    value = json.loads(raw)
    if value.get('schemaVersion') != 2 or value.get('mediaType') != MANIFEST:
        raise Refused('attestation_preparation_manifest_schema')
    normalized = [{k: item[k] for k in ('digest', 'size', 'mediaType')}
                  for item in [value['config'], *value['layers']]]
    if normalized != record['blobs'][1:]:
        raise Refused('attestation_preparation_manifest_closure')
    config = value['config']
    if config['mediaType'] == EMPTY and (value.get('artifactType') != 'application/vnd.docker.attestation.manifest.v1+json'
            or config.get('digest') != 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'
            or config.get('size') != 2 or config.get('data') != 'e30='):
        raise Refused('attestation_preparation_inline_config')


def acquire_metadata(report, expected):
    registry = BoundedRegistry()
    directory = private_directory(SUPPLEMENT)
    blobs = private_directory(directory/'blobs/sha256')
    acquired = {}
    for record in report['images']:
        repository = record['repository']
        for number, blob in enumerate(record['blobs']):
            digest, size = blob['digest'], blob['size']
            if digest in acquired:
                continue
            if number == 0:
                raw, _ = registry.manifest(repository, digest)
                manifest_matches(raw, record)
            elif blob['mediaType'] == EMPTY:
                raw = b'{}'
            else:
                sink = io.BytesIO()
                registry.transfer('https://lscr.io/v2/'+repository+'/blobs/'+digest,
                                  registry.headers(repository), sink, size, 120)
                raw = sink.getvalue()
            if (len(raw) != size or 'sha256:'+hashlib.sha256(raw).hexdigest() != digest
                    or not isinstance(json.loads(raw), dict)):
                raise Refused('attestation_preparation_metadata_bytes')
            publish_bytes(blobs, digest, raw)
            acquired[digest] = raw
    if set(acquired) != set(expected):
        raise Refused('attestation_preparation_metadata_incomplete')
    return acquired


def copy_archive(original, output, report, acquired):
    """Copy verified regular members only; add exact metadata blobs without extraction."""
    declared = {item['digest']: item for image in report['images'] for item in image['blobs']}
    if set(acquired) != set(declared) or any(
            len(raw) != declared[digest]['size'] or 'sha256:'+hashlib.sha256(raw).hexdigest() != digest
            for digest, raw in acquired.items()):
        raise Refused('attestation_preparation_copy_scope')
    with tarfile.open(fileobj=original, mode='r:') as source:
        members = {}
        for member in source:
            if (len(members) >= 256 or member.name in members or not member.isfile()
                    or member.issparse() or member.pax_headers or member.linkname
                    or not re.fullmatch(r'(?:index\.json|oci-layout|blobs/sha256/[0-9a-f]{64})', member.name)
                    or not 0 <= member.size <= 512*1024**2):
                raise Refused('attestation_preparation_archive_member')
            members[member.name] = member
        root = members.get('index.json')
        if root is None or root.size > 65536:
            raise Refused('attestation_preparation_root_index')
        with source.extractfile(root) as stream:
            if hashlib.sha256(stream.read()).hexdigest() != ROOT_INDEX_SHA256:
                raise Refused('attestation_preparation_root_index_changed')
        for record in report['images']:
            member = members.get('blobs/sha256/'+record['original_index_digest'][7:])
            if member is None or member.size > 65536:
                raise Refused('attestation_preparation_original_index_missing')
            with source.extractfile(member) as stream:
                raw = stream.read()
            if 'sha256:'+hashlib.sha256(raw).hexdigest() != record['original_index_digest']:
                raise Refused('attestation_preparation_original_index_changed')
            if record['attestation_descriptor'] not in json.loads(raw).get('manifests', []):
                raise Refused('attestation_preparation_index_reference_changed')
        if any('blobs/sha256/'+digest[7:] in members for digest in acquired):
            raise Refused('attestation_preparation_metadata_would_replace_member')
        with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as target:
            for name, member in members.items():
                entry = tarfile.TarInfo(name)
                entry.mode, entry.uid, entry.gid, entry.mtime, entry.size = 0o644, 0, 0, 0, member.size
                with source.extractfile(member) as stream:
                    target.addfile(entry, stream)
            for digest, raw in sorted(acquired.items()):
                entry = tarfile.TarInfo('blobs/sha256/'+digest[7:])
                entry.mode, entry.uid, entry.gid, entry.mtime, entry.size = 0o644, 0, 0, 0, len(raw)
                target.addfile(entry, io.BytesIO(raw))
    return len(members), len(acquired)


def old_load_evidence(root, diagnostic, evidence):
    directory = root/'image-index-load-diagnostic'
    result = json.loads(diagnostic.small(directory/'result.json'))
    if (result.get('status') != 'unverified' or result.get('attempt_terminal') != 'unverified'
            or result.get('prior_records_unchanged') is not True
            or result.get('capture', {}).get('capture_status') != 'exited'
            or result['capture'].get('client_exit_code') != 1
            or result['capture']['output']['stderr'] != {'file': 'stderr.private', 'bytes': 182, 'sha256': ERROR_SHA256}
            or result.get('observed_image_ids') != sorted('sha256:'+item[3] for item in IMAGES)):
        raise Refused('attestation_preparation_prior_diagnostic_changed')
    for relative in ('started.json', 'capture.json', 'result.json', 'stderr.private', 'stdout.private'):
        key = 'image-index-load-diagnostic/'+relative
        evidence[key] = diagnostic.small(root/key)
    evidence['image-index-load-diagnostic/state.sqlite3'] = journal_bytes(directory, 'unverified')
    if (hashlib.sha256(evidence['image-index-load-diagnostic/stderr.private']).hexdigest() != ERROR_SHA256
            or any(result['prior_record_sha256'].get(name) != hashlib.sha256(raw).hexdigest()
                   for name, raw in evidence.items() if not name.startswith('image-index-load-diagnostic/'))):
        raise Refused('attestation_preparation_history_chain_changed')


def guarded_load(diagnostic, docker, root, provenance, activation, children, evidence,
                 directory, descriptor, environment):
    # Acquisition and archive construction can take minutes. Revalidate at
    # the actual mutation boundary, not only before that preparatory work.
    diagnostic.require_builds_idle()
    diagnostic.check_engine(docker, provenance, activation, children, initial=True)
    if any(diagnostic.small(root/name) != raw for name, raw in evidence.items()):
        raise Refused('attestation_preparation_prior_history_drift_before_load')
    return diagnostic.capture_load(directory, descriptor, environment, timeout=min(600, remaining()))


def main():
    global DEADLINE, STAGE
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    trusted_install()
    os.umask(0o077)
    DEADLINE = time.monotonic()+1800
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(1800)
    diagnostic = bound_diagnostic()
    diagnostic.require_builds_idle()
    report_raw = base64.b64decode(REPORT_BASE64, validate=True)
    report, expected = report_scope(report_raw)
    root, activation, provenance, evidence = diagnostic.prior_evidence(guest)
    old_load_evidence(root, diagnostic, evidence)
    evidence['docker-readiness/state.sqlite3'] = journal_bytes(root/'docker-readiness', 'observed-complete')
    for path in (root/'image-attestation-preparation', SUPPLEMENT):
        if path.exists() or path.is_symlink():
            raise Refused('attestation_preparation_fresh_state_required')
    client = root/'docker-diagnostic-activation/docker-client'
    trusted_path(client, directory=True)
    if stat.S_IMODE(client.stat().st_mode) != 0o700 or next(client.iterdir(), None) is not None:
        raise Refused('attestation_preparation_empty_client_required')
    environment = dict(diagnostic.ENV, DOCKER_CONFIG=str(client))
    def docker(*arguments):
        return diagnostic.command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments],
                                  env=environment, timeout=min(30, remaining()))
    children = {'sha256:'+item[3] for item in IMAGES}
    indexes = {'sha256:'+item[2] for item in IMAGES}
    diagnostic.check_engine(docker, provenance, activation, children, initial=True)
    directory = root/'image-attestation-preparation'
    directory.mkdir(mode=0o700)
    parent = os.open(root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    journal = Journal(directory)
    try:
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        record = {'schema': 1, 'guest_id': guest, 'attempt': attempt, 'engine_id': diagnostic.ENGINE,
                  'original_source_archive_sha256': diagnostic.SOURCE_SHA256,
                  'original_acquisition_sha256': hashlib.sha256(diagnostic.small(INPUTS/'acquisition.json')).hexdigest(),
                  'prior_prepared_archive_sha256': PREPARED_SHA256, 'root_index_sha256': ROOT_INDEX_SHA256,
                  'supplement_acquisition_sha256': REPORT_SHA256,
                  'prior_record_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in evidence.items()},
                  'prior_import_remains_unverified': True, 'prior_preparation_remains_unknown': True,
                  'product_acceptance': False, 'platform': 'linux/amd64'}
        write_new(directory/'started.json', canonical(record)+b'\n')
        STAGE = 'acquire-exact-metadata'
        acquired = acquire_metadata(report, expected)
        record.update(guest_metadata_acquired_and_verified=True, guest_metadata_blob_count=len(acquired))
        write_new(SUPPLEMENT/'acquisition.json', report_raw)
        STAGE = 'build-supplemented-archive'
        path = root/'image-index-preparation/images.original-indexes.oci.tar'
        trusted_path(path)
        source_fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(source_fd, 'rb') as original:
            before = os.fstat(source_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                    or before.st_mode & 0o022 or before.st_size != 265943040 or before.st_nlink != 1
                    or hashlib.file_digest(original, 'sha256').hexdigest() != PREPARED_SHA256):
                raise Refused('attestation_preparation_archive_binding')
            original.seek(0)
            archive_path = directory/'images.attestations.oci.tar'
            fd = os.open(archive_path, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w+b') as output:
                original_count, added_count = copy_archive(original, output, report, acquired)
                output.flush();os.fsync(output.fileno());output.seek(0)
                digest = hashlib.file_digest(output, 'sha256').hexdigest()
                size = output.seek(0, os.SEEK_END)
                published_identity = identity(os.fstat(output.fileno()))
                if identity(before) != identity(os.fstat(source_fd)):
                    raise Refused('attestation_preparation_original_archive_drift')
            record.update(supplemented_archive_sha256=digest, supplemented_archive_bytes=size,
                          original_archive_members=original_count, added_metadata_blobs=added_count,
                          supplemental_metadata=report['images'])
            write_new(directory/'prepared.json', canonical(record)+b'\n')
            STAGE = 'load-supplemented-archive'
            load_fd = os.open(archive_path, os.O_RDONLY|os.O_NOFOLLOW)
            try:
                before_load = identity(os.fstat(load_fd))
                if before_load != published_identity:
                    raise Refused('attestation_preparation_published_archive_changed')
                captured = guarded_load(diagnostic, docker, root, provenance, activation, children, evidence,
                                        directory, load_fd, environment)
                if identity(os.fstat(load_fd)) != before_load:
                    raise Refused('attestation_preparation_load_archive_drift')
            finally:
                os.close(load_fd)
        write_new(directory/'capture.json', canonical(captured)+b'\n')
        record.update(capture=captured, error_summary=diagnostic.error_summary(diagnostic.small(directory/'stderr.private')))
        if any(diagnostic.small(root/name) != raw for name, raw in evidence.items()):
            raise Refused('attestation_preparation_prior_history_drift')
        if not captured['command_completed']:
            write_new(directory/'result.json', canonical(dict(record, status='unverified', attempt_terminal='unknown'))+b'\n')
            print(json.dumps({'status': 'unverified', 'stage': STAGE, 'attempt_terminal': 'unknown'}))
            return 75
        STAGE = 'observe-original-index-associations'
        ids = set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().splitlines())
        if not ids <= indexes|children:
            raise Refused('attestation_preparation_unexpected_image')
        diagnostic.check_engine(docker, provenance, activation, ids, initial=False)
        verified, missing, index_images, retained = [], [], [], []
        for name, repository, index, child, config, version in IMAGES:
            reference = 'lscr.io/'+repository+'@sha256:'+index
            try:
                view = json.loads(docker('image', 'inspect', '--format', INSPECT, reference))
                label = json.loads(docker('image', 'inspect', '--format',
                    '{{json (index .Config.Labels "org.opencontainers.image.version")}}', reference))
            except Refused as error:
                if str(error) != 'fixed_tool_failed':
                    raise
                missing.append(reference)
                continue
            if (view.get('Id') != 'sha256:'+index or view.get('Os') != 'linux'
                    or view.get('Architecture') != 'amd64' or label != version
                    or view.get('RepoTags') != ['lscr.io/'+repository+':mpkg-fixture-'+name]
                    or view.get('RepoDigests') != [reference]):
                raise Refused('attestation_preparation_original_association_changed')
            index_images.append(view)
            verified.append({'reference': reference, 'image_id': view['Id'], 'index_digest': 'sha256:'+index,
                             'manifest_digest': 'sha256:'+child, 'config_digest': 'sha256:'+config,
                             'platform': 'linux/amd64', 'version_label': label})
        for name, repository, _, child, _, _ in IMAGES:
            if 'sha256:'+child not in ids:
                continue
            view = json.loads(docker('image', 'inspect', '--format', INSPECT, 'sha256:'+child))
            if (view.get('Id') != 'sha256:'+child or view.get('Os') != 'linux' or view.get('Architecture') != 'amd64'
                    or view.get('RepoTags') not in (None, [], ['lscr.io/'+repository+':mpkg-fixture-'+name])
                    or view.get('RepoDigests') not in (None, [], ['lscr.io/'+repository+'@sha256:'+child])):
                raise Refused('attestation_preparation_retained_child_drift')
            retained.append(view)
        diagnostic.check_engine(docker, provenance, activation, ids, initial=False)
        if any(diagnostic.small(root/name) != raw for name, raw in evidence.items()):
            raise Refused('attestation_preparation_prior_history_drift')
        success = captured['client_exit_code'] == 0 and not missing and indexes <= ids
        result = dict(record, status='observed' if success else 'unverified',
                      attempt_terminal='observed-complete' if success else 'unverified',
                      load_command_completed=captured['client_exit_code'] == 0,
                      verified_associations=verified, unverified_associations=missing,
                      observed_image_ids=sorted(ids), observed_index_images=index_images,
                      retained_child_images=retained, prior_records_unchanged=True,
                      filesystem_layers_acquired=False, explicit_tag_operations=False)
        write_new(directory/'result.json', canonical(result)+b'\n')
        journal.finish(attempt, result['attempt_terminal'])
        print(json.dumps(result, sort_keys=True))
        return 0 if success else 75
    finally:
        journal.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        code = str(error) if isinstance(error, Refused) and re.fullmatch('[a-z0-9_]{1,96}', str(error)) else 'attestation_preparation_failed'
        print(json.dumps({'status': 'unverified', 'stage': STAGE, 'code': code,
                          'exception_type': type(error).__name__, 'product_acceptance': False}))
        sys.exit(74)
