#!/usr/bin/env python3
"""Use the bound control port for a new, separately recorded OCI preparation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import stat
import sys
import time
import types
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Journal, Refused, canonical, identity, private_directory, require_guest, write_new
from docker_diagnostic_resume import INSPECT, journal_bytes
from native_service import trusted_path
from oci_acquire import IMAGES, publish_bytes
from run import trusted_install

PREPARATION_BASE64 = None
DIAGNOSTIC_BASE64 = None
REPORT_BASE64 = None
REPORT_SHA256 = '2e1ab12cc11766ecbde486cdadbc0ef2c51c10ff6547c17006eb6e891ca9cbd4'
INPUTS = Path('/opt/mpkg-proof-inputs')
SUPPLEMENT = INPUTS/'oci-supplement-offline'
PORT_NAME = 'org.mpkg.fixture.control'
OLD_FILES = {
    'started.json': 'b0d35922ee68f2382888df270677367048e1d8fc18dfa2c506322aa18efe7fcf',
    'state.sqlite3': 'b15a4ace0b0df57bc0ff1881cb0a998a6a624ce955c1dcffdc9aff991964c4ef',
}
STAGE = 'not-started'


def bound_preparation():
    raw = base64.b64decode(PREPARATION_BASE64, validate=True)
    if len(raw) > 32768 or hashlib.sha256(raw).hexdigest() != '9918caedf77ca6d88f1fc0ae0bd337fb74e2a8e974368b1c4a1124d97e96de58':
        raise Refused('offline_preparation_source_changed')
    module = types.ModuleType('bound_attestation_preparation')
    exec(compile(raw, '<reviewed-attestation-preparation>', 'exec'), module.__dict__)
    module.REPORT_SHA256 = REPORT_SHA256
    module.DIAGNOSTIC_BASE64 = DIAGNOSTIC_BASE64
    return module


def failed_acquisition(root, diagnostic):
    directory = root/'image-attestation-preparation'
    trusted_path(directory, directory=True)
    if {p.name for p in directory.iterdir()} != set(OLD_FILES):
        raise Refused('offline_preparation_failed_attempt_shape')
    evidence = {}
    for name, digest in OLD_FILES.items():
        raw = diagnostic.small(directory/name)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise Refused('offline_preparation_failed_attempt_changed')
        evidence['image-attestation-preparation/'+name] = raw
    if journal_bytes(directory, None) != evidence['image-attestation-preparation/state.sqlite3']:
        raise Refused('offline_preparation_failed_journal_changed')
    directory = INPUTS/'oci-supplement'
    for path, names in ((directory, {'blobs'}), (directory/'blobs', {'sha256'}),
                        (directory/'blobs/sha256', set())):
        trusted_path(path, directory=True)
        if {p.name for p in path.iterdir()} != names:
            raise Refused('offline_preparation_partial_metadata_changed')
    return evidence


def open_control():
    directory = Path('/dev/virtio-ports')
    trusted_path(directory, directory=True)
    link = directory/PORT_NAME
    info = link.lstat()
    resolved = link.resolve(strict=True)
    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or resolved.parent != Path('/dev')
            or not re.fullmatch(r'vport[0-9]+p[0-9]+', resolved.name)):
        raise Refused('offline_preparation_control_path')
    port = Path('/sys/class/virtio-ports')/resolved.name
    if (port/'name').read_text() != PORT_NAME+'\n':
        raise Refused('offline_preparation_control_name')
    fd = os.open(resolved, os.O_RDWR|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_NOCTTY)
    try:
        actual = os.fstat(fd)
        device = f'{os.major(actual.st_rdev)}:{os.minor(actual.st_rdev)}\n'
        if (not stat.S_ISCHR(actual.st_mode) or actual.st_uid != 0 or actual.st_mode & 0o002
                or (port/'dev').read_text() != device):
            raise Refused('offline_preparation_control_device')
        return fd
    except BaseException:
        os.close(fd)
        raise


def transfer_remaining(deadline):
    remaining = deadline-time.monotonic()
    if remaining <= 0:
        raise Refused('offline_preparation_transfer_deadline')
    return min(remaining, 0.5)


def write_port(fd, raw, deadline):
    offset = 0
    while offset < len(raw):
        wait = transfer_remaining(deadline)
        if not select.select([], [fd], [], wait)[1]:
            continue
        try:
            count = os.write(fd, raw[offset:offset+65536])
        except BlockingIOError:
            continue
        if count <= 0:
            raise Refused('offline_preparation_transfer_closed')
        offset += count


def read_port(fd, length, deadline):
    if not 0 < length <= 16*1024**2:
        raise Refused('offline_preparation_frame_bound')
    data = bytearray()
    while len(data) < length:
        wait = transfer_remaining(deadline)
        if not select.select([fd], [], [], wait)[0]:
            continue
        try:
            chunk = os.read(fd, min(65536, length-len(data)))
        except BlockingIOError:
            continue
        if not chunk:
            raise Refused('offline_preparation_transfer_closed')
        data.extend(chunk)
    return bytes(data)


def receive_metadata(helper, report, expected, guest, attempt):
    deadline = time.monotonic()+300
    fd = open_control()
    try:
        ready = {'schema': 1, 'guest_id': guest, 'attempt': attempt,
                 'report_sha256': REPORT_SHA256, 'status': 'ready-for-fixed-metadata'}
        write_port(fd, canonical(ready)+b'\n', deadline)
        header = ('MPKG-OCI-SUPPLEMENT/1\n'+guest+'\n'+REPORT_SHA256+'\n').encode()
        if read_port(fd, len(header), deadline) != header:
            raise Refused('offline_preparation_header_changed')
        directory = private_directory(SUPPLEMENT)
        blobs = private_directory(directory/'blobs/sha256')
        acquired = {}
        for digest, descriptor in sorted(expected.items()):
            raw = read_port(fd, descriptor['size'], deadline)
            if ('sha256:'+hashlib.sha256(raw).hexdigest() != digest
                    or not isinstance(json.loads(raw), dict)):
                raise Refused('offline_preparation_blob_changed')
            publish_bytes(blobs, digest, raw)
            acquired[digest] = raw
        if read_port(fd, 4, deadline) != b'END\n':
            raise Refused('offline_preparation_end_frame')
        for record in report['images']:
            helper.manifest_matches(acquired[record['blobs'][0]['digest']], record)
        write_port(fd, canonical(dict(ready, status='metadata-verified', blobs=len(acquired)))+b'\n', deadline)
        return acquired
    finally:
        os.close(fd)


def guarded_offline_load(helper, diagnostic, docker, root, provenance, activation, children, evidence,
                         directory, descriptor, environment):
    failed_acquisition(root, diagnostic)
    return helper.guarded_load(diagnostic, docker, root, provenance, activation, children, evidence,
                               directory, descriptor, environment)


def main():
    global STAGE
    helper = bound_preparation()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    trusted_install()
    os.umask(0o077)
    helper.DEADLINE = time.monotonic()+1800
    signal.signal(signal.SIGALRM, helper.expired)
    signal.alarm(1800)
    diagnostic = helper.bound_diagnostic()
    diagnostic.require_builds_idle()
    report_raw = base64.b64decode(REPORT_BASE64, validate=True)
    report, expected = helper.report_scope(report_raw)
    root, activation, provenance, evidence = diagnostic.prior_evidence(guest)
    helper.old_load_evidence(root, diagnostic, evidence)
    evidence['docker-readiness/state.sqlite3'] = journal_bytes(root/'docker-readiness', 'observed-complete')
    evidence.update(failed_acquisition(root, diagnostic))
    for path in (root/'image-attestation-offline-preparation', SUPPLEMENT):
        if path.exists() or path.is_symlink():
            raise Refused('attestation_preparation_fresh_state_required')
    client = root/'docker-diagnostic-activation/docker-client'
    trusted_path(client, directory=True)
    if stat.S_IMODE(client.stat().st_mode) != 0o700 or next(client.iterdir(), None) is not None:
        raise Refused('attestation_preparation_empty_client_required')
    environment = dict(diagnostic.ENV, DOCKER_CONFIG=str(client))
    def docker(*arguments):
        return diagnostic.command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments],
                                  env=environment, timeout=min(30, helper.remaining()))
    children = {'sha256:'+item[3] for item in IMAGES}
    indexes = {'sha256:'+item[2] for item in IMAGES}
    diagnostic.check_engine(docker, provenance, activation, children, initial=True)
    directory = root/'image-attestation-offline-preparation'
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
                  'prior_prepared_archive_sha256': helper.PREPARED_SHA256, 'root_index_sha256': helper.ROOT_INDEX_SHA256,
                  'supplement_acquisition_sha256': REPORT_SHA256,
                  'prior_record_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in evidence.items()},
                  'prior_import_remains_unverified': True, 'prior_preparation_remains_unknown': True,
                  'product_acceptance': False, 'platform': 'linux/amd64',
                  'prior_metadata_acquisition_remains_unknown': True,
                  'metadata_transport': 'bound-virtio-control-port', 'network_acquisition': False}
        write_new(directory/'started.json', canonical(record)+b'\n')
        STAGE = 'receive-exact-offline-metadata'
        acquired = receive_metadata(helper, report, expected, guest, attempt)
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
                    or hashlib.file_digest(original, 'sha256').hexdigest() != helper.PREPARED_SHA256):
                raise Refused('attestation_preparation_archive_binding')
            original.seek(0)
            archive_path = directory/'images.attestations.oci.tar'
            fd = os.open(archive_path, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w+b') as output:
                original_count, added_count = helper.copy_archive(original, output, report, acquired)
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
                captured = guarded_offline_load(helper, diagnostic, docker, root, provenance, activation, children, evidence,
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
        failed_acquisition(root, diagnostic)
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
        journal.close()
        hashes = {name: hashlib.sha256(diagnostic.small(directory/name)).hexdigest()
                  for name in ('started.json', 'prepared.json', 'capture.json', 'result.json',
                               'state.sqlite3', 'stdout.private', 'stderr.private')}
        print(json.dumps(dict(result, preparation_record_sha256=hashes), sort_keys=True))
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
