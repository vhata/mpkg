#!/usr/bin/env python3
"""Run one separate local image-load diagnostic and retain bounded private errors."""
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Journal, Refused, canonical, identity, private_directory, read_regular, require_guest, write_new
from docker_diagnostic_resume import (ARCHIVE_BYTES, ENGINE, HASHES, INSPECT, PREPARED_SHA256,
                                      SOURCE_SHA256, journal_bytes, validate_child)
from docker_ready import UNITS, package_units, process_identity, socket_identity
from docker_resume import no_application_state, units, verify_engine
from image_import import validate_acquisition
from native_manifest import trusted_json
from native_service import trusted_path
from oci_acquire import IMAGES
from run import ENV, command, trusted_install

ACTIVATION_SHA256 = '4966aaa9d517ba4e4a7e5104f6a31e202bfecaa0f1a3636e5b2bb22f9b3e9a2e'
BUILD_UNITS = ('mpkg-fixture-python-build.service', 'mpkg-fixture-aur-ack.service',
               'mpkg-fixture-aur-gitstatus.service', 'mpkg-fixture-native-adoption.service',
               'mpkg-fixture-native-update-before.service')


def small(path):
    trusted_path(path)
    return read_regular(path)[0]


def activation_scope(value, guest):
    expected = {'schema': 1, 'guest_id': guest, 'status': 'unverified', 'diagnostic_status': 'observed',
                'diagnostic_only': True, 'engine_id': ENGINE, 'original_index_associations': 'unverified',
                'prior_import_remains_unverified': True, 'preparation_attempt_remains_unknown': True,
                'prior_records_unchanged': True, 'source_archive_sha256': SOURCE_SHA256,
                'prepared_archive_sha256': PREPARED_SHA256, 'containers': 0, 'volumes': 0,
                'enabled_services': False, 'product_acceptance': False}
    if any(type(value.get(key)) is not type(wanted) or value[key] != wanted for key, wanted in expected.items()):
        raise Refused('image_load_diagnostic_activation_scope')
    if len(value.get('child_images', [])) != len(IMAGES):
        raise Refused('image_load_diagnostic_activation_images')
    for image, (name, repository, _, child, _, _) in zip(value['child_images'], IMAGES):
        validate_child(image, name, repository, child)
    hashes = value.get('prior_record_sha256', {})
    if (set(hashes) != set(HASHES) | {'image-index-preparation/state.sqlite3'}
            or any(hashes[key] != digest for key, digest in HASHES.items())
            or any(not re.fullmatch('[0-9a-f]{64}', str(digest)) for digest in hashes.values())):
        raise Refused('image_load_diagnostic_activation_history')


def prior_evidence(guest):
    root = Path('/var/lib/mpkg-proofs')/guest
    no_application_state(root)
    for path in (Path('/opt/mpkg-proof-inputs/compose.json'), root/'image-index-preparation/result.json'):
        if path.exists() or path.is_symlink():
            raise Refused('image_load_diagnostic_prior_state_changed')
    raw = small(root/'docker-diagnostic-activation/result.json')
    activation = json.loads(raw)
    activation_scope(activation, guest)
    evidence = {'docker-diagnostic-activation/result.json': raw,
                'docker-diagnostic-activation/state.sqlite3':
                    journal_bytes(root/'docker-diagnostic-activation', 'observed-complete')}
    for relative, digest in activation['prior_record_sha256'].items():
        evidence[relative] = small(root/relative)
        if hashlib.sha256(evidence[relative]).hexdigest() != digest:
            raise Refused('image_load_diagnostic_prior_record_changed')
    if (journal_bytes(root/'image-import', 'unverified') != evidence['image-import/state.sqlite3']
            or journal_bytes(root/'image-index-preparation', None)
            != evidence['image-index-preparation/state.sqlite3']):
        raise Refused('image_load_diagnostic_prior_journal_changed')
    ready = json.loads(evidence['docker-readiness/result.json'])
    acquisition, acquired_hash = trusted_json('acquisition.json')
    source = validate_acquisition(acquisition)
    prepared = json.loads(evidence['image-index-preparation/prepared.json'])
    if (source['sha256'] != SOURCE_SHA256 or source['bytes'] != ARCHIVE_BYTES
            or prepared.get('acquisition_sha256') != acquired_hash
            or prepared.get('prepared_archive_sha256') != PREPARED_SHA256
            or prepared.get('prepared_archive_bytes') != ARCHIVE_BYTES):
        raise Refused('image_load_diagnostic_acquisition_changed')
    return root, activation, ready['packages_and_units'], evidence


def require_builds_idle():
    for unit in BUILD_UNITS:
        raw = command(['/usr/bin/systemctl', 'show', '--no-pager', '--plain',
                       '--property=ActiveState,SubState,MainPID,ControlPID,ControlGroup', unit])
        values = dict(line.split('=', 1) for line in raw.decode().splitlines())
        if (values.get('MainPID') != '0' or values.get('ControlPID') != '0'
                or values.get('ActiveState') not in {'inactive', 'failed', 'active'}
                or values.get('SubState') not in {'dead', 'failed', 'exited'}):
            raise Refused('image_load_diagnostic_build_not_idle')
        group = values.get('ControlGroup')
        if group and group != '/system.slice/'+unit:
            raise Refused('image_load_diagnostic_build_group_changed')
        path = Path('/sys/fs/cgroup/system.slice')/unit
        if path.exists():
            with (path/'cgroup.events').open() as stream:
                raw = stream.read(1025)
            if len(raw) > 1024 or dict(line.split() for line in raw.splitlines()).get('populated') != '0':
                raise Refused('image_load_diagnostic_build_descendants')
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            if path.stat().st_uid == 1502:
                raise Refused('image_load_diagnostic_builder_present')
            with (path/'comm').open() as stream:
                if stream.read(65).strip() == 'docker':
                    raise Refused('image_load_diagnostic_other_client_present')
        except (FileNotFoundError, ProcessLookupError):
            continue


def error_summary(raw):
    """Expose only closed categories and public content identities, never raw errors."""
    text = raw.decode('utf-8', errors='replace').lower()
    categories = [name for name, phrases in {
        'missing_path': ('no such file or directory',),
        'missing_content': ('content digest', 'content not found', 'not found'),
        'platform': ('requested platform', 'platform not found'),
        'archive_format': ('invalid tar header', 'unexpected eof', 'invalid archive'),
        'permission': ('permission denied',),
        'connection': ('cannot connect', 'connection refused',),
    }.items() if any(phrase in text for phrase in phrases)]
    return {'categories': categories,
            'digest_candidates': sorted(set(re.findall(r'sha256:[0-9a-f]{64}', text)))[:8],
            'public_path_candidates': sorted(set(re.findall(
                r'blobs/sha256/[0-9a-f]{64}|/proc/self/fd/[0-9]{1,6}|manifest\.json|index\.json', text)))[:8],
            'raw_output_disclosed': False}


def capture_load(directory, descriptor, environment, timeout=600, limit=1048576):
    """Capture only the fixed local Docker load; bounds do not assert daemon cancellation."""
    argv = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', 'image', 'load', '--quiet',
            '--platform', 'linux/amd64', '--input', '/proc/self/fd/'+str(descriptor)]
    streams, counts, digests = {}, {}, {}
    child = None
    outcome = 'spawn-failed'
    exit_code = None
    try:
        for name in ('stdout', 'stderr'):
            fd = os.open(directory/(name+'.private'), os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            streams[name] = os.fdopen(fd, 'wb', buffering=0)
            counts[name], digests[name] = 0, hashlib.sha256()
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=environment, pass_fds=(descriptor,))
        deadline = time.monotonic()+timeout
        outcome = 'running'
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    outcome = 'timeout'
                    break
                for key, _ in selector.select(min(remaining, 0.25)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    kept = chunk[:limit-counts[name]]
                    streams[name].write(kept)
                    counts[name] += len(kept)
                    digests[name].update(kept)
                    if len(kept) != len(chunk):
                        outcome = 'output-bound'
                        break
                if outcome != 'running':
                    break
            if outcome == 'running':
                try:
                    exit_code = child.wait(timeout=max(0.001, deadline-time.monotonic()))
                    outcome = 'exited'
                except subprocess.TimeoutExpired:
                    outcome = 'timeout'
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()  # Only the client is killed; daemon effects remain unknown.
            child.wait(timeout=10)
            if exit_code is None:
                exit_code = child.returncode
            child.stdout.close()
            child.stderr.close()
        for stream in streams.values():
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
    return {'capture_status': outcome, 'client_exit_code': exit_code,
            'command_completed': outcome == 'exited',
            'output': {name: {'file': name+'.private', 'bytes': counts[name], 'sha256': digests[name].hexdigest()}
                       for name in streams},
            'daemon_cancellation_claimed': False}


def check_engine(docker, provenance, activation, expected_ids, *, initial):
    if package_units() != provenance:
        raise Refused('image_load_diagnostic_packages_changed')
    observed = units(provenance, active=True)
    processes = {unit: process_identity(observed[unit], UNITS[unit][1].split()[0])
                 for unit in ('docker.service', 'containerd.service')}
    group = grp.getgrnam('docker')
    if group.gr_mem or any(user.pw_gid == group.gr_gid for user in pwd.getpwall()):
        raise Refused('image_load_diagnostic_docker_group_changed')
    sock = socket_identity(group.gr_gid, processes['docker.service'])
    if processes != activation['processes'] or sock != activation['socket']:
        raise Refused('image_load_diagnostic_daemon_restarted')
    info = json.loads(docker('info', '--format', '{{json .}}'))
    verify_engine(info, ENGINE, dict(enumerate(expected_ids)))
    if docker('container', 'ls', '--all', '--quiet').strip() or docker('volume', 'ls', '--quiet').strip():
        raise Refused('image_load_diagnostic_application_state_present')
    ids = set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().splitlines())
    if ids != expected_ids:
        raise Refused('image_load_diagnostic_inventory_changed')
    if initial:
        for name, repository, _, child, _, _ in IMAGES:
            validate_child(json.loads(docker('image', 'inspect', '--format', INSPECT, 'sha256:'+child)),
                           name, repository, child)
    return sorted(ids)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    trusted_install()
    os.umask(0o077)
    def expired(*_):
        raise Refused('image_load_diagnostic_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(1800)
    if hashlib.sha256(small(Path('/opt/mpkg-proofs/docker_diagnostic_resume.py'))).hexdigest() != ACTIVATION_SHA256:
        raise Refused('image_load_diagnostic_activation_helper_changed')
    require_builds_idle()
    root, activation, provenance, evidence = prior_evidence(guest)
    client = root/'docker-diagnostic-activation/docker-client'
    trusted_path(client, directory=True)
    if stat.S_IMODE(client.stat().st_mode) != 0o700 or next(client.iterdir(), None) is not None:
        raise Refused('image_load_diagnostic_empty_client_required')
    environment = dict(ENV, DOCKER_CONFIG=str(client))

    def docker(*arguments):
        return command(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *arguments], env=environment)

    children = {'sha256:'+child for _, _, _, child, _, _ in IMAGES}
    indexes = {'sha256:'+index for _, _, index, _, _, _ in IMAGES}
    check_engine(docker, provenance, activation, children, initial=True)
    archive = root/'image-index-preparation/images.original-indexes.oci.tar'
    trusted_path(archive)
    fd = os.open(archive, os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(fd)
        if (before.st_size != ARCHIVE_BYTES or before.st_nlink != 1 or before.st_uid != 0
                or before.st_gid != 0 or before.st_mode & 0o022 or not stat.S_ISREG(before.st_mode)
                or hashlib.file_digest(stream, 'sha256').hexdigest() != PREPARED_SHA256
                or identity(before) != identity(os.fstat(fd))):
            raise Refused('image_load_diagnostic_prepared_archive_changed')
        stream.seek(0)
        directory = root/'image-index-load-diagnostic'
        directory.mkdir(mode=0o700)
        parent = os.open(root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        private_directory(directory)
        journal = Journal(directory)
        try:
            attempt = str(uuid.uuid4())
            journal.begin(attempt)
            record = {'schema': 1, 'guest_id': guest, 'engine_id': ENGINE, 'attempt': attempt,
                      'diagnostic_only': True, 'product_acceptance': False, 'platform': 'linux/amd64',
                      'prepared_archive_sha256': PREPARED_SHA256, 'prepared_archive_bytes': ARCHIVE_BYTES,
                      'prior_record_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in evidence.items()},
                      'prior_import_remains_unverified': True, 'prior_preparation_remains_unknown': True}
            write_new(directory/'started.json', canonical(record)+b'\n')
            captured = capture_load(directory, fd, environment)
            write_new(directory/'capture.json', canonical(captured)+b'\n')
            summary = error_summary(small(directory/'stderr.private'))
            if (identity(before) != identity(os.fstat(fd))
                    or any(small(root/name) != raw for name, raw in evidence.items())):
                raise Refused('image_load_diagnostic_prior_evidence_changed')
            result = dict(record, capture=captured, error_summary=summary, status='unverified',
                          prior_records_unchanged=True, network_acquisition=False, explicit_tag_operations=False)
            # An interrupted client cannot establish that external work stopped.
            if not captured['command_completed']:
                result['attempt_terminal'] = 'unknown'
                write_new(directory/'result.json', canonical(result)+b'\n')
                print(json.dumps(result, sort_keys=True))
                return 75
            ids = set(docker('image', 'ls', '--all', '--quiet', '--no-trunc').decode().splitlines())
            if not ids <= children|indexes:
                raise Refused('image_load_diagnostic_unexpected_image')
            check_engine(docker, provenance, activation, ids, initial=False)
            verified, missing = [], []
            for _, repository, index, _, _, _ in IMAGES:
                reference = 'lscr.io/'+repository+'@sha256:'+index
                try:
                    image = json.loads(docker('image', 'inspect', '--format', INSPECT, reference))
                except Refused as error:
                    if str(error) != 'fixed_tool_failed':
                        raise
                    missing.append(reference)
                    continue
                if (image.get('Id') != 'sha256:'+index or reference not in (image.get('RepoDigests') or [])
                        or image.get('Os') != 'linux' or image.get('Architecture') != 'amd64'):
                    missing.append(reference)
                else:
                    verified.append({'reference': reference, 'image_id': image['Id']})
            if any(small(root/name) != raw for name, raw in evidence.items()):
                raise Refused('image_load_diagnostic_prior_evidence_changed')
            success = captured['client_exit_code'] == 0 and not missing
            result.update(status='observed' if success else 'unverified', observed_image_ids=sorted(ids),
                          verified_associations=verified, unverified_associations=missing,
                          load_command_completed=captured['client_exit_code'] == 0,
                          attempt_terminal='observed-complete' if success else 'unverified')
            write_new(directory/'result.json', canonical(result)+b'\n')
            journal.finish(attempt, result['attempt_terminal'])
            print(json.dumps(result, sort_keys=True))
            return 0 if success else 75
        finally:
            journal.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'diagnostic_only': True}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'image_load_diagnostic_failed', 'diagnostic_only': True}))
        sys.exit(74)
