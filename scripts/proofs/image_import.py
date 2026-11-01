#!/usr/bin/env python3
"""Import one reviewed OCI artifact inside the identified guest; never pull."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, identity, private_directory, read_regular, require_guest, write_new
from experiments import fresh
from oci_acquire import IMAGES
from run import ENV, command, trusted_install


INPUTS = Path('/opt/mpkg-proof-inputs')


def validate_acquisition(report):
    if report.get('schema') != 1 or report.get('docker_or_runtime_operations') is not False:
        raise Refused('acquisition_report_invalid')
    archive = report.get('archive', {})
    if (archive.get('filename') != 'images.oci.tar'
            or not re.fullmatch(r'[0-9a-f]{64}', str(archive.get('sha256', '')))
            or type(archive.get('bytes')) is not int
            or not 0 < archive['bytes'] <= 3 * 1024 ** 3 + 1048576):
        raise Refused('acquisition_archive_binding_invalid')
    images = report.get('images', [])
    by_name = {item['fixture_name']: item for item in images}
    if len(images) != len(IMAGES) or set(by_name) != {item[0] for item in IMAGES}:
        raise Refused('acquisition_image_scope_changed')
    for name, repository, index, manifest, config, version in IMAGES:
        expected = {'repository': 'lscr.io/' + repository, 'index_digest': 'sha256:' + index,
                    'manifest_digest': 'sha256:' + manifest, 'config_digest': 'sha256:' + config,
                    'platform': 'linux/amd64', 'version_label': version}
        if any(by_name[name].get(key) != value for key, value in expected.items()):
            raise Refused('acquisition_image_binding_changed')
    return archive


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    private_directory(INPUTS)
    raw, evidence = read_regular(INPUTS / 'acquisition.json')
    if evidence[4] != 0 or evidence[6] & 0o022:
        raise Refused('acquisition_report_not_trusted')
    archive = validate_acquisition(json.loads(raw))
    descriptor = os.open(INPUTS / 'images.oci.tar', os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & 0o022 or before.st_size != archive['bytes']):
            raise Refused('acquisition_archive_identity_changed')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != archive['sha256'] or identity(before) != identity(os.fstat(descriptor)):
            raise Refused('acquisition_archive_digest_changed')
        os.lseek(descriptor, 0, os.SEEK_SET)
        root = private_directory(Path('/var/lib/mpkg-proofs') / guest)
        directory = fresh(root, 'image-import')
        client = private_directory(directory / 'docker-client')
        environment = dict(ENV, DOCKER_CONFIG=str(client))
        def docker(*arguments, timeout=30, pass_fds=()):
            return command(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock',
                            *arguments], env=environment, timeout=timeout, pass_fds=pass_fds)
        engine = docker('info', '--format', '{{.ID}}').decode().strip()
        if not engine or len(engine) > 256:
            raise Refused('engine_identity_unavailable')
        lock = os.open(directory / 'apply.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            journal = Journal(directory)
            try:
                attempt = str(uuid.uuid4())
                journal.begin(attempt)
                # Held descriptor avoids reopening an unbound pathname. A client
                # timeout leaves the durable attempt unknown; no retry follows.
                docker('image', 'load', '--quiet', '--platform', 'linux/amd64',
                       '--input', '/proc/self/fd/' + str(descriptor), timeout=600,
                       pass_fds=(descriptor,))
                if identity(before) != identity(os.fstat(descriptor)):
                    raise Refused('acquisition_archive_changed_during_import')
                verified, missing = [], []
                for name, repository, index, manifest, config, version in IMAGES:
                    reference = 'lscr.io/' + repository + '@sha256:' + index
                    try:
                        value = json.loads(docker('image', 'inspect', reference))[0]
                    except Refused as error:
                        if str(error) != 'fixed_tool_failed':
                            raise
                        missing.append(reference)
                        continue
                    if (reference not in value.get('RepoDigests', [])
                            or value.get('Os') != 'linux' or value.get('Architecture') != 'amd64'
                            or value.get('Id') not in ('sha256:' + index, 'sha256:' + config)):
                        missing.append(reference)
                    else:
                        verified.append({'reference': reference, 'image_id': value['Id']})
                if docker('info', '--format', '{{.ID}}').decode().strip() != engine:
                    raise Refused('engine_identity_changed')
                result = {'schema': 1, 'guest_id': guest, 'engine_id': engine,
                          'archive_sha256': digest, 'load_command_completed': True,
                          'verified_associations': verified, 'unverified_associations': missing,
                          'status': 'unverified' if missing else 'observed',
                          'product_acceptance': False,
                          'limits': ['Only local image load was invoked; no pull, tag or container start.',
                                     'Original index RepoDigest association is required, never inferred.',
                                     'Missing association requires a separately reviewed preparation step.']}
                journal.finish(attempt, 'unverified' if missing else 'observed-complete')
                write_new(directory / 'result.json', canonical(result) + b'\n')
                print(json.dumps(result, sort_keys=True))
                return 75 if missing else 0
            finally:
                journal.close()
        finally:
            os.close(lock)
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'image_import_failed',
                          'product_acceptance': False}))
        sys.exit(74)
