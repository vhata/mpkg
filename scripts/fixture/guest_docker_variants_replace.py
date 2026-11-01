#!/usr/bin/env python3
"""Correct only the pristine variant helper before creating a reusable image checkpoint."""
import base64
import hashlib
import grp
import pwd
import json
import os
from pathlib import Path
import stat
import sys
import uuid

OLD_SHA256 = 'fb67486f1bbcce48855cf05ebf70768726161d5965c5d7e224b20fc9a390c6dc'
NEW_SHA256 = '1515a3b8ebd888c8bc1e555ed94c8c2606d64358e39230d5b80bf74e2589f447'
RESUME_SHA256 = 'f1c93ca71799b73a66142238978ea257a75a036f0ceb6d2cd547efd5c8fbec1b'
REPLACEMENT_BASE64 = None  # Filled only by the fixed host transport.


def protected_directory(path, mode=None):
    for part in (path, *path.parents):
        info = part.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_mode & 0o022):
            raise RuntimeError('replacement directory is not root-protected')
    if mode is not None and stat.S_IMODE(path.stat().st_mode) != mode:
        raise RuntimeError('replacement directory mode differs')


def stable_identity(info):
    return tuple(getattr(info, field) for field in (
        'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read_bound_file(path, digest):
    protected_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o644
                or before.st_size > 262144):
            raise RuntimeError('replacement input is not a root-protected helper')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(262145)
        if (stable_identity(before) != stable_identity(os.fstat(fd))
                or hashlib.sha256(raw).hexdigest() != digest):
            raise RuntimeError('replacement input bytes or identity differ')
        return raw, stable_identity(before)
    finally:
        os.close(fd)


def publish_replacement(target, data, expected_identity):
    if hashlib.sha256(data).hexdigest() != NEW_SHA256:
        raise RuntimeError('replacement payload differs from reviewed helper')
    _, current = read_bound_file(target, OLD_SHA256)
    if current != expected_identity:
        raise RuntimeError('old helper changed after pristine-state validation')
    temporary = target.with_name('.docker-variants-' + uuid.uuid4().hex + '.pending')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), 0o644)
        os.fsync(stream.fileno())
    _, current = read_bound_file(target, OLD_SHA256)
    if current != expected_identity:
        raise RuntimeError('old helper changed before atomic publication')
    os.replace(temporary, target)
    fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def require_fresh_state(guest, resume):
    root, provenance, images, evidence, large = resume.preparation_evidence(guest)
    if resume.package_units() != provenance:
        raise RuntimeError('variant correction package units changed')
    resume.units(provenance, active=False)
    resume.quiescent()
    for lookup, value in ((pwd.getpwnam, 'compose'), (pwd.getpwuid, 963),
                          (grp.getgrnam, 'compose'), (grp.getgrgid, 962)):
        try:
            lookup(value)
        except KeyError:
            continue
        raise RuntimeError('variant correction requires absent fixture account')
    shared = Path('/mnt/media/mpkg-fixture-shared')
    for path in (Path('/opt/docker'), shared/'radarr-root'):
        if path.exists() or path.is_symlink():
            raise RuntimeError('variant correction requires absent application data')
    resume.evidence_unchanged(evidence, large)
    return evidence, large


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def reserve_receipt(state):
    records = state/'proof-replacements'
    if not records.exists() and not records.is_symlink():
        records.mkdir(mode=0o700)
        sync_directory(state)
    protected_directory(records, 0o700)
    receipt = records/'docker-variants-pristine'
    receipt.mkdir(mode=0o700)
    sync_directory(records)
    return receipt


def main():
    if (sys.version_info[:2] != (3, 12) or os.geteuid() != 0 or os.getegid() != 0
            or REPLACEMENT_BASE64 is None or NEW_SHA256 is None):
        raise RuntimeError('fixed installed-guest variant correction required')
    sys.dont_write_bytecode = True
    directory = Path('/opt/mpkg-proofs')
    protected_directory(directory)
    # The read-only prerequisite validator and every direct dependency are
    # fixed before importing it; no lifecycle or resume entrypoint is called.
    dependencies = {
        'core.py': '0b13e3dc39d3a985ff7b8b3fd9885f3b09c75444854b41f775dd953b42d0167a',
        'docker_diagnostic_resume.py': '4966aaa9d517ba4e4a7e5104f6a31e202bfecaa0f1a3636e5b2bb22f9b3e9a2e',
        'docker_ready.py': '5efbc61753dbf873d26801f760c3e47f5a48831b1c3c0b02ba43a3c7c7e08a07',
        'docker_resume.py': '94fb8f960ee6bae8d28a958f1b9c8a54f23d83d1d98f5f174fb79630073b5f05',
        'image_import.py': '474fedcd6bf0925fbcbc1a5317fd0ef9ee7ebb0650e20ce8a30603ea04a6cca6',
        'native_manifest.py': 'ecac092012fcaebb2c7ff4bff43a236716d8b9a570b7d6567119574cf7ae5d2d',
        'native_service.py': 'd4183fa9a7251b1b0b97d5f09701bfeb1cbd52819aba143896de9eb14918e675',
        'oci_acquire.py': 'b6e25a460319dcf29a9800d7cd1160dffc8e929b8e141c142ef1d0964c8ff763',
        'run.py': 'adcd36404cb43e8bcdc0189eab6c98997ef8ea281461e54ba5aa3524dba8674e',
        'docker_supplement_resume.py': RESUME_SHA256,
        'account_defaults.py': '4d356ab3c41c8933e2030f20882ad25a3df142eb209cc5177c71f9a7b0991532',
        'service_environment.py': '91c819c3680eb4dae50458293e191bd36ebd2c39b439dd0122dc70928e83e502',
        'docker_baseline.py': 'f6af324e2d0844a6159f0e6dcf1e72c766679953dc4e4ec5c093ff42271bbeca',
        'docker_variant_plan.py': '1a0202a55e0ff303c07c67321b014fd7174591740a54d7066f05bbd0612c12eb',
        'compose_proof.py': 'da844883e9060a8a5f91ea14a560c5f76b26400cfb2dbe113221ea18f3eacbad',
        'experiments.py': '1f16927f2a84b196a8ad7491b7dc7e908b579cb49306ec25675e1cbde2d6bce1',
        'native_proof.py': '9a4eca361e2f1db56aa53f7817222e78ab9dabc10be36b5ae22a61454888c871',
    }
    for filename, digest in dependencies.items():
        read_bound_file(directory/filename, digest)
    sys.path.insert(0, str(directory))
    from core import require_guest, write_new
    import docker_supplement_resume as resume
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    os.umask(0o077)
    data = base64.b64decode(REPLACEMENT_BASE64, validate=True)
    if hashlib.sha256(data).hexdigest() != NEW_SHA256:
        raise RuntimeError('variant replacement bytes differ')
    target = directory/'docker_variants.py'
    old, observed = read_bound_file(target, OLD_SHA256)
    evidence, large = require_fresh_state(guest, resume)
    state = Path('/var/lib/mpkg-fixture')
    protected_directory(state, 0o700)
    receipt = reserve_receipt(state)
    write_new(receipt/'previous.py', old)
    result = {'schema': 1, 'guest_id': guest, 'path': str(target), 'old_sha256': OLD_SHA256,
              'new_sha256': NEW_SHA256, 'old_identity': observed, 'old_bytes': str(receipt/'previous.py'),
              'pristine_image_only': True, 'supplemental_resume_unused': True,
              'image_history_sha256': {str(path): hashlib.sha256(raw).hexdigest() for path, raw in evidence.items()},
              'executed': False}
    write_new(receipt/'prepared.json', (json.dumps(result, sort_keys=True)+'\n').encode())
    require_fresh_state(guest, resume)
    resume.evidence_unchanged(evidence, large)
    publish_replacement(target, data, observed)
    read_bound_file(target, NEW_SHA256)
    resume.evidence_unchanged(evidence, large)
    write_new(receipt/'complete.json', (json.dumps(result, sort_keys=True)+'\n').encode())
    print(json.dumps(dict(result, status='replaced'), sort_keys=True))


if __name__ == '__main__':
    main()
