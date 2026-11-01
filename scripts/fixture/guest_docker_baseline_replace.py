#!/usr/bin/env python3
"""Correct only the untouched Docker baseline helper, preserving prior bytes."""
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

OLD_SHA256 = 'ef9385b2a0f55f3074ccb7522ae14719fc97fddf1fd95e3d8f4796c53bfbbdb2'
NEW_SHA256 = 'f6af324e2d0844a6159f0e6dcf1e72c766679953dc4e4ec5c093ff42271bbeca'
DEFAULTS_SHA256 = '4d356ab3c41c8933e2030f20882ad25a3df142eb209cc5177c71f9a7b0991532'
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
    temporary = target.with_name('.docker-baseline-' + uuid.uuid4().hex + '.pending')
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


def require_fresh_state(guest):
    root = Path('/var/lib/mpkg-proofs') / guest
    for path in (root/'docker-baseline', root/'compose', root/'daemon', Path('/opt/docker'),
                 Path('/mnt/media/mpkg-fixture-shared/radarr-root')):
        if path.exists() or path.is_symlink():
            raise RuntimeError('Docker baseline correction requires untouched fixture paths')
    for lookup, value in ((pwd.getpwnam, 'compose'), (pwd.getpwuid, 963),
                          (grp.getgrnam, 'compose'), (grp.getgrgid, 962)):
        try:
            lookup(value)
        except KeyError:
            continue
        raise RuntimeError('Docker baseline correction requires absent fixture account')


def main():
    if (sys.version_info[:2] != (3, 12) or os.geteuid() != 0 or os.getegid() != 0
            or REPLACEMENT_BASE64 is None):
        raise RuntimeError('fixed installed-guest replacement transport required')
    sys.dont_write_bytecode = True
    directory = Path('/opt/mpkg-proofs')
    protected_directory(directory)
    info = (directory/'core.py').lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or info.st_mode & 0o022):
        raise RuntimeError('installed guest guard is not trusted')
    sys.path.insert(0, str(directory))
    from core import require_guest, write_new
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    os.umask(0o077)
    data = base64.b64decode(REPLACEMENT_BASE64, validate=True)
    if hashlib.sha256(data).hexdigest() != NEW_SHA256:
        raise RuntimeError('replacement payload differs from reviewed helper')
    read_bound_file(directory/'account_defaults.py', DEFAULTS_SHA256)
    target = directory/'docker_baseline.py'
    old, identity = read_bound_file(target, OLD_SHA256)
    require_fresh_state(guest)
    state = Path('/var/lib/mpkg-fixture')
    protected_directory(state, 0o700)
    records = state/'proof-replacements'
    if not records.exists() and not records.is_symlink():
        records.mkdir(mode=0o700)
    protected_directory(records, 0o700)
    receipt = records/'docker-baseline'
    receipt.mkdir(mode=0o700)
    protected_directory(receipt, 0o700)
    write_new(receipt/'previous.py', old)
    evidence = {'schema': 1, 'guest_id': guest, 'path': str(target),
                'old_sha256': OLD_SHA256, 'new_sha256': NEW_SHA256,
                'old_identity': identity, 'old_bytes': str(receipt/'previous.py'),
                'account_defaults_sha256': DEFAULTS_SHA256,
                'fixture_state_absent': True, 'executed': False}
    write_new(receipt/'prepared.json', (json.dumps(evidence, sort_keys=True)+'\n').encode())
    require_fresh_state(guest)
    publish_replacement(target, data, identity)
    read_bound_file(target, NEW_SHA256)
    write_new(receipt/'complete.json', (json.dumps(evidence, sort_keys=True)+'\n').encode())
    print(json.dumps({'status': 'replaced', 'path': str(target),
                      'sha256': NEW_SHA256, 'executed': False}))


if __name__ == '__main__':
    main()
