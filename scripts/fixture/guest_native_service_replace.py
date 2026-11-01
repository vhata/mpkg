#!/usr/bin/env python3
"""Replace one unused fixture helper, preserving its exact prior bytes."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import uuid

OLD_SHA256 = '7b570707869fc9e3e54cbcf6ae5d01d89d4fbaf33ac761ab2c31e52c8f549ab8'
NEW_SHA256 = 'fbb713c105ed23fe140d2ccc9443eca6295d34e5b788e2e58c994c821638f7b6'
ENVIRONMENT_SHA256 = '91c819c3680eb4dae50458293e191bd36ebd2c39b439dd0122dc70928e83e502'
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


def require_fresh_state(guest, previous):
    paths = [previous.state_root(guest), previous.PUBLIC, previous.EXTERNAL_UNIT,
             previous.EXCLUSIVE, previous.SHARED, previous.MANAGED_DROPINS,
             Path('/home/fixture-native'), Path('/home/fixture-external')]
    if any(path.exists() or path.is_symlink() for path in paths):
        raise RuntimeError('native service fixture already has state')
    raw = previous.command(['/usr/bin/systemctl', 'show', 'sshd.service',
        '--property=ActiveState,SubState,MainPID,ControlPID,UnitFileState,FragmentPath,DropInPaths'])
    observed = dict(line.split('=', 1) for line in raw.decode().splitlines())
    expected = {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0',
                'ControlPID': '0', 'UnitFileState': 'disabled', 'DropInPaths': '',
                'FragmentPath': '/usr/lib/systemd/system/sshd.service'}
    if observed != expected:
        raise RuntimeError('native service replacement requires untouched packaged unit')
    # This exact old helper's preflight is read-only. It additionally binds
    # accounts, ports, package/signature evidence and packaged config/unit bytes.
    previous.preflight(previous.state_root(guest))
    return observed


def publish_replacement(target, data, expected_identity):
    if hashlib.sha256(data).hexdigest() != NEW_SHA256:
        raise RuntimeError('replacement payload differs from reviewed helper')
    _, current = read_bound_file(target, OLD_SHA256)
    if current != expected_identity:
        raise RuntimeError('old helper changed after pristine-state validation')
    temporary = target.with_name('.native-service-' + uuid.uuid4().hex + '.pending')
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


def main():
    if (sys.version_info[:2] != (3, 12) or os.geteuid() != 0 or os.getegid() != 0
            or REPLACEMENT_BASE64 is None):
        raise RuntimeError('fixed installed-guest replacement transport required')
    sys.dont_write_bytecode = True
    directory = Path('/opt/mpkg-proofs')
    protected_directory(directory)
    core = directory / 'core.py'
    info = core.lstat()
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
    read_bound_file(directory / 'service_environment.py', ENVIRONMENT_SHA256)
    read_bound_file(directory / 'account_defaults.py', DEFAULTS_SHA256)
    target = directory / 'native_service.py'
    old, identity = read_bound_file(target, OLD_SHA256)
    spec = importlib.util.spec_from_file_location('previous_native_service', target)
    previous = importlib.util.module_from_spec(spec)
    exec(compile(old, str(target), 'exec'), previous.__dict__)
    observed = require_fresh_state(guest, previous)
    state = Path('/var/lib/mpkg-fixture')
    protected_directory(state, 0o700)
    records = state / 'proof-replacements'
    if not records.exists() and not records.is_symlink():
        records.mkdir(mode=0o700)
    protected_directory(records, 0o700)
    receipt = records / 'native-service'
    receipt.mkdir(mode=0o700)  # Existing evidence, including failed attempts, blocks replay.
    protected_directory(receipt, 0o700)
    write_new(receipt / 'previous.py', old)
    evidence = {'schema': 1, 'guest_id': guest, 'path': str(target),
                'old_sha256': OLD_SHA256, 'new_sha256': NEW_SHA256,
                'old_identity': identity, 'old_bytes': str(receipt / 'previous.py'),
                'service_environment_sha256': ENVIRONMENT_SHA256,
                'account_defaults_sha256': DEFAULTS_SHA256,
                'untouched_service': observed, 'executed': False}
    write_new(receipt / 'prepared.json', (json.dumps(evidence, sort_keys=True) + '\n').encode())
    publish_replacement(target, data, identity)
    read_bound_file(target, NEW_SHA256)
    write_new(receipt / 'complete.json', (json.dumps(evidence, sort_keys=True) + '\n').encode())
    print(json.dumps({'status': 'replaced', 'path': str(target),
                      'sha256': NEW_SHA256, 'executed': False}))


if __name__ == '__main__':
    main()
