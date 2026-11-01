#!/usr/bin/env python3
"""Correct the used SSH verifier while preserving both unknown attempt journals."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import uuid

OLD_SHA256 = '645822526f899506a9f0b6e13c27945003b111ed6d9b065e1df992095acf5961'
NEW_SHA256 = 'd4183fa9a7251b1b0b97d5f09701bfeb1cbd52819aba143896de9eb14918e675'
ENVIRONMENT_SHA256 = '91c819c3680eb4dae50458293e191bd36ebd2c39b439dd0122dc70928e83e502'
DEFAULTS_SHA256 = '4d356ab3c41c8933e2030f20882ad25a3df142eb209cc5177c71f9a7b0991532'
OBSERVER_SHA256 = '6f519fbc6a2fe4da2b558653cc86e9e813ad54e6586656bfd620ba1c229df5c7'
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
    temporary = target.with_name('.native-verifier-' + uuid.uuid4().hex + '.pending')
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


def observed_state(guest, native, observer):
    root = native.state_root(guest)
    recovery = root.parent/'native-service-recovery'
    original_raw = observer.unknown_history(root, 8)
    recovery_raw = observer.unknown_history(recovery, 0)
    for path in (recovery/'result.json', root.parent/'native-service-observation',
                 native.MANAGED_CONFIG.with_name('sshd_config.mpkg-fixture-new')):
        if path.exists() or path.is_symlink():
            raise RuntimeError('verifier correction requires the observed unfinished fixture')
    native.trusted_path(root/'baseline.json')
    manifest = json.loads(native.read_regular(root/'baseline.json')[0])
    if (manifest.get('schema') != 1 or manifest.get('guest_id') != guest
            or manifest.get('assembly_continuation') != 'native-service-recovery'):
        raise RuntimeError('verifier correction baseline identity differs')
    baseline, packaged_unit, version = native.package_baseline()
    if (native.read_regular(root/'packaged-sshd_config')[0] != baseline
            or native.read_regular(root/'packaged-sshd.service')[0] != packaged_unit
            or manifest.get('openssh_version') != version):
        raise RuntimeError('verifier correction packaged evidence differs')
    native.data_inventory()
    observed = {}
    for role, (_, _, port, unit) in native.ROLES.items():
        native.identity(role)
        config = native.MANAGED_CONFIG if role == 'native' else native.PUBLIC/'external.conf'
        native.trusted_path(config)
        if native.read_regular(config)[0] != native.configuration(role, root):
            raise RuntimeError('verifier correction configuration differs')
        manager = native.service_properties(unit)
        fragment = native.PACKAGED_UNIT if role == 'native' else native.EXTERNAL_UNIT
        if (manager.get('ActiveState') != 'active' or manager.get('SubState') != 'running'
                or manager.get('UnitFileState') != 'enabled' or int(manager.get('MainPID', '0')) <= 0
                or manager.get('LimitCORE') != '0' or manager.get('FragmentPath') != str(fragment)):
            raise RuntimeError('verifier correction requires the running fixed fixture')
        native.assert_startup(manager, role)
        if role == 'native':
            path = native.MANAGED_DROPINS/'50-mpkg-fixture.conf'
            native.trusted_path(path)
            if native.read_regular(path)[0] != native.DROPIN:
                raise RuntimeError('verifier correction drop-in differs')
        else:
            native.trusted_path(native.EXTERNAL_UNIT)
            if native.read_regular(native.EXTERNAL_UNIT)[0] != native.external_unit():
                raise RuntimeError('verifier correction external unit differs')
        observed[role] = native.listener_identity(manager, port)
    return original_raw, recovery_raw, observed


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
    read_bound_file(directory/'service_environment.py', ENVIRONMENT_SHA256)
    observer_raw, _ = read_bound_file(directory/'native_service_observe.py', OBSERVER_SHA256)
    target = directory/'native_service.py'
    old, identity = read_bound_file(target, OLD_SHA256)
    spec = importlib.util.spec_from_file_location('native_service', target)
    native = importlib.util.module_from_spec(spec)
    sys.modules['native_service'] = native
    exec(compile(old, str(target), 'exec'), native.__dict__)
    spec = importlib.util.spec_from_file_location('native_service_observe', directory/'native_service_observe.py')
    observer = importlib.util.module_from_spec(spec)
    exec(compile(observer_raw, spec.origin, 'exec'), observer.__dict__)
    original_raw, recovery_raw, observed = observed_state(guest, native, observer)
    state = Path('/var/lib/mpkg-fixture')
    protected_directory(state, 0o700)
    records = state/'proof-replacements'
    if not records.exists() and not records.is_symlink():
        records.mkdir(mode=0o700)
    protected_directory(records, 0o700)
    receipt = records/'native-verifier'
    receipt.mkdir(mode=0o700)
    parent_fd = os.open(records, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    protected_directory(receipt, 0o700)
    write_new(receipt/'previous.py', old)
    write_new(receipt/'original-state.sqlite3', original_raw)
    write_new(receipt/'recovery-state.sqlite3', recovery_raw)
    evidence = {'schema': 1, 'guest_id': guest, 'path': str(target),
                'old_sha256': OLD_SHA256, 'new_sha256': NEW_SHA256,
                'old_identity': identity, 'old_bytes': str(receipt/'previous.py'),
                'observer_sha256': OBSERVER_SHA256, 'account_defaults_sha256': DEFAULTS_SHA256,
                'original_journal_sha256': hashlib.sha256(original_raw).hexdigest(),
                'recovery_journal_sha256': hashlib.sha256(recovery_raw).hexdigest(),
                'both_attempts_remain_unknown': True, 'service_actions': False,
                'authenticated_requests': False, 'replacement_executed': False}
    write_new(receipt/'prepared.json', (json.dumps(evidence, sort_keys=True)+'\n').encode())
    if observed_state(guest, native, observer) != (original_raw, recovery_raw, observed):
        raise RuntimeError('fixture changed before verifier correction')
    publish_replacement(target, data, identity)
    read_bound_file(target, NEW_SHA256)
    if observed_state(guest, native, observer) != (original_raw, recovery_raw, observed):
        raise RuntimeError('fixture changed during verifier correction')
    write_new(receipt/'complete.json', (json.dumps(evidence, sort_keys=True)+'\n').encode())
    print(json.dumps({'status': 'replaced', 'path': str(target), 'sha256': NEW_SHA256,
                      'both_attempts_remain_unknown': True, 'replacement_executed': False}))


if __name__ == '__main__':
    main()
