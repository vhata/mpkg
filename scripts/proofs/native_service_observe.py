#!/usr/bin/env python3
"""Observe the running SSH fixture without completing either failed attempt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import sqlite3
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_service as native
from core import Journal, Refused, canonical, private_directory, read_regular, require_guest, write_new
from run import trusted_install


NATIVE_SHA256 = 'd4183fa9a7251b1b0b97d5f09701bfeb1cbd52819aba143896de9eb14918e675'


def unknown_history(directory, protected_count):
    native.trusted_path(directory, directory=True)
    path = directory / 'state.sqlite3'
    info = native.trusted_path(path)
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise Refused('native_observation_journal_permissions')
    database = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1)
    try:
        database.execute('PRAGMA query_only=ON')
        attempts = database.execute('SELECT id,terminal FROM attempts').fetchall()
        if (len(attempts) != 1 or attempts[0][1] is not None
                or str(uuid.UUID(attempts[0][0])) != attempts[0][0]
                or database.execute('SELECT attempt,kind FROM events ORDER BY seq').fetchall() != [(attempts[0][0], 'started')]
                or database.execute('SELECT COUNT(*) FROM protected').fetchone() != (protected_count,)
                or database.execute('SELECT recovery_required FROM store_guard').fetchall() != [(0,)]):
            raise Refused('native_observation_history_not_expected_unknown')
    finally:
        database.close()
    return read_regular(path)[0]


def bindings(guest):
    source = Path(native.__file__).resolve()
    if source != Path('/opt/mpkg-proofs/native_service.py') or hashlib.sha256(read_regular(source)[0]).hexdigest() != NATIVE_SHA256:
        raise Refused('native_observation_source_not_corrected')
    root = native.state_root(guest)
    recovery = root.parent / 'native-service-recovery'
    original_raw, recovery_raw = unknown_history(root, 8), unknown_history(recovery, 0)
    for path in (recovery / 'result.json', root.parent / 'native-service-observation'):
        if path.exists() or path.is_symlink():
            raise Refused('native_observation_requires_unobserved_state')
    native.trusted_path(root / 'baseline.json')
    manifest = json.loads(read_regular(root / 'baseline.json')[0])
    if (manifest.get('schema') != 1 or manifest.get('guest_id') != guest
            or manifest.get('assembly_continuation') != 'native-service-recovery'):
        raise Refused('native_observation_baseline_binding_changed')
    return root, recovery, original_raw, recovery_raw


def observe(guest):
    root, recovery, original_raw, recovery_raw = bindings(guest)
    directory = root.parent / 'native-service-observation'
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise Refused('native_observation_fresh_attempt_required') from None
    descriptor = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    private_directory(directory)
    write_new(directory / 'original-state.sqlite3', original_raw)
    write_new(directory / 'recovery-state.sqlite3', recovery_raw)
    journal = Journal(directory)
    try:
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        # Existing bounded configuration, protected-input, unit/process and
        # pinned-key SFTP checks. No setup, enable, start, stop or restart.
        result = native.check(guest)
        if unknown_history(root, 8) != original_raw or unknown_history(recovery, 0) != recovery_raw:
            raise Refused('native_observation_prior_history_changed')
        result.update(original_attempt_remains_unknown=True, recovery_attempt_remains_unknown=True,
                      observation_attempt=attempt, assembly_observation=True, product_acceptance=False)
        write_new(directory / 'result.json', canonical(result) + b'\n')
        journal.finish(attempt, 'observed-complete')
        return result
    finally:
        journal.close()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', required=True)
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    trusted_install()
    os.umask(0o077)
    print(json.dumps(observe(guest), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'native_service_observation_failed', 'product_acceptance': False}))
        sys.exit(74)
