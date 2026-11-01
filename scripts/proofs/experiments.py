"""Fixed disposable experiments; none are part of ordinary repository checks."""
import fcntl
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
import uuid

from core import (Journal, Refused, change_xml_port, delete_inventory,
                  inventory_tree, private_directory, read_regular, replace_xml,
                  write_new)
from run import CASES, ENV, INSTALL, command


def expect_refusal(code, operation):
    try:
        operation()
    except Refused as error:
        if str(error) == code:
            return True
        raise
    raise Refused('expected_refusal_missing')


def fresh(root, name):
    path = root / name
    if path.exists():
        raise Refused('fresh_restore_point_required')
    return private_directory(path)


def wait_for(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise Refused('observation_timeout')


def worker_argv(guest, case, attempt, verb='worker'):
    return [sys.executable, '-I', str(INSTALL / 'run.py'), verb,
            '--guest-id', guest, '--case', case, '--attempt', attempt]


def prove_journal(guest, root):
    cases = []
    for case in CASES[:5]:
        directory = fresh(root, case)
        attempt = str(uuid.uuid4())
        result = subprocess.run(worker_argv(guest, case, attempt), env=ENV,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=False)
        journal = Journal(directory)
        history = journal.export()
        has_effect = (directory / 'effect').exists()
        if case == 'before-start':
            if history or has_effect or result.returncode == 0:
                raise Refused('effect_without_durable_start')
            expected = 'not-started'
        else:
            expected = 'observed-complete' if case == 'complete' else 'unknown'
            if (len(history) != 1 or history[0]['state'] != expected
                    or has_effect != (case != 'after-start')):
                raise Refused('journal_fault_predicate_failed')
            if expected == 'unknown':
                expect_refusal('unresolved_attempt',
                               lambda: journal.begin(str(uuid.uuid4())))
        cases.append({'case': case, 'state': expected, 'effect': has_effect})
        journal.close()
    return {'status': 'observed', 'cases': cases,
            'sqlite_version': sqlite3.sqlite_version,
            'limits': ['Process exits and SQLite query-only faults are not power-loss tests.',
                       'No automatic recovery or retry is implemented.']}


def prove_inputs(guest, root):
    directory = fresh(root, 'inputs')
    source = directory / 'source.env'
    sentinel = b'FIXTURE_SECRET=' + uuid.uuid4().hex.encode() + b'\nLITERAL=$dollar\n'
    write_new(source, sentinel)
    journal = Journal(directory)
    reference = journal.capture(source)
    if not journal.unchanged(reference, source):
        raise Refused('capture_mismatch')
    replay = directory / 'replayed.env'
    journal.replay(reference, replay)
    if replay.read_bytes() != sentinel:
        raise Refused('replay_mismatch')
    source.write_bytes(sentinel + b'CHANGED=1\n')
    if journal.unchanged(reference, source):
        raise Refused('input_drift_not_detected')
    projection = json.dumps(journal.export()).encode()
    if sentinel.splitlines()[0] in projection or reference.encode() in projection:
        raise Refused('protected_projection_leak')
    # A real SQLite SQLITE_FULL during protected capture cannot publish a ref.
    pages = journal.db.execute('PRAGMA page_count').fetchone()[0]
    journal.db.execute('PRAGMA max_page_count=' + str(pages))
    large = directory / 'too-large-for-database'
    write_new(large, os.urandom(1024 * 1024))
    before = journal.db.execute('SELECT COUNT(*) FROM protected').fetchone()[0]
    try:
        journal.capture(large)
    except sqlite3.OperationalError as error:
        if error.sqlite_errorcode != sqlite3.SQLITE_FULL:
            raise
    else:
        raise Refused('storage_full_fault_missing')
    after = journal.db.execute('SELECT COUNT(*) FROM protected').fetchone()[0]
    if before != after:
        raise Refused('failed_capture_published_reference')
    # Restore a prior history through the explicit quarantining path.
    snapshot = directory / 'snapshot'
    journal.backup(snapshot)
    effect = directory / 'external-effect'
    write_new(effect, b'external state survives history restoration')
    restored = Journal.restore(snapshot, directory / 'restored')
    try:
        expect_refusal('history_recovery_required',
                       lambda: restored.begin(str(uuid.uuid4())))
        if effect.read_bytes() != b'external state survives history restoration':
            raise Refused('history_restoration_changed_external_state')
    finally:
        restored.close()
    journal.close()
    return {'status': 'observed', 'exact_replay': True, 'drift_blocks': True,
            'failed_capture_has_no_reference': True, 'export_has_no_secret': True,
            'restored_history_requires_recovery': True, 'external_effect_not_rolled_back': True,
            'limits': ['Protected bytes remain plaintext in a private store.',
                       'This checks the prototype projection, not every product error path.']}


def prove_xml(guest, root):
    directory = fresh(root, 'xml')
    source = directory / 'config.xml'
    secret = uuid.uuid4().hex
    raw = ('<?xml version="1.0"?><Config><!-- preserve comment -->'
           '<Port keep="yes">19891</Port><ApiKey>' + secret + '</ApiKey>'
           '<InstanceName>unmanaged fixture</InstanceName></Config>').encode()
    write_new(source, raw, 0o640)
    accepted, evidence = read_regular(source)
    changed = replace_xml(source, accepted, evidence, 19892)
    if changed != change_xml_port(raw, 19892):
        raise Refused('xml_preservation_failed')
    expect_refusal('config_changed',
                   lambda: replace_xml(source, accepted, evidence, 19893))
    current, evidence = read_regular(source)
    expect_refusal('config_changed', lambda: replace_xml(
        source, current, evidence, 19893,
        before_publish=lambda: source.write_bytes(current + b'\n')))
    if source.read_bytes() != current + b'\n':
        raise Refused('intervening_writer_overwritten')
    return {'status': 'observed', 'unmanaged_bytes_preserved': True,
            'stale_and_intervening_edits_blocked': True,
            'limits': ['Synthetic XML only; the compose proof tests stopped Sonarr.',
                       'Exclusive writer maintenance is required; rename is not compare-and-swap.']}


def prove_retirement(guest, root):
    directory = fresh(root, 'retirement')
    kept = private_directory(directory / 'keep')
    write_new(kept / 'sentinel', b'kept')
    accepted = inventory_tree(kept)
    consumers = directory / 'consumers.json'
    write_new(consumers, b'[]')
    consumers.write_bytes(b'["external:radarr"]')
    expect_refusal('data_shared',
                   lambda: delete_inventory(kept, accepted, json.loads(consumers.read_bytes())))
    if (kept / 'sentinel').read_bytes() != b'kept':
        raise Refused('shared_retention_failed')
    deleted = private_directory(directory / 'delete')
    write_new(deleted / 'first', b'a')
    write_new(deleted / 'second', b'b')
    accepted = inventory_tree(deleted)
    write_new(deleted / 'new-descendant', b'new')
    expect_refusal('data_inventory_changed',
                   lambda: delete_inventory(deleted, accepted, []))
    accepted = inventory_tree(deleted)
    journal = Journal(directory)
    attempt = str(uuid.uuid4())
    journal.begin(attempt)
    expect_refusal('injected_partial_delete',
                   lambda: delete_inventory(deleted, accepted, [], fail_after=1))
    journal.finish(attempt, 'unverified')
    if len(list(deleted.iterdir())) != 2:
        raise Refused('partial_delete_predicate_failed')
    # A new explicitly captured disposition accounts for the remaining scope.
    remaining = inventory_tree(deleted)
    attempt = str(uuid.uuid4())
    journal.begin(attempt)
    removed = delete_inventory(deleted, remaining, [])
    journal.finish(attempt, 'observed-complete')
    journal.close()
    mounted = private_directory(directory / 'mount-check')
    point = private_directory(mounted / 'point')
    origin = private_directory(directory / 'mount-origin')
    command(['/usr/bin/mount', '--bind', str(origin), str(point)])
    try:
        expect_refusal('data_mount_changed', lambda: inventory_tree(mounted))
    finally:
        command(['/usr/bin/umount', str(point)])
    return {'status': 'observed', 'kept_shared_sentinel': True,
            'changed_consumers_block': True, 'same_filesystem_bind_mount_blocks': True,
            'new_descendant_blocks': True, 'partial_outcome': 'unverified',
            'fresh_disposition_removed_entries': removed,
            'limits': ['Directory experiment only; no product retirement claim.',
                       'Consumer declarations and exclusive writers are explicit assumptions.']}


def prove_supervision(guest, root):
    observations = []
    for case in ('supervised', 'orphan'):
        directory = fresh(root, case)
        attempt = str(uuid.uuid4())
        unit = 'mpkg-proof-' + attempt + '.service'
        controller = subprocess.Popen(worker_argv(guest, case, attempt, 'launch'),
                                      env=ENV, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
        try:
            wait_for(lambda: (directory / 'worker-started').exists())
            controller.kill()
            controller.wait(timeout=5)
            blocked = subprocess.run(worker_argv(guest, case, str(uuid.uuid4())),
                                     env=ENV, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=5)
            if blocked.returncode != 73:
                raise Refused('overlapping_worker_not_blocked')
            if case == 'supervised':
                write_new(directory / 'release', b'release')
                def completed():
                    journal = Journal(directory)
                    try:
                        return journal.export()[0]['state'] == 'observed-complete'
                    finally:
                        journal.close()
                wait_for(completed)
                state = 'observed-complete'
            else:
                wait_for(lambda: (directory / 'child-effect').exists(), 15)
                def lock_released():
                    descriptor = os.open(directory / 'apply.lock', os.O_RDWR | os.O_NOFOLLOW)
                    try:
                        try:
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            return False
                        return True
                    finally:
                        os.close(descriptor)
                wait_for(lock_released)
                journal = Journal(directory)
                try:
                    if journal.export()[0]['state'] != 'unknown':
                        raise Refused('dead_worker_fabricated_completion')
                    expect_refusal('unresolved_attempt',
                                   lambda: journal.begin(str(uuid.uuid4())))
                finally:
                    journal.close()
                state = 'unknown'
            observations.append({'case': case, 'controller_killed': True,
                                 'overlap_blocked': True, 'state': state})
        finally:
            if controller.poll() is None:
                controller.kill()
                controller.wait(timeout=5)
            # Cleanup does not reinterpret an unresolved attempt as success.
            command(['/usr/bin/systemctl', 'stop', unit], timeout=15)
    return {'status': 'observed', 'cases': observations,
            'limits': ['Manager-owned service and surviving child tested separately.',
                       'Docker daemon work requires the separate compose experiment.']}


def prove_compose(guest, root):
    import compose_proof
    return compose_proof.run(guest, root)


def prove_native(guest, root):
    import native_proof
    return native_proof.run(guest, root)
