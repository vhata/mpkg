#!/usr/bin/env python3
"""Prove private projection and command-error confinement in a fresh guest case."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Journal, Refused, canonical, private_directory, read_regular, require_guest, write_new
from run import command, trusted_install


INSTALL = Path('/opt/mpkg-proofs')
PYTHON = '/opt/mpkg-python/3.12.16/bin/python3.12'
DEPENDENCIES = {
    'core.py': '0b13e3dc39d3a985ff7b8b3fd9885f3b09c75444854b41f775dd953b42d0167a',
    'run.py': 'adcd36404cb43e8bcdc0189eab6c98997ef8ea281461e54ba5aa3524dba8674e',
}
FAULTS = {
    'failure': ('fixed_tool_failed', 10),
    'output-bound': ('tool_output_bound_external_work_unknown', 10),
    'timeout': ('tool_timeout_external_work_unknown', 1),
}
# Input arrives only over stdin. These fixed children never spawn descendants.
FAULT_SOURCE = r'''import os, sys, time
value = sys.stdin.buffer.read(4097)
if not 1 <= len(value) <= 4096:
    sys.exit(91)
os.write(1, value)
os.write(2, value)
descriptor = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(descriptor, b'emitted-to-both-streams\n')
os.fsync(descriptor)
os.close(descriptor)
if sys.argv[1] == 'failure':
    sys.exit(17)
if sys.argv[1] == 'output-bound':
    chunk = (value * (8192 // len(value) + 1))[:8192]
    for unused in range(640):
        sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    sys.exit(0)
if sys.argv[1] == 'timeout':
    time.sleep(30)
    sys.exit(0)
sys.exit(92)
'''


def no_protected_bytes(raw, forbidden):
    if not isinstance(raw, bytes) or any(not item or item in raw for item in forbidden):
        raise Refused('protected_output_leak')


def isolated_environment(home):
    """Never merge caller Git/config/credential/trace environment into this case."""
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(home),
            'XDG_CONFIG_HOME': str(home), 'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_ATTR_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GIT_PAGER': 'cat', 'GIT_CEILING_DIRECTORIES': str(home.parent)}


def git_objects(git, projection, forbidden):
    """Check every object, including unreachable ones, without exporting bytes."""
    if git('ls-tree', '-r', '--name-only', 'HEAD') != b'projection.json\n':
        raise Refused('protected_git_file_scope')
    reachable = git('rev-list', '--objects', '--all').splitlines()
    reachable_ids = {line.split(b' ', 1)[0] for line in reachable}
    inventory = git('cat-file', '--batch-all-objects', '--batch-check').splitlines()
    objects, counts = {}, {'commit': 0, 'tree': 0, 'blob': 0}
    for line in inventory:
        fields = line.split()
        if (len(fields) != 3 or re.fullmatch(rb'[0-9a-f]{40}', fields[0]) is None
                or fields[1] not in (b'commit', b'tree', b'blob')
                or re.fullmatch(rb'[0-9]+', fields[2]) is None
                or not 0 < int(fields[2]) <= 65536 or fields[0] in objects):
            raise Refused('protected_git_object_scope')
        identifier, kind, size = fields[0], fields[1].decode(), int(fields[2])
        raw = git('cat-file', kind, identifier.decode())
        no_protected_bytes(raw, forbidden)
        if len(raw) != size or (kind == 'blob' and raw != projection):
            raise Refused('protected_git_object_content')
        objects[identifier] = kind
        counts[kind] += 1
    if counts != {'commit': 1, 'tree': 1, 'blob': 1} or set(objects) != reachable_ids:
        raise Refused('protected_git_reachability')
    if git('remote').strip() or git('status', '--porcelain', '--untracked-files=all').strip():
        raise Refused('protected_git_repository_scope')
    return counts


def command_faults(directory, sentinel, environment, *, python=PYTHON):
    observations = {}
    for name, (expected, timeout) in FAULTS.items():
        receipt = directory / (name + '-child-receipt')
        try:
            command([python, '-I', '-c', FAULT_SOURCE, name, str(receipt)], timeout=timeout,
                    env=environment, input_bytes=sentinel)
        except Refused as error:
            if str(error) != expected:
                raise Refused('protected_fault_boundary_mismatch') from None
            # This is the selected command boundary's public failure shape.
            public = canonical({'status': 'refused', 'code': str(error),
                                'product_acceptance': False})
            no_protected_bytes(public, [sentinel])
            observations[name] = {'code': expected, 'sentinel_absent': True}
        else:
            raise Refused('protected_fault_not_observed')
        if read_regular(receipt)[0] != b'emitted-to-both-streams\n':
            raise Refused('protected_fault_emission_unverified')
    return observations


def execute(guest):
    trusted_install()
    if Path(__file__).resolve() != INSTALL / 'protected_output.py' or sys.executable != PYTHON:
        raise Refused('protected_output_installed_runtime_required')
    for name, expected in DEPENDENCIES.items():
        raw, _ = read_regular(INSTALL / name)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise Refused('protected_output_dependency_mismatch')
    parent = private_directory(Path('/var/lib/mpkg-proofs') / guest)
    directory = parent / 'protected-output'
    # Atomic reservation rejects both previous terminal and uncertain attempts.
    directory.mkdir(mode=0o700)
    journal = Journal(directory)
    try:
        attempt = str(uuid.uuid4())
        journal.begin(attempt)
        home = private_directory(directory / 'home')
        empty = private_directory(directory / 'empty-template-and-hooks')
        repository = private_directory(directory / 'repository')
        environment = isolated_environment(home)
        sentinel = ('MPKG_PRIVATE_SENTINEL_' + uuid.uuid4().hex).encode()
        source = directory / 'private-input'
        write_new(source, sentinel)
        reference = journal.capture(source)
        key = journal.db.execute('SELECT key FROM private_key').fetchone()[0]
        token = journal.db.execute('SELECT token FROM protected WHERE id=?', (reference,)).fetchone()[0]
        forbidden = [sentinel, reference.encode(), key, token, key.hex().encode(), token.hex().encode()]
        projection = canonical(journal.export()) + b'\n'
        no_protected_bytes(projection, forbidden)

        def git(*arguments):
            return command(['/usr/bin/git', '-c', 'core.hooksPath=' + str(empty),
                            '-c', 'core.attributesFile=/dev/null',
                            '-c', 'credential.helper=', '-c', 'protocol.allow=never',
                            '-c', 'commit.gpgSign=false', '-c', 'tag.gpgSign=false',
                            '-c', 'user.name=mpkg disposable proof',
                            '-c', 'user.email=fixture@invalid', *arguments],
                           cwd=repository, env=environment)

        git('init', '--quiet', '--object-format=sha1', '--initial-branch=proof',
            '--template=' + str(empty), '.')
        write_new(repository / 'projection.json', projection)
        git('add', '--', 'projection.json')
        git('commit', '--quiet', '--no-gpg-sign', '-m', 'Record public fixture projection')
        objects = git_objects(git, projection, forbidden)
        faults = command_faults(directory, sentinel, environment)
        result = {'schema': 1, 'guest_id': guest, 'proof': 'protected-output',
                  'status': 'observed', 'product_acceptance': False,
                  'projection_has_no_protected_bytes': True,
                  'all_git_objects_match_reachable_scope': True,
                  'git_object_types': objects, 'command_faults': faults,
                  'earlier_proof_records_untouched': True,
                  'limits': ['Selected private projection and fixed command boundaries only.',
                             'No future product Git staging or arbitrary error path is implemented.',
                             'Private synthetic plaintext and the isolated Git repository remain for inspection.',
                             'Timeout and output faults have no descendants or external daemon effects.']}
        no_protected_bytes(canonical(result), forbidden)
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
    os.umask(0o077)
    return execute(guest)


if __name__ == '__main__':
    try:
        print(json.dumps(main(), sort_keys=True))
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error), 'product_acceptance': False}))
        sys.exit(73)
    except FileExistsError:
        print(json.dumps({'status': 'refused', 'code': 'protected_output_fresh_attempt_required',
                          'product_acceptance': False}))
        sys.exit(73)
    except Exception:
        print(json.dumps({'status': 'unverified', 'code': 'protected_output_failed',
                          'product_acceptance': False}))
        sys.exit(74)
