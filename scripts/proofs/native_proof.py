"""Real libalpm prepare/revalidation; never commits or refreshes the live DB."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import uuid

from core import Journal, Refused, private_directory, read_regular, write_new
from experiments import fresh
from run import INSTALL, command


INPUTS = Path('/opt/mpkg-proof-inputs')


def artifact_path(record):
    path = Path(record['path'])
    if not path.is_absolute() or not path.is_relative_to(INPUTS):
        raise Refused('artifact_outside_fixture_inputs')
    current = INPUTS
    for part in path.relative_to(INPUTS).parts:
        if part in ('.', '..'):
            raise Refused('artifact_path_unsupported')
        current /= part
        info = current.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise Refused('artifact_not_private')
    if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 ** 3:
        raise Refused('artifact_shape_unsupported')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != record['sha256']:
        raise Refused('artifact_digest_mismatch')
    return path


def fingerprint(path):
    digest = hashlib.sha256()
    for item in sorted(path.rglob('*')):
        if item.is_symlink():
            raise Refused('database_symlink_unsupported')
        if item.is_file():
            raw, _ = read_regular(item)
            digest.update(str(item.relative_to(path)).encode() + b'\0' + raw)
    return digest.hexdigest()


def package_lines(artifacts):
    lines = []
    for item in artifacts:
        source = item['source']
        if source not in ('repository', 'fixture-build'):
            raise Refused('artifact_source_unsupported')
        fields = [source, item['name'], item['version'], item['path']]
        if any(not isinstance(field, str) or not field or
               any(c in field for c in '\t\r\n') for field in fields):
            raise Refused('artifact_metadata_invalid')
        lines.append('\t'.join(fields))
    return ('\n'.join(lines) + '\n').encode()


def run(guest, root):
    raw, info = read_regular(INPUTS / 'native.json')
    if info[4] != 0 or stat.S_IMODE(info[6]) & 0o022:
        raise Refused('native_manifest_not_trusted')
    manifest = json.loads(raw)
    if manifest.get('schema') != 1 or manifest.get('guest_id') != guest:
        raise Refused('native_manifest_identity')
    artifacts = manifest['artifacts']
    by_name = {item['name']: item for item in artifacts}
    if len(by_name) != len(artifacts):
        raise Refused('duplicate_artifact_name')
    for artifact in artifacts:
        artifact_path(artifact)
    targets = manifest['targets']
    if (not targets or len(targets) != len(set(targets))
            or any(not re.fullmatch(r'[a-z0-9@._+-]+', target) for target in targets)):
        raise Refused('native_targets_invalid')
    directory = fresh(root, 'native')
    database = private_directory(directory / 'staged-db')
    local = Path('/var/lib/pacman/local')
    live_sync = Path('/var/lib/pacman/sync')
    local_before = fingerprint(local)
    sync_before = fingerprint(live_sync)
    shutil.copytree(local, database / 'local', symlinks=True)
    if fingerprint(local) != local_before or fingerprint(database / 'local') != local_before:
        raise Refused('installed_snapshot_unstable')
    private_directory(database / 'sync')
    repos = manifest['repository_databases']
    if {item['name'] for item in repos} != {'core', 'extra'} or len(repos) != 2:
        raise Refused('frozen_repositories_required')
    for repository in repos:
        source = artifact_path(repository)
        shutil.copyfile(source, database / 'sync' / (repository['name'] + '.db'))
        if repository.get('signature'):
            signature = artifact_path(repository['signature'])
            shutil.copyfile(signature, database / 'sync' / (repository['name'] + '.db.sig'))
    write_new(directory / 'targets.list', ('\n'.join(targets) + '\n').encode())
    write_new(directory / 'packages.list', package_lines(artifacts))
    binary = directory / 'alpm-probe'
    command(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
             str(INSTALL / 'alpm_probe.c'), '-lalpm', '-o', str(binary)], timeout=90)
    binary.chmod(0o700)

    def probe(mode):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, ('MPKG-PROOF:' + guest + '\n').encode())
            os.close(write_fd)
            write_fd = None
            return command([str(binary), mode, guest, str(read_fd)],
                           timeout=90, pass_fds=(read_fd,))
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)

    accepted = probe('stage')
    if accepted.startswith(b'BLOCK '):
        raise Refused('staged_transaction_blocked')
    rows = [line.split('\t') for line in accepted.decode().splitlines()]
    version_rows = [row for row in rows if row[0] == 'V']
    if len(version_rows) != 1 or version_rows[0][1] != manifest['libalpm_version']:
        raise Refused('libalpm_version_mismatch')
    added = {row[1] for row in rows if row[0] == 'A'}
    if not set(targets) <= added or 'libutempter' not in added:
        raise Refused('missing_dependency_baseline_required')
    if any(row[0] == 'R' for row in rows):
        raise Refused('removal_fixture_not_supported')
    selected = [by_name[name] for name in sorted(added)]
    (directory / 'packages.list').write_bytes(package_lines(selected))
    write_new(directory / 'accepted.plan', accepted)
    journal = Journal(directory)
    attempt = str(uuid.uuid4())
    journal.begin(attempt)
    if probe('compare') != b'MATCH\n':
        raise Refused('live_prepared_set_differs')
    (directory / 'accepted.plan').write_bytes(accepted + b'I\tinvented\t0\t0\n')
    if probe('compare') != b'BLOCK prepared-set-mismatch\n':
        raise Refused('accepted_scope_mismatch_not_blocked')
    (directory / 'accepted.plan').write_bytes(accepted)
    without_dependency = [item for item in selected if item['name'] != 'libutempter']
    (directory / 'packages.list').write_bytes(package_lines(without_dependency))
    if probe('compare') != b'BLOCK missing-dependency\n':
        raise Refused('missing_dependency_not_blocked')
    # An explicitly synthetic unsigned archive tests native conflict handling.
    conflict = directory / 'conflict.pkg.tar'
    metadata = (b'pkgname = mpkg-proof-conflict\npkgbase = mpkg-proof-conflict\n'
                b'pkgver = 1-1\npkgdesc = Disposable conflict probe\n'
                b'builddate = 0\npackager = fixture\nsize = 0\narch = any\n'
                b'conflict = filesystem\n')
    with tarfile.open(conflict, 'w') as archive:
        member = tarfile.TarInfo('.PKGINFO')
        member.size = len(metadata)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(metadata))
    conflict_record = {'source': 'fixture-build', 'name': 'mpkg-proof-conflict',
                       'version': '1-1', 'path': str(conflict)}
    (directory / 'packages.list').write_bytes(package_lines(selected + [conflict_record]))
    if probe('compare') not in (b'BLOCK conflict\n', b'BLOCK native-question\n'):
        raise Refused('native_conflict_not_blocked')
    if fingerprint(local) != local_before or fingerprint(live_sync) != sync_before:
        raise Refused('live_package_database_changed')
    journal.finish(attempt, 'observed-complete')
    journal.close()
    return {'status': 'observed', 'prepared_add_count': len(added),
            'exact_staged_live_match': True, 'scope_mismatch_blocks': True,
            'missing_dependency_blocks': True, 'native_conflict_blocks': True,
            'live_sync_and_local_unchanged': True,
            'libalpm_version': manifest['libalpm_version'],
            'limits': ['Prepare-only bridge: no installation, hooks or upgrade commit tested.',
                       'Conflict archive is a disclosed synthetic fixture.',
                       'Install reasons are compared as current inventory, not changed.',
                       'ABI compilation and signature checks must succeed inside this guest.']}
