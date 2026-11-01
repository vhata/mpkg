#!/usr/bin/env python3
"""Acquire and extract a verified QEMU runner without host installation."""
import argparse
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
from contextlib import contextmanager
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import uuid

PROJECT = Path(__file__).resolve().parents[2]
CACHE = PROJECT / '.cache' / 'fixture'
INPUTS = Path(__file__).with_name('runner-inputs.json')
KEYRINGS = Path('/usr/share/pacman/keyrings')
SAFE_ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private_directory(path):
    """Reject existing symlinks along a cache path before creating it."""
    path = Path(path).absolute()
    for part in reversed((path, *path.parents)):
        if part.exists() or part.is_symlink():
            if part.is_symlink() or not part.is_dir():
                raise ValueError(f'unsafe directory: {part}')
        else:
            part.mkdir(mode=0o700)
    if path.stat().st_uid != os.getuid():
        raise ValueError('cache directory is owned by another account')
    return path


def regular_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f'not a private regular file: {path}')
    return path


def write_new(path, data, mode=0o600):
    private_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def checked_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'archive.archlinux.org'
            or parsed.query or parsed.fragment or '\\' in parsed.path
            or '%' in parsed.path or '..' in PurePosixPath(parsed.path).parts):
        raise ValueError('only fixed HTTPS Arch archive URLs are permitted')
    return url


class ArchiveRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@contextmanager
def artifact_deadline(seconds=1800):
    def expired(signum, frame):
        raise TimeoutError('artifact acquisition exceeded its overall deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def download(url, destination, max_bytes, expected_digest=None, exact_size=None):
    checked_url(url)
    private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        regular_file(destination)
        if destination.stat().st_size > max_bytes:
            raise ValueError('cached artifact exceeds size bound')
        if expected_digest is not None and sha256(destination) != expected_digest:
            raise ValueError('cached artifact digest mismatch')
        if exact_size is not None and destination.stat().st_size != exact_size:
            raise ValueError('cached artifact size mismatch')
        return
    partial = destination.with_name(destination.name + '.part')
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ArchiveRedirect())
        digest = hashlib.sha256()
        count = 0
        with os.fdopen(fd, 'wb') as output, artifact_deadline(), opener.open(url, timeout=60) as response:
            if response.status != 200:
                raise ValueError('artifact server did not return HTTP 200')
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > max_bytes:
                    raise ValueError('artifact exceeds declared size bound')
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if expected_digest is not None and digest.hexdigest() != expected_digest:
            raise ValueError('downloaded artifact digest mismatch')
        if exact_size is not None and count != exact_size:
            raise ValueError('downloaded artifact size mismatch')
        os.link(partial, destination, follow_symlinks=False)
    finally:
        partial.unlink(missing_ok=True)


def run_gpg(home, arguments, input_bytes=None):
    return subprocess.run([
        '/usr/bin/gpg', '--no-options', '--batch', '--no-tty', '--no-autostart',
        '--homedir', str(home), '--no-auto-key-retrieve', '--auto-key-locate', 'clear',
        *arguments,
    ], input=input_bytes, capture_output=True, env=SAFE_ENV, timeout=120)


def trust_home(cache):
    """Publish a complete private trust store; keep failed staging for diagnosis."""
    # Long worktree paths exceed the Unix socket limit even with --no-autostart.
    home = cache.parent / 'g'
    staging = cache.parent / 'h'
    if any(len(os.fsencode(path / 'S.gpg-agent.browser')) >= 108 for path in (home, staging)):
        raise ValueError('worktree path is too long for the private GPG socket name')
    if home.exists():
        private_directory(home)
        marker = regular_file(home / 'keyring-inputs.json')
        expected = json.loads(marker.read_text())
        for name, digest in expected.items():
            if sha256(KEYRINGS / name) != digest:
                raise ValueError('host Arch trust input changed; create a new cache')
        return home
    staging.mkdir(mode=0o700)  # Exclusive fixed short staging name; concurrent init fails closed.
    files = ['archlinux.gpg', 'archlinux-trusted', 'archlinux-revoked']
    hashes = {name: sha256(KEYRINGS / name) for name in files}
    roots = []
    for line in (KEYRINGS / 'archlinux-trusted').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        fingerprint = line.split(':')[0]
        if not re.fullmatch('[A-F0-9]{40}', fingerprint):
            raise ValueError('invalid Arch master fingerprint')
        roots.append(fingerprint)
    if not roots:
        raise ValueError('no trusted Arch master keys')
    steps = [(['--import', str(KEYRINGS / 'archlinux.gpg')], None),
             (['--import-ownertrust'], ''.join(f'{key}:6:\n' for key in roots).encode()),
             (['--check-trustdb'], None)]
    for index, (arguments, input_bytes) in enumerate(steps):
        result = run_gpg(staging, arguments, input_bytes)
        if result.returncode:
            write_new(staging / f'failed-step-{index}.txt', result.stderr[:262144])
            preserved = cache.parent / ('gpg-failed-' + uuid.uuid4().hex)
            staging.rename(preserved)
            raise RuntimeError(f'private GPG initialization step {index} failed; preserved {preserved.name}')
    write_new(staging / 'keyring-inputs.json', (json.dumps(hashes, indent=2) + '\n').encode())
    if home.exists() or home.is_symlink():
        raise ValueError('private GPG publication target appeared during initialization')
    staging.rename(home)
    return home


def verify_signature(home, artifact, signature):
    regular_file(artifact)
    regular_file(signature)
    result = run_gpg(home, ['--status-fd', '1', '--verify', str(signature), str(artifact)])
    statuses = [line[len('[GNUPG:] '):].split() for line in result.stdout.decode(errors='replace').splitlines()
                if line.startswith('[GNUPG:] ')]
    valid = [line for line in statuses if line[0] == 'VALIDSIG']
    trusted = any(line[0] in {'TRUST_FULLY', 'TRUST_ULTIMATE'} for line in statuses)
    rejected = {'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYREVOKED'}
    if result.returncode or len(valid) != 1 or not trusted or any(s[0] in rejected for s in statuses):
        raise ValueError(f'archive signature is not valid under explicit Arch roots: {artifact.name}')
    signer = valid[0][1]
    primary = valid[0][-1]
    revoked = set((KEYRINGS / 'archlinux-revoked').read_text().splitlines())
    if signer in revoked or primary in revoked:
        raise ValueError('signature uses a revoked Arch key')
    return {'signing_fingerprint': signer, 'primary_fingerprint': primary,
            'signature_sha256': sha256(signature), 'trust': 'Arch master roots; full GPG validity'}


def packages():
    data = json.loads(INPUTS.read_text())
    for package in data['packages']:
        if not re.fullmatch('[a-f0-9]{64}', package['sha256']):
            raise ValueError('invalid expected package digest')
        checked_url(package['url'])
        if not (0 < package['size'] < 1024 ** 3):
            raise ValueError('invalid archive size')
    return data['packages']


def acquire(cache):
    home = trust_home(cache)
    evidence = []
    for package in packages():
        path = cache / 'archives' / (package['sha256'] + '.pkg.tar.zst')
        download(package['url'], path, package['size'], package['sha256'], package['size'])
        signature = path.with_name(path.name + '.sig')
        download(package['url'] + '.sig', signature, 16384)
        proof = verify_signature(home, path, signature)
        evidence.append({'name': package['name'], 'version': package['version'],
                         'sha256': sha256(path), **proof})
        print(f"verified {package['name']} {package['version']}", flush=True)
    target = cache / 'runner-acquisition.json'
    if target.exists():
        regular_file(target)
        target.unlink()
    write_new(target, (json.dumps(evidence, indent=2) + '\n').encode())


def verify_iso(cache):
    manifest = json.loads((PROJECT / 'docs/fixtures/2026-10-31-arch-native-inputs.json').read_text())
    name = 'archlinux-2026.10.01-x86_64.iso'
    source = PROJECT / '.cache' / 'artifacts' / (name + '.part')
    regular_file(source)
    expected = manifest['iso']
    if (source.stat().st_size != expected['content_length_observed_via_head']
            or sha256(source) != expected['sha256_published']):
        raise ValueError('ISO size or digest mismatch')
    signature = source.with_name(name + '.sig')
    proof = verify_signature(trust_home(cache), source, signature)
    write_new(cache / 'iso-verification.json', (json.dumps({
        'filename': name, 'sha256': sha256(source), 'bytes': source.stat().st_size,
        **proof,
    }, indent=2) + '\n').encode())
    print('ISO verified under explicit Arch master roots', flush=True)


def member_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('unsafe archive member path')
    return path


def validate_member(member):
    path = member_path(member.name)
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise ValueError('archive contains a special file')
    if member.issym():
        target = PurePosixPath(member.linkname)
        if target.is_absolute():
            if member.linkname.startswith('//') or '..' in target.parts:
                raise ValueError('ambiguous absolute archive symlink')
            # Interpret package absolute links under the private extracted root.
            target = PurePosixPath(posixpath.relpath(member.linkname.lstrip('/'), str(path.parent)))
            member.linkname = str(target)
        depth = len(path.parent.parts)
        for part in target.parts:
            depth += -1 if part == '..' else 0 if part == '.' else 1
            if depth < 0:
                raise ValueError('archive symlink escapes extraction root')
    if member.islnk():
        member_path(member.linkname)
    return path


def extraction_target(root, relative):
    path = root.joinpath(*relative.parts)
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError('archive path traverses existing symlink')
    if path.is_symlink():
        raise ValueError('archive would replace an existing symlink')
    return path


def extract_tar(archive, root):
    """No tar extraction helpers: all member writes are explicitly bounded."""
    private_directory(root)
    with tarfile.open(fileobj=archive, mode='r:') as tar:
        members = [(m, validate_member(m)) for m in tar.getmembers()]
        links = []
        for member, relative in members:
            if len(relative.parts) == 1 and relative.name.startswith('.'):
                continue  # Per-package metadata must not overwrite other packages.
            target = extraction_target(root, relative)
            if member.isdir():
                private_directory(target)
            elif member.issym():
                private_directory(target.parent)
                os.symlink(member.linkname, target)
            elif member.islnk():
                links.append((target, member_path(member.linkname)))
            else:
                private_directory(target.parent)
                if target.exists():
                    raise ValueError(f'archive file collision: {relative}')
                mode = 0o755 if member.mode & 0o111 else 0o644
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
                with os.fdopen(fd, 'wb') as output, tar.extractfile(member) as source:
                    shutil.copyfileobj(source, output)
        for target, relative in links:
            source = extraction_target(root, relative)
            if not stat.S_ISREG(source.lstat().st_mode):
                raise ValueError('hardlink target is not a regular extracted file')
            private_directory(target.parent)
            os.link(source, target, follow_symlinks=False)


def extract(cache):
    home = trust_home(cache)
    destination = cache / 'runner'
    if destination.exists() or destination.is_symlink():
        private_directory(destination)
        if (destination / '.mpkg-verified-runner.json').exists():
            raise ValueError('a completed runner already exists; preserve it')
        preserved = cache / ('runner-failed-' + uuid.uuid4().hex)
        destination.rename(preserved)
        print(f'preserved incomplete extraction: {preserved.name}', flush=True)
    private_directory(destination)
    for package in packages():
        path = regular_file(cache / 'archives' / (package['sha256'] + '.pkg.tar.zst'))
        if sha256(path) != package['sha256']:
            raise ValueError('archive changed after acquisition')
        verify_signature(home, path, path.with_name(path.name + '.sig'))
        with tempfile.TemporaryFile(dir=cache) as temporary:
            subprocess.run(['/usr/bin/zstd', '-d', '-c', '--', str(path)], stdout=temporary,
                           stderr=subprocess.PIPE, check=True, env=SAFE_ENV, timeout=120)
            temporary.seek(0)
            extract_tar(temporary, destination)
        print(f"extracted {package['name']}", flush=True)
    for path in destination.rglob('*'):
        if path.is_symlink() and not path.resolve().is_relative_to(destination):
            raise ValueError('extracted symlink graph escapes private root')
    write_new(destination / '.mpkg-verified-runner.json', json.dumps({
        'inputs_sha256': sha256(INPUTS), 'packages': len(packages()),
        'host_packages_installed': False,
    }, indent=2).encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['acquire', 'extract', 'verify-iso'])
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error('Python 3.12 is required')
    os.umask(0o077)
    cache = private_directory(CACHE)
    os.chmod(cache, 0o700)
    {'acquire': acquire, 'extract': extract, 'verify-iso': verify_iso}[args.operation](cache)


if __name__ == '__main__':
    main()
