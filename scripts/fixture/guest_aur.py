#!/usr/bin/env python3
"""Build the pinned AUR inputs only inside the bound disposable Arch guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import stat
import subprocess
import sys

sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, identity, require_guest, write_new

PYTHON = '/opt/mpkg-python/3.12.16/bin/python3.12'
INPUTS = Path('/opt/mpkg-proof-inputs')
STATE = Path('/var/lib/mpkg-fixture')
INSTALLED = Path('/opt/mpkg-fixture/guest_aur.py')
SOURCE_SHA = 'c4713eff10cd435487a043a093e02bc596e88a10853e2d6e8ae7d3e384418c30'
UID = 1502
ENV = {'PATH': '/usr/bin', 'LC_ALL': 'C', 'HOME': '/root'}
BUILD_DEPENDENCIES = {'cmake', 'cppdap', 'hicolor-icon-theme', 'jsoncpp', 'libuv', 'rhash', 'zsh'}


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, env=ENV, timeout=3500, **kwargs)


def checked_file(path, expected=None, root=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > 128*1024**2
                or (root and (before.st_uid != 0 or stat.S_IMODE(before.st_mode) & 0o022))):
            raise Refused('untrusted_fixture_input')
        data = stream.read(128*1024**2+1)
        if identity(os.fstat(stream.fileno())) != identity(before) or len(data) != before.st_size:
            raise Refused('fixture_input_changed_during_read')
    if expected and hashlib.sha256(data).hexdigest() != expected:
        raise Refused('fixture_input_changed')
    return data


def inventory():
    return dict(line.split() for line in run(['/usr/bin/pacman', '-Q'], capture_output=True).stdout.decode().splitlines())


def verify_baseline(source, with_ack):
    names = set(source['resolutions']['native_change']['resolved_package_names'])
    expected = {p['name']: p['version'] for p in source['repository_packages'] if p['name'] in names}
    if with_ack:
        expected.update({p['package_base']: p['srcinfo_version'] for p in source['aur_packages']
                         if p['package_base'] in {'ack', 'perl-file-next'}})
    if inventory() != expected:
        raise Refused('native_change_baseline_changed')


def as_builder(arguments, work, output=None):
    command = ['/usr/bin/runuser', '-u', 'mpkg-aurbuild', '--', '/usr/bin/env', '-i',
               'PATH=/usr/bin', 'LC_ALL=C', 'HOME='+str(work), 'MAKEFLAGS=-j1',
               'CMAKE_BUILD_PARALLEL_LEVEL=1', *arguments]
    return run(command, cwd=work, stdout=output)


def normalized_srcinfo(data):
    return sorted(line.strip() for line in data.decode().splitlines()
                  if line.strip() and not line.lstrip().startswith('#'))


def require_idle_unit(status):
    if status.get('MainPID') != '0' or status.get('ControlPID') != '0':
        raise Refused('another_heavy_guest_build_is_active')
    inactive = status.get('ActiveState') in {'inactive', 'failed'}
    completed = (status.get('ActiveState') == 'active' and status.get('SubState') == 'exited'
                 and status.get('ExecMainStatus') == '0' and status.get('Result') == 'success')
    if not (inactive or completed):
        raise Refused('build_activity_unknown')


def build_one(source, package, guest, state):
    recipe = next(p for p in source['aur_packages'] if p['package_base'] == package)
    work = Path('/var/lib/mpkg-aur-build') / package
    work.mkdir(mode=0o700)
    os.chown(work, UID, UID)
    recipe_hashes = {}
    verified_sources = []
    for name, entry in recipe['recipe_files'].items():
        data = checked_file(INPUTS/'sources'/package/name, entry['sha256_computed'])
        write_new(work/name, data)
        os.chown(work/name, UID, UID)
        recipe_hashes[name] = entry['sha256_computed']
    for entry in recipe['sources']:
        name = entry['filename']
        data = checked_file(INPUTS/'sources'/package/name)
        for algorithm, digest in entry['digests_published_in_recipe'].items():
            if hashlib.new(algorithm, data).hexdigest() != digest:
                raise Refused('pinned_aur_source_changed')
            verified_sources.append({'filename': name, 'algorithm': algorithm, 'digest': digest, 'verified': True})
        write_new(work/name, data)
        os.chown(work/name, UID, UID)
    # Preserve package defaults while forcing real checks and a single non-debug archive.
    config = checked_file(Path('/etc/makepkg.conf')) + b'\nBUILDENV=(!distcc !color !ccache check !sign)\nOPTIONS=(strip docs !libtool !staticlibs emptydirs zipman purge !debug lto)\nPKGEXT=.pkg.tar.zst\n'
    config_path = work.parent/(package+'.makepkg.conf')
    write_new(config_path, config, mode=0o644)
    os.chmod(config_path, 0o644)
    arguments = ['/usr/bin/makepkg', '--config', str(config_path)]
    generated = state/(package+'-generated.SRCINFO')
    with generated.open('xb') as output:
        as_builder(arguments+['--printsrcinfo'], work, output)
    if normalized_srcinfo(generated.read_bytes()) != normalized_srcinfo((work/'.SRCINFO').read_bytes()):
        raise Refused('generated_srcinfo_differs_from_pinned_recipe')
    as_builder(arguments+['--verifysource', '--noconfirm'], work)
    as_builder(arguments+['--cleanbuild', '--noconfirm'], work)
    for name, digest in recipe_hashes.items():
        checked_file(work/name, digest, root=False)
    artifacts = list(work.glob('*.pkg.tar.zst'))
    if len(artifacts) != 1:
        raise Refused('ambiguous_built_artifact')
    data = checked_file(artifacts[0], root=False)
    if not 0 < len(data) <= 64*1024**2:
        raise Refused('build_artifact_size')
    # Freeze captured bytes under the root-private artifact directory before
    # parsing package metadata; the builder cannot swap the inspected archive.
    digest = hashlib.sha256(data).hexdigest()
    artifact = INPUTS/'artifacts'/(digest+'.pkg.tar.zst')
    write_new(artifact, data)
    metadata = run(['/usr/bin/bsdtar', '-xOf', str(artifact), '.PKGINFO'], capture_output=True).stdout.decode()
    pairs = [line.split(' = ', 1) for line in metadata.splitlines()
             if line.startswith(('pkgname = ', 'pkgver = '))]
    fields = dict(pairs)
    if len(pairs) != 2 or fields != {'pkgname': package, 'pkgver': recipe['srcinfo_version']}:
        raise Refused('built_package_identity_changed')
    result = {'schema': 1, 'guest_id': guest, 'package_base': package,
              'recipe_commit': recipe['recipe_commit'], 'recipe_files': recipe_hashes,
              'sources': verified_sources, 'build_uid': UID, 'source_verification_exit_code': 0,
              'generated_metadata_matches': True, 'build_exit_code': 0,
              'check_status': 'not-defined' if package == 'gitstatus' else 'passed',
              'makepkg_configuration_sha256': hashlib.sha256(config).hexdigest(),
              'worker_sha256': hashlib.sha256(checked_file(INSTALLED)).hexdigest(),
              'artifact': {'name': package, 'version': recipe['srcinfo_version'],
                           'sha256': digest, 'size': len(data)}}
    write_new(INPUTS/(package+'-build.json'), (json.dumps(result, indent=2)+'\n').encode())
    return artifact


def worker(mode, guest, state):
    source = json.loads(checked_file(INPUTS/'source-inventory.json', SOURCE_SHA))
    verify_baseline(source, with_ack=mode == 'gitstatus')
    try:
        user = pwd.getpwnam('mpkg-aurbuild')
        if user.pw_uid != UID or user.pw_gid != UID:
            raise Refused('builder_identity_changed')
    except KeyError:
        run(['/usr/bin/groupadd', '--gid', str(UID), 'mpkg-aurbuild'])
        run(['/usr/bin/useradd', '--uid', str(UID), '--gid', str(UID), '--no-create-home',
             '--home-dir', '/var/lib/mpkg-aur-build', '--shell', '/usr/bin/nologin', 'mpkg-aurbuild'])
    workspace = Path('/var/lib/mpkg-aur-build')
    if not workspace.exists():
        workspace.mkdir(mode=0o755)
        os.chmod(workspace, 0o755)
    if workspace.is_symlink() or workspace.stat().st_uid != 0 or workspace.stat().st_mode & 0o022:
        raise Refused('builder_workspace_changed')
    if mode == 'gitstatus':
        # The separate output disk's authorization is created only after the host checkpoint.
        output = Path('/run/mpkg-build-output')
        device = tuple(int(v) for v in Path('/sys/class/block/vdd/dev').read_text().strip().split(':'))
        actual = os.stat(output).st_dev
        if ((os.major(actual), os.minor(actual)) != device
                or Path('/sys/class/block/vdd/serial').read_text().strip() != 'mpkgout'+guest.replace('-', '')[:13]
                or int(Path('/sys/class/block/vdd/size').read_text())*512 != 128*1024**2):
            raise Refused('bound_build_output_disk_required')
        authorization = json.loads(checked_file(output/'authorization.json'))
        if (authorization['guest_id'] != guest or authorization['checkpoint'] != 'native-change'
                or not re.fullmatch('[0-9a-f]{64}', authorization['checkpoint_record_sha256'])):
            raise Refused('preserved_baseline_required')
        selected = [p for p in source['repository_packages'] if p['name'] in BUILD_DEPENDENCIES]
        if len(selected) != len(BUILD_DEPENDENCIES):
            raise Refused('build_dependency_set_changed')
        archives = []
        for package in selected:
            digest = package['package_sha256_published_in_database']
            path = INPUTS/'artifacts'/(digest+'.pkg.tar.zst')
            checked_file(path, digest)
            archives.append(str(path))
        # System pacman policy still requires repository package signatures.
        expected = inventory() | {p['name']: p['version'] for p in selected}
        run(['/usr/bin/pacman', '-U', '--noconfirm', *archives])
        if inventory() != expected:
            raise Refused('build_dependency_transaction_changed_other_packages')
        artifact = build_one(source, 'gitstatus', guest, state)
        if inventory() != expected:
            raise Refused('package_build_changed_installed_state')
        write_new(output/'gitstatus.pkg.tar.zst', checked_file(artifact))
        write_new(output/'gitstatus-build.json', checked_file(INPUTS/'gitstatus-build.json'))
        os.sync()
    else:
        # This repository-free configuration accepts only the exact artifacts
        # whose pinned sources, checks, package identity and bytes were just verified.
        config = state/'fixture-build-pacman.conf'
        write_new(config, b'[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Never\n')
        for package in ('perl-file-next', 'ack'):
            artifact = build_one(source, package, guest, state)
            run(['/usr/bin/pacman', '--config', str(config), '-U', '--noconfirm', str(artifact)])
        run(['/usr/bin/pacman', '-D', '--asdeps', 'perl-file-next'])
        verify_baseline(source, with_ack=True)


def main():
    if sys.version_info[:2] != (3, 12):
        raise Refused('python_312_required')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-id', default=os.environ.get('MPKG_GUEST_ID'))
    parser.add_argument('--mode', choices=['ack', 'gitstatus'], default='ack')
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    guest = require_guest(args.guest_id)
    os.umask(0o077)
    mode = args.mode
    state = STATE/('aur-'+mode)
    if args.worker:
        checked_file(INSTALLED)
        code = 1
        try:
            worker(mode, guest, state)
            write_new(state/'complete', (guest+'\n').encode())
            code = 0
        finally:
            write_new(state/'exit', (str(code)+'\n').encode())
        return
    for unit in ('mpkg-fixture-python-build.service', 'mpkg-fixture-aur-ack.service',
                 'mpkg-fixture-aur-gitstatus.service'):
        result = subprocess.run(['/usr/bin/systemctl', 'show', '--property=ActiveState,SubState,MainPID,ControlPID,ExecMainStatus,Result,ControlGroup', unit], env=ENV, timeout=10, check=True, capture_output=True)
        status = dict(line.split('=', 1) for line in result.stdout.decode().splitlines())
        require_idle_unit(status)
        group = status.get('ControlGroup')
        if group:
            if group != '/system.slice/'+unit:
                raise Refused('unexpected_build_control_group')
            events = dict(line.split() for line in (Path('/sys/fs/cgroup')/group.lstrip('/')/'cgroup.events').read_text().splitlines())
            if events.get('populated') != '0':
                raise Refused('build_descendants_still_running')
    state.mkdir(mode=0o700)
    data = checked_file(Path(__file__).resolve())
    if not INSTALLED.parent.exists():
        INSTALLED.parent.mkdir(mode=0o700)
    if INSTALLED.exists():
        if checked_file(INSTALLED) != data:
            raise Refused('installed_builder_changed')
    else:
        write_new(INSTALLED, data)
    unit = 'mpkg-fixture-aur-'+mode+'.service'
    content = ('[Unit]\nDescription=Bound disposable AUR fixture build\n'
               '[Service]\nType=oneshot\nUMask=0077\nPrivateNetwork=yes\n'
               'TimeoutStartSec=3600\nTimeoutStopSec=15\nKillMode=control-group\nLimitCORE=0\n'
               'StandardOutput=append:'+str(state/'build.log')+'\nStandardError=inherit\n'
               'ExecStart='+PYTHON+' -I '+str(INSTALLED)+' --worker --mode '+mode+' --guest-id '+guest+'\n')
    write_new(Path('/etc/systemd/system')/unit, content.encode())
    write_new(state/'started', (guest+'\n').encode())
    run(['/usr/bin/systemctl', 'daemon-reload'])
    run(['/usr/bin/systemctl', 'start', '--no-block', unit])
    print(json.dumps({'status': 'started', 'mode': mode, 'guest_id': guest, 'unit': unit}))


if __name__ == '__main__':
    main()
