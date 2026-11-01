#!/usr/bin/env python3
"""Preserve a guest-built artifact across an offline baseline restore."""
import argparse
import json
import os
from pathlib import Path
import resource
import re
import subprocess
import sys
import uuid

import inputs
import native
import runner
import snapshot
import vm

SIZE = 128*1024**2


def image_from_tree(tree, image, label):
    fd = os.open(image, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.truncate(SIZE)
    subprocess.run(['/usr/bin/mkfs.ext4', '-q', '-F', '-L', label, '-E',
                    'root_owner=0:0', '-d', str(tree), str(image)],
                   check=True, env=runner.SAFE_ENV, timeout=120)
    # mkfs -d retains the host UID on descendants. Normalize only these fixed
    # new image members, using the verified private tool and no host chown.
    for member in sorted(tree.iterdir()):
        runner.regular_file(member)
        if not re.fullmatch('[a-zA-Z0-9_.-]+', member.name):
            raise ValueError('unsafe image member name')
        for field in ('uid', 'gid'):
            command = vm.sandbox_command(['/usr/bin/debugfs', '-w', '-R',
                         'set_inode_field /'+member.name+' '+field+' 0',
                         '/run/mpkg-image.img'], writable_vm=False)
            command[command.index('--chdir'):command.index('--chdir')] = [
                '--unshare-net', '--bind', str(image), '/run/mpkg-image.img']
            subprocess.run(command, check=True, env=runner.SAFE_ENV, timeout=30,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        command = vm.sandbox_command(['/usr/bin/debugfs', '-R', 'stat /'+member.name,
                                     '/run/mpkg-fixture/'+image.name], writable_vm=False)
        result = subprocess.run(command, check=True, env=runner.SAFE_ENV, timeout=30,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not re.search(rb'User:\s+0\s+Group:\s+0\b', result.stdout):
            raise ValueError('generated image member ownership was not normalized')


def prepare(identity):
    record = runner.regular_file(vm.VM/'snapshots/native-change.json')
    checkpoint = json.loads(record.read_text())
    found = next((s for s in snapshot.info().get('snapshots', []) if s['name'] == 'native-change'), None)
    if (checkpoint['guest_id'] != identity['guest_id'] or not checkpoint['vm_stopped']
            or found is None or found['id'] != checkpoint['snapshot']['id']):
        raise ValueError('the native-change baseline must be preserved first')
    tree = vm.VM/'output-initial-tree'
    tree.mkdir(mode=0o700)
    authorization = {'schema': 1, 'guest_id': identity['guest_id'], 'checkpoint': 'native-change',
                     'checkpoint_record_sha256': runner.sha256(record)}
    runner.write_new(tree/'authorization.json', (json.dumps(authorization, indent=2)+'\n').encode())
    image = vm.VM/'outputs.img'
    image_from_tree(tree, image, 'MPKG_OUTPUT')
    evidence = {**authorization, 'disk_bytes': SIZE, 'initial_sha256': runner.sha256(image),
                'guest_readonly': False, 'host_mount_or_loop_device_used': False}
    runner.write_new(vm.VM/'outputs-verification.json', (json.dumps(evidence, indent=2)+'\n').encode())
    return evidence


def harvest(identity):
    proof = json.loads(runner.regular_file(vm.VM/'outputs-verification.json').read_text())
    image = runner.regular_file(vm.VM/'outputs.img')
    if proof['guest_id'] != identity['guest_id'] or image.stat().st_size != SIZE:
        raise ValueError('bound build output disk changed')
    destination = vm.VM/('export-'+uuid.uuid4().hex)
    destination.mkdir(mode=0o700)
    disk_hash = runner.sha256(image)
    for name in ('authorization.json', 'gitstatus-build.json', 'gitstatus.pkg.tar.zst'):
        command = vm.sandbox_command(['/usr/bin/debugfs', '-R',
                    'dump /'+name+' /run/mpkg-export/'+name,
                    '/run/mpkg-fixture/outputs.img'], writable_vm=False)
        position = command.index('--chdir')
        command[position:position] = ['--unshare-net', '--bind', str(destination), '/run/mpkg-export']
        subprocess.run(command, check=True, env=runner.SAFE_ENV, timeout=60,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        runner.regular_file(destination/name)
    if runner.sha256(image) != disk_hash:
        raise ValueError('stopped output disk changed during extraction')
    if (destination/'authorization.json').stat().st_size > 4096:
        raise ValueError('output authorization exceeds bound')
    authorization = json.loads((destination/'authorization.json').read_text())
    if any(authorization[key] != proof[key] for key in ('schema','guest_id','checkpoint','checkpoint_record_sha256')):
        raise ValueError('output checkpoint authorization changed')
    record_path = destination/'gitstatus-build.json'
    if record_path.stat().st_size > 65536:
        raise ValueError('build evidence exceeds bound')
    record = json.loads(record_path.read_text())
    source = json.loads(native.MANIFEST.read_text())
    # Reuse the proof's pure provenance validator; no guest or libalpm calls.
    sys.path.insert(0, str(runner.PROJECT/'scripts/proofs'))
    from native_manifest import validate_build
    artifact = validate_build(record, source, identity['guest_id'])
    archive = destination/'gitstatus.pkg.tar.zst'
    if (not 0 < artifact['size'] <= 64*1024**2 or archive.stat().st_size != artifact['size']
            or runner.sha256(archive) != artifact['sha256']):
        raise ValueError('built archive does not match actual build evidence')
    tree = vm.VM/'built-input-tree'
    tree.mkdir(mode=0o700)
    inputs.copy_new(archive, tree/(artifact['sha256']+'.pkg.tar.zst'))
    inputs.copy_new(record_path, tree/'gitstatus-build.json')
    inputs.copy_new(destination/'authorization.json', tree/'native-change-checkpoint.json')
    runner.write_new(tree/'identity.json', (json.dumps(identity, indent=2)+'\n').encode())
    paths = sorted(tree.iterdir())
    runner.write_new(tree/'SHA256SUMS', ''.join(f'{runner.sha256(p)}  {p.name}\n' for p in paths).encode())
    image = vm.VM/'built.img'
    image_from_tree(tree, image, 'MPKG_BUILT')
    evidence = {'guest_id': identity['guest_id'], 'disk_bytes': SIZE, 'sha256': runner.sha256(image),
                'output_disk_sha256': disk_hash, 'archive_sha256': artifact['sha256'],
                'build_record_sha256': runner.sha256(record_path), 'guest_readonly': True,
                'host_mount_or_loop_device_used': False}
    runner.write_new(vm.VM/'built-verification.json', (json.dumps(evidence, indent=2)+'\n').encode())
    return evidence


if __name__ == '__main__':
    if sys.version_info[:2] != (3, 12):
        raise SystemExit('Python 3.12 is required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'harvest'])
    args = parser.parse_args()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256*1024**2, 256*1024**2))
    identity = vm.vm_identity()
    with vm.vm_lock():
        vm.require_no_restore_pending()
        print(json.dumps(prepare(identity) if args.operation == 'prepare' else harvest(identity)), flush=True)
