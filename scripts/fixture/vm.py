#!/usr/bin/env python3
"""Operate only the bound disposable VM using a private QEMU runner."""
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import select
import shutil
import socket
import subprocess
import sys
import time
import uuid

import runner

VM = runner.CACHE / 'vm'
ISO = runner.PROJECT / '.cache/artifacts/archlinux-2026.10.01-x86_64.iso.part'
DISK_BYTES = 40 * 1024 ** 3


def sandbox_command(arguments, writable_vm=True, include_iso=False):
    root = runner.CACHE / 'runner'
    marker = runner.regular_file(root / '.mpkg-verified-runner.json')
    if json.loads(marker.read_text())['inputs_sha256'] != runner.sha256(runner.INPUTS):
        raise ValueError('extracted runner does not match the bound input manifest')
    command = ['/usr/bin/bwrap', '--unshare-user', '--uid', '0', '--gid', '0',
               '--unshare-pid', '--unshare-ipc', '--unshare-uts', '--new-session',
               '--die-with-parent', '--cap-drop', 'ALL', '--clearenv',
               '--ro-bind', str(root), '/', '--proc', '/proc', '--dev', '/dev',
               '--tmpfs', '/tmp', '--tmpfs', '/run',
               '--bind' if writable_vm else '--ro-bind', str(VM), '/run/mpkg-fixture',
               '--setenv', 'PATH', '/usr/bin', '--setenv', 'HOME', '/tmp',
               '--setenv', 'LC_ALL', 'C', '--setenv', 'QEMU_MODULE_DIR', '/usr/lib/qemu',
               '--setenv', 'QEMU_FIRMWAREPATH', '/usr/share/qemu']
    if include_iso:
        runner.regular_file(ISO)
        proof = json.loads(runner.regular_file(runner.CACHE / 'iso-verification.json').read_text())
        if runner.sha256(ISO) != proof['sha256']:
            raise ValueError('verified ISO bytes changed')
        command += ['--ro-bind', str(ISO), '/run/mpkg-fixture/installer.iso']
    return command + ['--chdir', '/run/mpkg-fixture',
                      '/usr/lib/ld-linux-x86-64.so.2', '--inhibit-cache',
                      '--library-path', '/usr/lib', *arguments]


def vm_identity():
    record = json.loads(runner.regular_file(VM / 'identity.json').read_text())
    if str(uuid.UUID(record['guest_id'])) != record['guest_id']:
        raise ValueError('invalid VM UUID')
    if record['disk_serial'] != 'mpkg' + uuid.UUID(record['guest_id']).hex[:16]:
        raise ValueError('invalid disposable disk serial')
    if record['disk_bytes'] != DISK_BYTES or not record['disposable']:
        raise ValueError('unexpected VM disk identity')
    return record


def vm_lock():
    runner.private_directory(VM)
    path = VM / 'operator.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, 'r+')


def prepare():
    runner.private_directory(VM)
    os.chmod(VM, 0o700)
    with vm_lock():
        for name in ['identity.json', 'disk.qcow2', 'vars.fd']:
            if (VM/name).exists() or (VM/name).is_symlink():
                raise ValueError('VM preparation already has state; preserve it')
        identity = str(uuid.uuid4())
        runner.write_new(VM / 'identity.json', (json.dumps({
            'schema': 1, 'guest_id': identity, 'fixture_id': 'first-release-2026-10-31',
            'disposable': True, 'disk_serial': 'mpkg' + uuid.UUID(identity).hex[:16],
            'disk_bytes': DISK_BYTES,
        }, indent=2)+'\n').encode())
        firmware = runner.CACHE / 'runner/usr/share/edk2/x64/OVMF_VARS.4m.fd'
        runner.regular_file(firmware)
        runner.write_new(VM / 'vars.fd', firmware.read_bytes())
        subprocess.run(sandbox_command(['/usr/bin/qemu-img', 'create', '-f', 'qcow2',
                                        '/run/mpkg-fixture/disk.qcow2', str(DISK_BYTES)]),
                       env=runner.SAFE_ENV, check=True, timeout=60)
        # Extract only two fixed regular ISO members to fresh files after trust proof.
        proof = json.loads(runner.regular_file(runner.CACHE/'iso-verification.json').read_text())
        if runner.sha256(ISO) != proof['sha256']:
            raise ValueError('ISO changed after signature verification')
        for member, name in [('arch/boot/x86_64/vmlinuz-linux', 'vmlinuz'),
                             ('arch/boot/x86_64/initramfs-linux.img', 'initramfs')]:
            fd = os.open(VM/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output:
                subprocess.run(['/usr/bin/bsdtar', '-xOf', str(ISO), member], stdout=output,
                               stderr=subprocess.PIPE, env=runner.SAFE_ENV, check=True, timeout=60)
        print(json.dumps(vm_identity()))


def qemu_arguments(identity, installer):
    arguments = ['/usr/bin/qemu-system-x86_64', '-no-user-config', '-nodefaults',
                 '-display', 'none', '-machine', 'q35,accel=tcg,dump-guest-core=off', '-cpu', 'qemu64',
                 '-smp', '4', '-m', '8192', '-uuid', identity['guest_id'],
                 '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
                 '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd',
                 '-drive', 'if=pflash,format=raw,file=/run/mpkg-fixture/vars.fd',
                 '-drive', 'if=none,id=os,format=qcow2,file=/run/mpkg-fixture/disk.qcow2',
                 '-device', 'virtio-blk-pci,drive=os,serial='+identity['disk_serial'],
                 '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0',
                 '-chardev', 'socket,id=console,path=/run/mpkg-fixture/c.sock,server=on,wait=off',
                 '-serial', 'chardev:console',
                 '-qmp', 'unix:/run/mpkg-fixture/q.sock,server=on,wait=off',
                 '-device', 'virtio-serial-pci',
                 '-chardev', 'socket,id=control,path=/run/mpkg-fixture/g.sock,server=on,wait=off',
                 '-device', 'virtserialport,chardev=control,name=org.mpkg.fixture.control']
    if installer:
        arguments += ['-drive', 'if=none,id=cd,format=raw,readonly=on,media=cdrom,file=/run/mpkg-fixture/installer.iso',
                      '-device', 'ide-cd,drive=cd', '-kernel', '/run/mpkg-fixture/vmlinuz',
                      '-initrd', '/run/mpkg-fixture/initramfs', '-append',
                      'archisobasedir=arch archisosearchuuid=2026-10-01-14-49-03-00 console=ttyS0,115200']
    return arguments


def start(installer):
    identity = vm_identity()
    with vm_lock():
        for name in ('disk.qcow2', 'vars.fd'):
            runner.regular_file(VM/name)
        for name in ('c.sock','q.sock','g.sock'):
            path = VM/name
            if path.exists() or path.is_symlink():
                if not path.is_socket() or path.is_symlink():
                    raise ValueError('unexpected existing VM socket path')
                path.unlink()
        command = sandbox_command(qemu_arguments(identity, installer), include_iso=installer)
        print(json.dumps({'guest_id':identity['guest_id'],'boot':'installer' if installer else 'disk',
                          'host_shared_mounts_in_guest':False,'inbound_forwarding':False}),flush=True)
        result = subprocess.run(command, env=runner.SAFE_ENV)
        if result.returncode:
            raise RuntimeError(f'private QEMU exited {result.returncode}')


def qmp_query(operation):
    if operation not in {'query-status','system_powerdown'}:
        raise ValueError('unsupported QMP operation')
    identity = vm_identity()
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(str(VM/'q.sock'))
        file = sock.makefile('rwb')
        greeting=json.loads(file.readline(65537));assert 'QMP' in greeting
        def request(command):
            file.write((json.dumps({'execute':command})+'\n').encode());file.flush()
            while True:
                raw=file.readline(65537)
                if not raw or len(raw)>65536:raise ValueError('invalid QMP reply')
                reply=json.loads(raw)
                if 'error' in reply:raise ValueError('QMP rejected request')
                if 'return' in reply:return reply['return']
        request('qmp_capabilities')
        if request('query-uuid')['UUID'].lower()!=identity['guest_id']:
            raise ValueError('QMP UUID does not match bound disposable guest')
        return request(operation)


def console(script=None, seconds=10):
    qmp_query('query-status')  # Bind the socket family to the expected running VM first.
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10);sock.connect(str(VM/'c.sock'))
        if script is not None:
            source=Path(script).resolve()
            allowed=runner.PROJECT/'scripts'
            if not source.is_relative_to(allowed) or source.suffix != '.sh':
                raise ValueError('console input must be a reviewed script in this worktree')
            data=runner.regular_file(source).read_bytes()
            if len(data)>262144:raise ValueError('console script exceeds input bound')
            encoded=base64.b64encode(data).decode()
            chunks='\n'.join(encoded[i:i+76] for i in range(0,len(encoded),76))
            command="\nstty -echo\nbase64 -d > /run/mpkg-fixture-input.sh <<'MPKG_INPUT'\n"+chunks+"\nMPKG_INPUT\nbash /run/mpkg-fixture-input.sh; printf '\\nMPKG_CONSOLE_EXIT=%s\\n' \"$?\"\nstty echo\n"
            sock.sendall(command.encode())
        end=time.monotonic()+seconds;data=bytearray()
        while time.monotonic()<end and len(data)<262144:
            ready,_,_=select.select([sock],[],[],min(1,end-time.monotonic()))
            if not ready:continue
            chunk=sock.recv(16384)
            if not chunk:break
            data.extend(chunk)
        # Console logs are private and bounded; callers should not echo credentials in scripts.
        sys.stdout.buffer.write(data[-16384:])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['prepare','start-installer','start-disk','status','powerdown','console'])
    parser.add_argument('--script')
    parser.add_argument('--seconds',type=int,default=10)
    args=parser.parse_args()
    if sys.version_info[:2]!=(3,12):parser.error('Python 3.12 is required')
    if not 1<=args.seconds<=30:parser.error('console observation must be 1–30 seconds')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if args.operation=='prepare':prepare()
    elif args.operation.startswith('start-'):start(args.operation=='start-installer')
    elif args.operation=='console':console(args.script,args.seconds)
    else:print(json.dumps(qmp_query('query-status' if args.operation=='status' else 'system_powerdown')))


if __name__=='__main__':main()
