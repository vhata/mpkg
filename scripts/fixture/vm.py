#!/usr/bin/env python3
"""Operate only the bound disposable VM using a private QEMU runner."""
import argparse
import base64
import fcntl
import hashlib
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


def require_no_restore_pending():
    for name in ('restore-vars.pending','restore.pending.json'):
        if (VM/name).exists() or (VM/name).is_symlink():
            raise ValueError('interrupted checkpoint restore requires evidence reconciliation')


def qemu_arguments(identity, installer, inputs=False, sources=False, console_log=None,
                   outputs=False, built=False):
    arguments = ['/usr/bin/qemu-system-x86_64', '-no-user-config', '-nodefaults',
                 '-display', 'none', '-machine', 'q35,accel=tcg,dump-guest-core=off', '-cpu', 'qemu64',
                 '-smp', '4', '-m', '8192', '-uuid', identity['guest_id'],
                 '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
                 '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd',
                 '-drive', 'if=pflash,format=raw,file=/run/mpkg-fixture/vars.fd',
                 '-drive', 'if=none,id=os,format=qcow2,file=/run/mpkg-fixture/disk.qcow2',
                 '-device', 'virtio-blk-pci,drive=os,serial='+identity['disk_serial'],
                 '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0',
                 '-chardev', 'socket,id=console,path=/run/mpkg-fixture/c.sock,server=on,wait=off'+
                 (',logfile=/run/mpkg-fixture/'+console_log+',logappend=on' if console_log else ''),
                 '-serial', 'chardev:console',
                 '-qmp', 'unix:/run/mpkg-fixture/q.sock,server=on,wait=off',
                 '-device', 'virtio-serial-pci',
                 '-chardev', 'socket,id=control,path=/run/mpkg-fixture/g.sock,server=on,wait=off',
                 '-device', 'virtserialport,chardev=control,name=org.mpkg.fixture.control']
    if inputs:
        arguments += ['-drive', 'if=none,id=inputs,format=raw,readonly=on,file=/run/mpkg-fixture/inputs.img',
                      '-device', 'virtio-blk-pci,drive=inputs,serial=mpkgin'+uuid.UUID(identity['guest_id']).hex[:14]]
    if sources:
        if not inputs:raise ValueError('source disk requires the original input disk binding')
        arguments += ['-drive', 'if=none,id=sources,format=raw,readonly=on,file=/run/mpkg-fixture/sources.img',
                      '-device', 'virtio-blk-pci,drive=sources,serial=mpkgsrc'+uuid.UUID(identity['guest_id']).hex[:13]]
    if outputs:
        if not sources:raise ValueError('build output disk requires the source/input bindings')
        arguments += ['-drive', 'if=none,id=outputs,format=raw,file=/run/mpkg-fixture/outputs.img',
                      '-device', 'virtio-blk-pci,drive=outputs,serial=mpkgout'+uuid.UUID(identity['guest_id']).hex[:13]]
    if built:
        if not outputs:raise ValueError('built input disk requires the output disk identity')
        arguments += ['-drive', 'if=none,id=built,format=raw,readonly=on,file=/run/mpkg-fixture/built.img',
                      '-device', 'virtio-blk-pci,drive=built,serial=mpkgbld'+uuid.UUID(identity['guest_id']).hex[:13]]
    if installer:
        arguments += ['-drive', 'if=none,id=cd,format=raw,readonly=on,media=cdrom,file=/run/mpkg-fixture/installer.iso',
                      '-device', 'ide-cd,drive=cd', '-kernel', '/run/mpkg-fixture/vmlinuz',
                      '-initrd', '/run/mpkg-fixture/initramfs', '-append',
                      'archisobasedir=arch archisosearchuuid=2026-10-01-14-49-03-00 console=ttyS0,115200']
    return arguments


def start(installer):
    identity = vm_identity()
    with vm_lock():
        require_no_restore_pending()
        for name in ('disk.qcow2', 'vars.fd'):
            runner.regular_file(VM/name)
        for name in ('c.sock','q.sock','g.sock'):
            path = VM/name
            if path.exists() or path.is_symlink():
                if not path.is_socket() or path.is_symlink():
                    raise ValueError('unexpected existing VM socket path')
                path.unlink()
        inputs = (VM/'inputs-verification.json').exists()
        if inputs:
            proof=json.loads(runner.regular_file(VM/'inputs-verification.json').read_text())
            image=runner.regular_file(VM/'inputs.img')
            if (proof['guest_id']!=identity['guest_id'] or image.stat().st_size!=proof['disk_bytes']
                    or runner.sha256(image)!=proof['sha256']):
                raise ValueError('read-only guest input disk does not match its binding')
        sources = (VM/'sources-verification.json').exists()
        if sources:
            proof=json.loads(runner.regular_file(VM/'sources-verification.json').read_text())
            image=runner.regular_file(VM/'sources.img')
            if (proof['guest_id']!=identity['guest_id'] or image.stat().st_size!=proof['disk_bytes']
                    or runner.sha256(image)!=proof['sha256']):
                raise ValueError('read-only source disk does not match its binding')
        outputs = (VM/'outputs-verification.json').exists()
        if outputs:
            proof=json.loads(runner.regular_file(VM/'outputs-verification.json').read_text())
            image=runner.regular_file(VM/'outputs.img')
            if proof['guest_id']!=identity['guest_id'] or image.stat().st_size!=128*1024**2:
                raise ValueError('writable build output disk does not match its binding')
        built = (VM/'built-verification.json').exists()
        if built:
            proof=json.loads(runner.regular_file(VM/'built-verification.json').read_text())
            image=runner.regular_file(VM/'built.img')
            if (proof['guest_id']!=identity['guest_id'] or image.stat().st_size!=proof['disk_bytes']
                    or runner.sha256(image)!=proof['sha256']):
                raise ValueError('read-only built artifact disk does not match its binding')
        console_log='serial-'+uuid.uuid4().hex+'.log'
        runner.write_new(VM/console_log,b'')
        command = sandbox_command(qemu_arguments(identity, installer, inputs, sources,console_log,
                                                 outputs,built), include_iso=installer)
        print(json.dumps({'guest_id':identity['guest_id'],'boot':'installer' if installer else 'disk',
                          'host_shared_mounts_in_guest':False,'inbound_forwarding':False,
                          'private_console_log':console_log}),flush=True)
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


def proof_install_payload(name):
    additions={
        'docker-ready':('docker_ready.py','5efbc61753dbf873d26801f760c3e47f5a48831b1c3c0b02ba43a3c7c7e08a07'),
        'service-environment':('service_environment.py','91c819c3680eb4dae50458293e191bd36ebd2c39b439dd0122dc70928e83e502'),
        'account-defaults':('account_defaults.py','4d356ab3c41c8933e2030f20882ad25a3df142eb209cc5177c71f9a7b0991532'),
        'native-service-recover':('native_service_recover.py','f8e55069f53055d89c1603db90b5259e87b47129747d0bccf831053544828b3e'),
        'docker-baseline':('docker_baseline.py','f6af324e2d0844a6159f0e6dcf1e72c766679953dc4e4ec5c093ff42271bbeca'),
        'docker-resume':('docker_resume.py','94fb8f960ee6bae8d28a958f1b9c8a54f23d83d1d98f5f174fb79630073b5f05'),
        'native-conflict':('native_conflict.py','5f9ba29849f9e2cdc0dcf6572bba5a4c3cc4d9abcf3a04c56ff6037d5aad7c2b'),
    }
    if name not in additions:
        raise ValueError('proof addition is not allowlisted')
    filename,digest=additions[name]
    source=runner.PROJECT/'scripts/proofs'/filename
    data=runner.regular_file(source).read_bytes()
    if hashlib.sha256(data).hexdigest()!=digest:
        raise ValueError('proof addition bytes differ from the reviewed digest')
    payload=r'''import base64, hashlib, json, os, stat, sys, uuid
from pathlib import Path

def protected_directory(path, mode=None):
    info=path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0
            or info.st_mode & 0o022 or path.resolve()!=path
            or (mode is not None and stat.S_IMODE(info.st_mode)!=mode)):
        raise RuntimeError('proof addition directory is not root-protected')

def publish_new_file(target, data):
    temporary=target.with_name('.proof-addition-'+uuid.uuid4().hex+'.pending')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(),0o644)
        os.fsync(stream.fileno())
    os.link(temporary,target,follow_symlinks=False)
    temporary.unlink()
    directory=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)

def install():
    if sys.version_info[:2]!=(3,12) or os.geteuid()!=0 or os.getegid()!=0:
        raise RuntimeError('installed guest Python and root required')
    sys.dont_write_bytecode=True
    target_directory=Path('/opt/mpkg-proofs')
    protected_directory(target_directory)
    core=target_directory/'core.py'
    info=core.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0
            or info.st_nlink!=1 or info.st_mode & 0o022):
        raise RuntimeError('installed guest guard is not trusted')
    sys.path.insert(0,str(target_directory))
    from core import require_guest, write_new
    guest=require_guest(os.environ.get('MPKG_GUEST_ID'))
    os.umask(0o077)
    dependencies={
        'docker_ready.py':[('service_environment.py','91c819c3680eb4dae50458293e191bd36ebd2c39b439dd0122dc70928e83e502')],
        'docker_baseline.py':[('account_defaults.py','4d356ab3c41c8933e2030f20882ad25a3df142eb209cc5177c71f9a7b0991532')],
        'native_service_recover.py':[
            ('account_defaults.py','4d356ab3c41c8933e2030f20882ad25a3df142eb209cc5177c71f9a7b0991532'),
            ('native_service.py','645822526f899506a9f0b6e13c27945003b111ed6d9b065e1df992095acf5961'),
        ],
    }
    for dependency_name,dependency_hash in dependencies.get(ADDITION_FILENAME,[]):
        dependency=target_directory/dependency_name
        fd=os.open(dependency,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0
                    or info.st_nlink!=1 or info.st_mode & 0o022 or info.st_size>262144):
                raise RuntimeError('proof dependency is not trusted')
            with os.fdopen(fd,'rb',closefd=False) as stream:dependency_data=stream.read(262145)
            if hashlib.sha256(dependency_data).hexdigest()!=dependency_hash:
                raise RuntimeError('proof dependency differs from reviewed bytes')
        finally:os.close(fd)
    data=base64.b64decode(PAYLOAD_BASE64,validate=True)
    digest=ADDITION_DIGEST
    if hashlib.sha256(data).hexdigest()!=digest:
        raise RuntimeError('proof addition digest mismatch')
    target=target_directory/ADDITION_FILENAME
    if target.exists() or target.is_symlink():
        raise RuntimeError('proof addition destination already exists')
    state=Path('/var/lib/mpkg-fixture')
    protected_directory(state,0o700)
    records=state/'proof-additions'
    if not records.exists() and not records.is_symlink():records.mkdir(mode=0o700)
    protected_directory(records,0o700)
    record=records/ADDITION_RECORD
    if record.exists() or record.is_symlink():
        raise RuntimeError('proof addition already has evidence')
    publish_new_file(target,data)
    evidence={'schema':1,'guest_id':guest,'path':str(target),'sha256':digest,
              'mode':'0644','uid':0,'gid':0,'executed':False}
    write_new(record,(json.dumps(evidence,sort_keys=True)+'\n').encode())
    print(json.dumps({'status':'installed','path':str(target),'sha256':digest,'executed':False}))

install()
'''
    return (payload.replace('PAYLOAD_BASE64',repr(base64.b64encode(data).decode()))
            .replace('ADDITION_DIGEST',repr(digest)).replace('ADDITION_FILENAME',repr(filename))
            .replace('ADDITION_RECORD',repr(name+'.json')).encode())


def native_service_replacement_payload():
    source=runner.PROJECT/'scripts/proofs/native_service.py'
    data=runner.regular_file(source).read_bytes()
    if hashlib.sha256(data).hexdigest()!='fbb713c105ed23fe140d2ccc9443eca6295d34e5b788e2e58c994c821638f7b6':
        raise ValueError('native service replacement differs from reviewed bytes')
    template=runner.regular_file(runner.PROJECT/'scripts/fixture/guest_native_service_replace.py').read_text()
    marker='REPLACEMENT_BASE64 = None'
    if template.count(marker)!=1:
        raise ValueError('native service replacement template changed')
    return template.replace(marker,'REPLACEMENT_BASE64 = '+repr(base64.b64encode(data).decode())).encode()


def docker_baseline_replacement_payload():
    source=runner.PROJECT/'scripts/proofs/docker_baseline.py'
    data=runner.regular_file(source).read_bytes()
    if hashlib.sha256(data).hexdigest()!='f6af324e2d0844a6159f0e6dcf1e72c766679953dc4e4ec5c093ff42271bbeca':
        raise ValueError('Docker baseline replacement differs from reviewed bytes')
    template=runner.regular_file(runner.PROJECT/'scripts/fixture/guest_docker_baseline_replace.py').read_text()
    marker='REPLACEMENT_BASE64 = None'
    if template.count(marker)!=1:
        raise ValueError('Docker baseline replacement template changed')
    return template.replace(marker,'REPLACEMENT_BASE64 = '+repr(base64.b64encode(data).decode())).encode()


def console(script=None, seconds=10, prompt=False, login_root=False, addition=None, replacement=None):
    payload=None
    if replacement:
        if script is not None or prompt or login_root or addition is not None:
            raise ValueError('native service replacement cannot include other console input')
        if replacement=='native-service':payload=native_service_replacement_payload()
        elif replacement=='docker-baseline':payload=docker_baseline_replacement_payload()
        else:raise ValueError('replacement is not allowlisted')
        suffix='.py'
    elif addition is not None:
        if script is not None or prompt or login_root:
            raise ValueError('proof installation cannot include other console input')
        payload=proof_install_payload(addition)
        suffix='.py'
    elif script is not None:
        source=Path(script).resolve()
        allowed=runner.PROJECT/'scripts'
        if not source.is_relative_to(allowed) or source.suffix not in {'.sh','.py'}:
            raise ValueError('console input must be a reviewed script in this worktree')
        payload=runner.regular_file(source).read_bytes()
        suffix=source.suffix
    if payload is not None and len(payload)>262144:
        raise ValueError('console script exceeds input bound')
    qmp_query('query-status')  # Bind the socket family to the expected running VM first.
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10);sock.connect(str(VM/'c.sock'))
        if prompt:
            sock.sendall(b'\n')
        if login_root:
            sock.sendall(b'root\n')
        if payload is not None:
            data=payload
            encoded=base64.b64encode(data).decode()
            chunks='\n'.join(encoded[i:i+76] for i in range(0,len(encoded),76))
            digest=hashlib.sha256(data).hexdigest()
            interpreter=('bash' if suffix=='.sh' else
                         '/opt/mpkg-python/3.12.16/bin/python3.12 -I')
            guest_path='/run/mpkg-fixture-input-'+digest+'-'+uuid.uuid4().hex+'.sh'
            command=("\nstty -echo\numask 077\nif (set -o noclobber; base64 -d > "+guest_path+
                     " <<'MPKG_INPUT'\n"+chunks+"\nMPKG_INPUT\n); then\n"+
                     "if printf '%s  %s\\n' "+digest+" "+guest_path+
                     " | sha256sum --strict --check >/dev/null; then\n"+
                     "MPKG_GUEST_ID="+vm_identity()['guest_id']+" SYSTEMD_PAGER=cat PAGER=cat SYSTEMD_COLORS=0 "+interpreter+" "+guest_path+
                     " </dev/null; code=$?; printf '%s\\n' \"$code\" > "+guest_path+".exit; "+
                     "printf '\\nMPKG_CONSOLE_EXIT=%s\\n' \"$code\"\n"+
                     "else printf '\\nMPKG_TRANSFER_HASH_FAILED\\n'; fi\n"+
                     "else printf '\\nMPKG_TRANSFER_DECODE_FAILED\\n'; fi\nstty echo\n")

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
    parser.add_argument('operation',choices=['prepare','start-installer','start-disk','status','powerdown','console','install-docker-ready','install-docker-baseline','install-native-conflict','install-service-environment','install-account-defaults','install-native-service-recover','install-docker-resume','replace-native-service','replace-docker-baseline'])
    parser.add_argument('--script')
    parser.add_argument('--prompt',action='store_true')
    parser.add_argument('--login-root',action='store_true')
    parser.add_argument('--seconds',type=int,default=10)
    args=parser.parse_args()
    if sys.version_info[:2]!=(3,12):parser.error('Python 3.12 is required')
    if sum(bool(value) for value in (args.prompt,args.login_root,args.script))>1:
        parser.error('choose one console input mode')
    if args.operation!='console' and any((args.prompt,args.login_root,args.script)):
        parser.error('console input options require the console operation')
    if not 1<=args.seconds<=30:parser.error('console observation must be 1–30 seconds')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if args.operation=='prepare':prepare()
    elif args.operation.startswith('start-'):start(args.operation=='start-installer')
    elif args.operation=='console':console(args.script,args.seconds,args.prompt,args.login_root)
    elif args.operation=='install-docker-ready':console(seconds=args.seconds,addition='docker-ready')
    elif args.operation=='install-docker-baseline':console(seconds=args.seconds,addition='docker-baseline')
    elif args.operation=='install-native-conflict':console(seconds=args.seconds,addition='native-conflict')
    elif args.operation=='install-service-environment':console(seconds=args.seconds,addition='service-environment')
    elif args.operation=='install-account-defaults':console(seconds=args.seconds,addition='account-defaults')
    elif args.operation=='install-native-service-recover':console(seconds=args.seconds,addition='native-service-recover')
    elif args.operation=='install-docker-resume':console(seconds=args.seconds,addition='docker-resume')
    elif args.operation=='replace-native-service':console(seconds=args.seconds,replacement='native-service')
    elif args.operation=='replace-docker-baseline':console(seconds=args.seconds,replacement='docker-baseline')
    else:print(json.dumps(qmp_query('query-status' if args.operation=='status' else 'system_powerdown')))


if __name__=='__main__':main()
