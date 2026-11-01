#!/usr/bin/env python3
"""Build a read-only guest input disk as a private regular host file."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import native
import runner
import vm


def copy_new(source, target):
    runner.regular_file(source)
    runner.private_directory(target.parent)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with source.open('rb') as incoming,os.fdopen(fd,'wb') as outgoing:
        shutil.copyfileobj(incoming,outgoing)


def prepare():
    identity=vm.vm_identity()
    with vm.vm_lock():
        tree=runner.CACHE/'input-tree'
        if tree.exists() or tree.is_symlink() or (vm.VM/'inputs.img').exists():
            raise ValueError('input-disk assembly already has state; preserve it')
        tree.mkdir(mode=0o700)
        manifest=json.loads(native.MANIFEST.read_text())
        records=native.native_inputs()
        acquired=json.loads(runner.regular_file(runner.CACHE/'native-acquisition.json').read_text())
        if {(p['name'],p['version'],p['sha256']) for p in records} != {
                (p['name'],p['version'],p['sha256']) for p in acquired}:
            raise ValueError('native acquisition is incomplete or changed')
        home=runner.trust_home(runner.CACHE)
        for package in records:
            name=package['sha256']+'.pkg.tar.zst'
            source=runner.regular_file(runner.CACHE/'archives'/name)
            if source.stat().st_size!=package['size'] or runner.sha256(source)!=package['sha256']:
                raise ValueError('acquired native archive changed')
            signature=source.with_name(name+'.sig')
            runner.verify_signature(home,source,signature)
            copy_new(source,tree/'artifacts'/name)
            copy_new(signature,tree/'artifacts'/(name+'.sig'))
        baseline=manifest['resolutions']['native_change']
        names=set(baseline['resolved_package_names'])
        packages={p['name']:p for p in manifest['repository_packages']}
        if len(names)!=207 or {'tmux','ripgrep','libutempter','gitstatus','cmake','zsh'} & names:
            raise ValueError('baseline lost its required initial absences')
        roots=set(baseline['requested_repository_packages'])
        values={
            'baseline-artifacts.list': ''.join(packages[n]['package_sha256_published_in_database']+'.pkg.tar.zst\n' for n in sorted(names)),
            'baseline-versions.txt': ''.join(f"{n} {packages[n]['version']}\n" for n in sorted(names)),
            'baseline-dependencies.list': ''.join(n+'\n' for n in sorted(names-roots)),
            'identity.json':json.dumps(identity,indent=2)+'\n',
            'pacman.conf':'[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Required\n'+''.join(f'[{repo}]\nServer = https://archive.archlinux.org/repos/2026/10/30/{repo}/os/x86_64\n' for repo in ('core','extra')),
        }
        for name,value in values.items():runner.write_new(tree/name,value.encode())
        copy_new(native.MANIFEST,tree/'source-inventory.json')
        for name in ('archlinux.gpg','archlinux-trusted','archlinux-revoked'):
            copy_new(runner.KEYRINGS/name,tree/'keyrings'/name)
        for group,date in [(manifest['repository_databases'],'2026-10-30'),
                           (manifest['native_update_target']['repository_databases'],'2026-10-31')]:
            for database in group:
                source=runner.CACHE/'native-metadata'/(database['sha256_computed']+'.db')
                if runner.sha256(source)!=database['sha256_computed']:raise ValueError('database changed')
                copy_new(source,tree/'databases'/date/(database['repository']+'.db'))
        files=sorted(path for path in tree.rglob('*') if path.is_file())
        for path in files:runner.regular_file(path)
        sums=''.join(f'{runner.sha256(path)}  {path.relative_to(tree).as_posix()}\n' for path in files)
        runner.write_new(tree/'SHA256SUMS',sums.encode())
        content_bytes=sum(path.stat().st_size for path in files)
        disk_bytes=((2*content_bytes+256*1024**2+1024**3-1)//1024**3)*1024**3
        if disk_bytes>8*1024**3:raise ValueError('input disk exceeds 8 GiB bound')
        image=vm.VM/'inputs.img'
        fd=os.open(image,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.truncate(disk_bytes)
        runner.regular_file(image)
        subprocess.run(['/usr/bin/mkfs.ext4','-q','-F','-L','MPKG_INPUTS',
                        '-E','root_owner=0:0','-d',str(tree),str(image)],
                       check=True,env=runner.SAFE_ENV,timeout=300)
        evidence={'guest_id':identity['guest_id'],'disk_bytes':disk_bytes,
                  'sha256':runner.sha256(image),'files':len(files)+1,
                  'host_mount_or_loop_device_used':False,
                  'guest_readonly':True,'native_archive_count':len(records)}
        runner.write_new(vm.VM/'inputs-verification.json',(json.dumps(evidence,indent=2)+'\n').encode())
        print(json.dumps(evidence),flush=True)


if __name__=='__main__':
    if sys.version_info[:2]!=(3,12):raise SystemExit('Python 3.12 is required')
    os.umask(0o077)
    prepare()
