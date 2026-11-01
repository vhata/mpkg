#!/usr/bin/env python3
"""Build a separate offline source/proof input disk for the bound guest."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import inputs
import runner
import sources
import vm


def prepare(oci_snapshot):
    common=Path(subprocess.check_output(['/usr/bin/git','-C',str(runner.PROJECT),'rev-parse',
                                        '--path-format=absolute','--git-common-dir'],
                                       env=runner.SAFE_ENV,text=True).strip())
    allowed=common.parent/'.cache/fixture-oci'
    snapshot=Path(oci_snapshot).absolute()
    if snapshot.parent!=allowed or not re.fullmatch('snapshot-[a-f0-9]{32}',snapshot.name):
        raise ValueError('OCI input is outside the shared private acquisition directory')
    if not snapshot.is_dir():raise ValueError('OCI acquisition snapshot is missing')
    runner.private_directory(snapshot)
    acquisition=json.loads(runner.regular_file(snapshot/'acquisition.json').read_text())
    archive=runner.regular_file(snapshot/'images.oci.tar')
    if (acquisition['archive']['filename']!='images.oci.tar'
            or archive.stat().st_size!=acquisition['archive']['bytes']
            or runner.sha256(archive)!=acquisition['archive']['sha256']):
        raise ValueError('OCI acquisition archive identity mismatch')
    identity=vm.vm_identity()
    with vm.vm_lock():
        tree=runner.CACHE/'source-tree'
        if tree.exists() or tree.is_symlink() or (vm.VM/'sources.img').exists():
            raise ValueError('source disk already has state; preserve it')
        tree.mkdir(mode=0o700)
        acquired=json.loads(runner.regular_file(runner.CACHE/'source-acquisition.json').read_text())
        expected=sources.records()
        keys=lambda rows:{(r['package'],r['name'],tuple(sorted(r['digests'].items()))) for r in rows}
        if keys(acquired)!=keys(expected):raise ValueError('source acquisition is incomplete or changed')
        for record in acquired:
            sources.validate_record(record)
            if not re.fullmatch('[a-z0-9][a-z0-9+_.-]*',record['package']):
                raise ValueError('invalid source package directory')
            key=next(iter(record['digests'].values()))+'.source'
            if record['cache_file']!=key:raise ValueError('source cache identity changed')
            path=runner.CACHE/'sources'/key
            sources.verify(path,record)
            inputs.copy_new(path,tree/'sources'/record['package']/record['name'])
        proof_root=runner.PROJECT/'scripts/proofs'
        files=subprocess.check_output(['/usr/bin/git','-C',str(runner.PROJECT),'ls-files','-z','--','scripts/proofs'],env=runner.SAFE_ENV).split(b'\0')
        proof_files=[]
        for raw in files:
            if not raw:continue
            source=runner.PROJECT/os.fsdecode(raw)
            relative=source.relative_to(proof_root)
            if source.is_symlink() or not source.resolve().is_relative_to(proof_root):
                raise ValueError('proof input escapes its reviewed source directory')
            inputs.copy_new(source,tree/'proofs'/relative)
            proof_files.append({'path':str(relative),'sha256':runner.sha256(source)})
        runner.write_new(tree/'identity.json',(json.dumps(identity,indent=2)+'\n').encode())
        inputs.copy_new(runner.CACHE/'source-acquisition.json',tree/'source-acquisition.json')
        inputs.copy_new(runner.CACHE/'native-acquisition.json',tree/'native-acquisition.json')
        inputs.copy_new(archive,tree/'images.oci.tar')
        inputs.copy_new(snapshot/'acquisition.json',tree/'acquisition.json')
        proof_revision=subprocess.check_output(['/usr/bin/git','-C',str(runner.PROJECT),'rev-parse','HEAD'],env=runner.SAFE_ENV,text=True).strip()
        runner.write_new(tree/'proof-inputs.json',(json.dumps({'revision':proof_revision,'files':proof_files},indent=2)+'\n').encode())
        paths=sorted(path for path in tree.rglob('*') if path.is_file())
        for path in paths:runner.regular_file(path)
        runner.write_new(tree/'SHA256SUMS',''.join(f'{runner.sha256(path)}  {path.relative_to(tree).as_posix()}\n' for path in paths).encode())
        content_bytes=sum(path.stat().st_size for path in paths)
        disk_bytes=((2*content_bytes+128*1024**2+256*1024**2-1)//(256*1024**2))*(256*1024**2)
        if disk_bytes>2*1024**3:raise ValueError('source disk exceeds 2 GiB bound')
        image=vm.VM/'sources.img'
        fd=os.open(image,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.truncate(disk_bytes)
        runner.regular_file(image)
        subprocess.run(['/usr/bin/mkfs.ext4','-q','-F','-L','MPKG_SOURCES','-E','root_owner=0:0',
                        '-d',str(tree),str(image)],check=True,env=runner.SAFE_ENV,timeout=300)
        evidence={'guest_id':identity['guest_id'],'disk_bytes':disk_bytes,'sha256':runner.sha256(image),
                  'files':len(paths)+1,'sources':len(acquired),'proof_revision':proof_revision,
                  'guest_readonly':True,'host_mount_or_loop_device_used':False}
        runner.write_new(vm.VM/'sources-verification.json',(json.dumps(evidence,indent=2)+'\n').encode())
        print(json.dumps(evidence),flush=True)


if __name__=='__main__':
    if sys.version_info[:2]!=(3,12):raise SystemExit('Python 3.12 is required')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oci-snapshot',required=True)
    args=parser.parse_args()
    os.umask(0o077)
    prepare(args.oci_snapshot)
