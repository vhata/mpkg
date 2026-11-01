#!/usr/bin/env python3
"""Create or restore named disk checkpoints only while the bound VM is stopped."""
import argparse
import json
import os
import re
import subprocess
import sys
import uuid

import inputs
import runner
import vm


def info():
    output=subprocess.check_output(vm.sandbox_command(['/usr/bin/qemu-img','info','--output=json',
                                                      '/run/mpkg-fixture/disk.qcow2'],writable_vm=False),
                                   env=runner.SAFE_ENV,timeout=60)
    data=json.loads(output)
    if data['format']!='qcow2' or data['virtual-size']!=vm.DISK_BYTES or data.get('backing-filename'):
        raise ValueError('unexpected disposable disk format, size or backing file')
    return data


def create(name,identity):
    directory=runner.private_directory(vm.VM/'snapshots')
    if (directory/(name+'.json')).exists() or any(s['name']==name for s in info().get('snapshots',[])):
        raise ValueError('checkpoint already exists; never overwrite it')
    inputs.copy_new(vm.VM/'vars.fd',directory/(name+'.vars.fd'))
    subprocess.run(vm.sandbox_command(['/usr/bin/qemu-img','snapshot','-c',name,
                                       '/run/mpkg-fixture/disk.qcow2']),
                   env=runner.SAFE_ENV,check=True,timeout=120)
    snapshots=[s for s in info().get('snapshots',[]) if s['name']==name]
    if len(snapshots)!=1:raise ValueError('created checkpoint identity is unresolved')
    result={'schema':1,'guest_id':identity['guest_id'],'name':name,'snapshot':snapshots[0],
            'firmware_vars_sha256':runner.sha256(directory/(name+'.vars.fd')),
            'disk_bytes':vm.DISK_BYTES,'vm_stopped':True}
    runner.write_new(directory/(name+'.json'),(json.dumps(result,indent=2)+'\n').encode())
    return result


def operation(action,name):
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,47}',name):raise ValueError('invalid checkpoint name')
    identity=vm.vm_identity()
    with vm.vm_lock():
        runner.regular_file(vm.VM/'disk.qcow2');runner.regular_file(vm.VM/'vars.fd')
        vm.require_no_restore_pending()
        if action=='create':return create(name,identity)
        directory=vm.VM/'snapshots'
        record=json.loads(runner.regular_file(directory/(name+'.json')).read_text())
        variables=runner.regular_file(directory/(name+'.vars.fd'))
        if record['guest_id']!=identity['guest_id'] or record['name']!=name:
            raise ValueError('checkpoint belongs to another VM')
        if runner.sha256(variables)!=record['firmware_vars_sha256']:
            raise ValueError('checkpoint firmware variables changed')
        current=next((s for s in info().get('snapshots',[]) if s['name']==name),None)
        if current is None or current['id']!=record['snapshot']['id']:
            raise ValueError('checkpoint is missing or was replaced')
        backup='before-restore-'+uuid.uuid4().hex[:16]
        create(backup,identity)
        temporary=vm.VM/'restore-vars.pending'
        inputs.copy_new(variables,temporary)
        pending=vm.VM/'restore.pending.json'
        runner.write_new(pending,(json.dumps({'guest_id':identity['guest_id'],
                         'restore':name,'preserved_previous':backup})+'\n').encode())
        subprocess.run(vm.sandbox_command(['/usr/bin/qemu-img','snapshot','-a',name,
                                           '/run/mpkg-fixture/disk.qcow2']),
                       env=runner.SAFE_ENV,check=True,timeout=120)
        os.replace(temporary,vm.VM/'vars.fd')
        os.replace(pending,vm.VM/('restore-complete-'+uuid.uuid4().hex+'.json'))
        return {'guest_id':identity['guest_id'],'restored':name,'preserved_previous':backup,
                'guest_running':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['create','restore']);parser.add_argument('name')
    args=parser.parse_args()
    if sys.version_info[:2]!=(3,12):parser.error('Python 3.12 is required')
    os.umask(0o077)
    print(json.dumps(operation(args.operation,args.name)),flush=True)
