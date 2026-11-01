#!/usr/bin/env python3
"""Send only the verified metadata closure through the bound VM control port."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import time
import uuid

import runner
import vm

REPORT_SHA256 = '2e1ab12cc11766ecbde486cdadbc0ef2c51c10ff6547c17006eb6e891ca9cbd4'
SOURCE = runner.CACHE/'oci-supplements/acquisition-4fe679e2d8c24dd699b1724fcf66a125'


def inputs():
    raw = runner.regular_file(SOURCE/'acquisition.json').read_bytes()
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != REPORT_SHA256:
        raise ValueError('offline metadata report changed')
    report = json.loads(raw)
    descriptors = {}
    for image in report['images']:
        for blob in image['blobs']:
            digest = blob['digest']
            if digest in descriptors and descriptors[digest] != blob:
                raise ValueError('offline metadata descriptor conflict')
            descriptors[digest] = blob
    if len(descriptors) != 11 or sum(b['size'] for b in descriptors.values()) > 32*1024**2:
        raise ValueError('offline metadata scope changed')
    files = {}
    for digest, blob in sorted(descriptors.items()):
        if not 0 < blob['size'] <= 16*1024**2:
            raise ValueError('offline metadata size bound')
        path = runner.regular_file(SOURCE/'blobs/sha256'/digest[7:])
        if path.stat().st_size != blob['size']:
            raise ValueError('offline metadata size changed')
        data = path.read_bytes()
        if 'sha256:'+hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('offline metadata digest changed')
        files[digest] = data
    return files


def timeout(sock, deadline):
    remaining = deadline-time.monotonic()
    if remaining <= 0:
        raise ValueError('offline metadata transfer deadline')
    sock.settimeout(min(30, remaining))


def line(sock, deadline):
    value = bytearray()
    while len(value) < 1024:
        timeout(sock, deadline)
        try:
            part = sock.recv(1)
        except TimeoutError:
            continue
        if not part:
            raise ValueError('offline metadata peer closed')
        if part == b'\n':
            return json.loads(value)
        value.extend(part)
    raise ValueError('offline metadata peer message bound')


def send(sock, data, deadline):
    for offset in range(0, len(data), 65536):
        timeout(sock, deadline)
        sock.sendall(data[offset:offset+65536])


def validate_ready(value, guest):
    if (set(value) != {'schema', 'guest_id', 'attempt', 'report_sha256', 'status'}
            or value['schema'] != 1 or value['guest_id'] != guest
            or value['report_sha256'] != REPORT_SHA256 or value['status'] != 'ready-for-fixed-metadata'
            or str(uuid.UUID(value['attempt'])) != value['attempt']):
        raise ValueError('offline metadata receiver binding changed')
    return value['attempt']


def main():
    os.umask(0o077)
    data = inputs()
    guest = vm.vm_identity()['guest_id']
    lock = os.open(vm.VM/'metadata-transfer.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, 'r+'):
        fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        if vm.qmp_query('query-status').get('status') != 'running':
            raise ValueError('bound VM is not running')
        path = vm.VM/'g.sock'
        info = path.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError('control socket is not private and owned')
        deadline = time.monotonic()+300
        with socket.socket(socket.AF_UNIX) as sock:
            timeout(sock, deadline)
            sock.connect(str(path))
            print(json.dumps({'status': 'waiting-for-bound-guest', 'guest_id': guest,
                              'report_sha256': REPORT_SHA256}), flush=True)
            ready = line(sock, deadline)
            attempt = validate_ready(ready, guest)
            # Revalidate QMP UUID/running status immediately before transmitting.
            stable = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_ctime_ns)
            if (vm.qmp_query('query-status').get('status') != 'running'
                    or stable(path.lstat()) != stable(info)):
                raise ValueError('control VM/socket changed before transfer')
            send(sock, ('MPKG-OCI-SUPPLEMENT/1\n'+guest+'\n'+REPORT_SHA256+'\n').encode(), deadline)
            for raw in data.values():
                send(sock, raw, deadline)
            send(sock, b'END\n', deadline)
            accepted = line(sock, deadline)
            if accepted != dict(ready, status='metadata-verified', blobs=11):
                raise ValueError('guest did not verify exact metadata')
            if vm.qmp_query('query-status').get('status') != 'running':
                raise ValueError('bound VM stopped during transfer')
        print(json.dumps({'status': 'metadata-delivered-and-verified', 'guest_id': guest,
                          'attempt': attempt, 'report_sha256': REPORT_SHA256,
                          'blobs': len(data), 'bytes': sum(map(len, data.values())),
                          'image_load_success_claimed': False}), flush=True)


if __name__ == '__main__':
    if sys.version_info[:2] != (3, 12):
        raise SystemExit('Python 3.12 is required')
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'unverified', 'code': 'offline_metadata_transfer_failed',
                          'exception_type': type(error).__name__}), flush=True)
        raise SystemExit(74)
