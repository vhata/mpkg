#!/usr/bin/env python3
"""Import the verified build output after restoring the native-change guest."""
import json
import os
from pathlib import Path
import resource
import subprocess
import sys

sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, require_guest, write_new
from native_manifest import validate_build


def main():
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    sys.path.insert(0, '/opt/mpkg-fixture')
    from guest_aur import checked_file, verify_baseline, SOURCE_SHA
    inputs = Path('/opt/mpkg-proof-inputs')
    source = json.loads(checked_file(inputs/'source-inventory.json', SOURCE_SHA))
    verify_baseline(source, with_ack=True)
    if (Path('/sys/class/block/vde/serial').read_text().strip() != 'mpkgbld'+guest.replace('-', '')[:13]
            or int(Path('/sys/class/block/vde/size').read_text())*512 != 128*1024**2
            or Path('/sys/class/block/vde/ro').read_text().strip() != '1'):
        raise Refused('readonly_built_input_disk_required')
    mount = Path('/run/mpkg-built-input')
    mount.mkdir(mode=0o700)
    env = {'PATH': '/usr/bin', 'LC_ALL': 'C', 'HOME': '/root'}
    subprocess.run(['/usr/bin/mount', '-o', 'ro,nodev,nosuid,noexec', '/dev/vde', str(mount)],
                   env=env, check=True, timeout=30)
    device = tuple(int(v) for v in Path('/sys/class/block/vde/dev').read_text().strip().split(':'))
    actual = mount.stat().st_dev
    if (os.major(actual), os.minor(actual)) != device:
        raise Refused('built_input_mount_changed')
    if checked_file(mount/'identity.json') != checked_file(Path('/etc/mpkg-fixture/identity.json')):
        raise Refused('built_input_guest_identity_changed')
    subprocess.run(['/usr/bin/sha256sum', '--strict', '--check', 'SHA256SUMS'], cwd=mount,
                   env=env, check=True, stdout=subprocess.DEVNULL, timeout=30)
    record_bytes = checked_file(mount/'gitstatus-build.json')
    record = json.loads(record_bytes)
    artifact = validate_build(record, source, guest)
    filename = artifact['sha256']+'.pkg.tar.zst'
    data = checked_file(mount/filename, artifact['sha256'])
    if len(data) != artifact['size']:
        raise Refused('built_artifact_size_changed')
    write_new(inputs/'artifacts'/filename, data)
    write_new(inputs/'gitstatus-build.json', record_bytes)
    write_new(Path('/var/lib/mpkg-fixture/gitstatus-artifact-imported'), (guest+'\n').encode())
    print(json.dumps({'status': 'imported', 'guest_id': guest,
                      'artifact_sha256': artifact['sha256'], 'installed': False}))


if __name__ == '__main__':
    main()
