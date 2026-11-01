#!/usr/bin/env python3
"""Read only the exact public Docker load error already bound by its capture."""
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/mpkg-proofs')
from core import Refused, read_regular, require_guest
from native_service import trusted_path
from run import trusted_install

DIGEST = '3c15efd23ab2fa788fd8aa890f35ea386e0118fb267e7abdbae7042099979350'
SIZE = 182


def exact_error(raw):
    if (len(raw) != SIZE or hashlib.sha256(raw).hexdigest() != DIGEST
            or any(value not in (10, 13) and not 32 <= value <= 126 for value in raw)):
        raise Refused('image_error_read_exact_bytes_required')
    return raw.decode('ascii')


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    guest = require_guest(os.environ.get('MPKG_GUEST_ID'))
    trusted_install()
    directory = Path('/var/lib/mpkg-proofs')/guest/'image-index-load-diagnostic'
    capture_path = directory/'capture.json'
    trusted_path(capture_path)
    capture = json.loads(read_regular(capture_path)[0])
    if (capture.get('capture_status') != 'exited' or capture.get('client_exit_code') != 1
            or capture.get('command_completed') is not True
            or capture.get('output', {}).get('stderr') != {'file': 'stderr.private', 'bytes': SIZE, 'sha256': DIGEST}):
        raise Refused('image_error_read_capture_changed')
    path = directory/'stderr.private'
    info = trusted_path(path)
    if info.st_size != SIZE or stat.S_IMODE(info.st_mode) != 0o600:
        raise Refused('image_error_read_file_shape')
    raw = read_regular(path)[0]
    print(json.dumps({'schema': 1, 'guest_id': guest, 'read_only': True,
                      'source': 'fixed local Docker image-load stderr', 'sha256': DIGEST,
                      'bytes': SIZE, 'stderr': exact_error(raw)}, sort_keys=True))


if __name__ == '__main__':
    main()
