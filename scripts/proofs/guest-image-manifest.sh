#!/usr/bin/env bash
# Record observed associations after a separately verified local import.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/image_manifest.py \
    --guest-id "$MPKG_GUEST_ID"
/opt/mpkg-python/3.12.16/bin/python3.12 -I - "$MPKG_GUEST_ID" <<'PY'
import json
import resource
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.path.insert(0, '/opt/mpkg-proofs')
try:
    from core import Refused, require_guest
    from native_manifest import trusted_json
    from run import trusted_install
    guest = require_guest(sys.argv[1])
    trusted_install()
    value, digest = trusted_json('compose.json')
    if value.get('schema') != 1 or value.get('guest_id') != guest:
        raise Refused('compose_manifest_hash_identity_changed')
    print(json.dumps({'status': 'observed', 'guest_id': guest, 'compose_sha256': digest}, sort_keys=True))
except Exception:
    print('{"status":"unverified","code":"compose_manifest_hash_unverified"}')
    sys.exit(73)
PY
