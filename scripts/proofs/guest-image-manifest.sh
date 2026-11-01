#!/usr/bin/env bash
# Record observed associations after a separately verified local import.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/image_manifest.py \
    --guest-id "$MPKG_GUEST_ID"
