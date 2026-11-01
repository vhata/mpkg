#!/usr/bin/env bash
# Fixed real package conflict, metadata-only, in an empty isolated guest DB.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/native_conflict.py \
    --guest-id "$MPKG_GUEST_ID"
