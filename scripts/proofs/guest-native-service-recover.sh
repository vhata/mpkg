#!/usr/bin/env bash
# Continue only the reviewed one-group/no-user fixture state.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/native_service_recover.py \
    --guest-id "$MPKG_GUEST_ID"
