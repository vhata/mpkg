#!/usr/bin/env bash
# Verify the running fixture while retaining both earlier unknown attempts.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/native_service_observe.py \
    --guest-id "$MPKG_GUEST_ID"
