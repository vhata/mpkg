#!/usr/bin/env bash
# Fixed native fixture baseline setup and authenticated checks.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/native_service.py setup \
    --guest-id "$MPKG_GUEST_ID"
