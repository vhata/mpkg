#!/usr/bin/env bash
# Fixed private Git/projection and command-error proof, guest only.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/protected_output.py \
    --guest-id "$MPKG_GUEST_ID"
