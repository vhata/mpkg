#!/usr/bin/env bash
# Check the assembled running fixture, including after an explicit restore.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/docker_baseline.py check \
    --guest-id "$MPKG_GUEST_ID"
