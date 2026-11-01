#!/usr/bin/env bash
# Resume only a pinned successful supplemented image-only guest checkpoint.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/docker_supplement_resume.py \
    --guest-id "$MPKG_GUEST_ID"
