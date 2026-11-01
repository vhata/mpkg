#!/usr/bin/env bash
# Activate only the retained incomplete image-preparation checkpoint.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/docker_diagnostic_resume.py \
    --guest-id "$MPKG_GUEST_ID"
