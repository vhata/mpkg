#!/usr/bin/env bash
# Fixed preacquired Sonarr/Radarr mechanism experiment.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/run.py run \
    --guest-id "$MPKG_GUEST_ID" --proof compose
