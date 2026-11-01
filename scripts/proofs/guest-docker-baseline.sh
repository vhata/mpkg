#!/usr/bin/env bash
# Assemble the running adoption fixture; leave snapshots to the coordinator.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/docker_baseline.py setup \
    --guest-id "$MPKG_GUEST_ID"
