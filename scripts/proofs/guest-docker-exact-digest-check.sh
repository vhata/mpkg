#!/usr/bin/env bash
# Fixed guest fixture check; the Python entrypoint verifies VM and disk identity.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/docker_variants.py check \
    --variant docker-exact-digest --guest-id "$MPKG_GUEST_ID"
