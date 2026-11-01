#!/usr/bin/env bash
# Fixed resource retirement mechanism after its completed port experiment.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/docker_variant_retire.py \
    --variant volume-delete --guest-id "$MPKG_GUEST_ID"
