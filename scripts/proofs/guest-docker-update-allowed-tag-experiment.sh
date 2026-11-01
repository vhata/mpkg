#!/usr/bin/env bash
# Fixed disposable mechanism attempt; no product acceptance is inferred.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/docker_variant_experiment.py \
    --variant docker-update-allowed-tag --guest-id "$MPKG_GUEST_ID"
