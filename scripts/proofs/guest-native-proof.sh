#!/usr/bin/env bash
# Require real acquisition/build evidence, then run prepare-only native proof.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/native_manifest.py \
    --guest-id "$MPKG_GUEST_ID"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/run.py run \
    --guest-id "$MPKG_GUEST_ID" --proof native
