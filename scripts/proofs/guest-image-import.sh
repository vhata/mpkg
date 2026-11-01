#!/usr/bin/env bash
# Import exactly the acquired archive; publish bindings only if verified.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/image_import.py \
    --guest-id "$MPKG_GUEST_ID"
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/image_manifest.py \
    --guest-id "$MPKG_GUEST_ID"
