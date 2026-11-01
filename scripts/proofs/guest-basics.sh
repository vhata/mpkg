#!/usr/bin/env bash
# Fixed non-package/non-container experiments; stop at the first failure.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
for proof in journal inputs xml retirement supervision; do
    /opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-proofs/run.py run \
        --guest-id "$MPKG_GUEST_ID" --proof "$proof"
done
