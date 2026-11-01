#!/usr/bin/env bash
# Read-only readiness observation after the host binds the QMP UUID.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
[[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]]
[[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]]
printf 'MPKG_GUEST_READY=%s\n' "$MPKG_GUEST_ID"
id
lsblk -o NAME,SIZE,TYPE,SERIAL,MOUNTPOINTS
date --utc --iso-8601=seconds
uptime
systemctl is-system-running || true
