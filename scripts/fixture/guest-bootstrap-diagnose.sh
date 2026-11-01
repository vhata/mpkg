#!/usr/bin/env bash
# Read-only guard diagnostics for the observed partial bootstrap.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
[[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]]
[[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]]
value() { local label=$1 output; shift; output=$("$@" 2>&1) || true; printf '%s=%q\n' "$label" "$output"; }
value started_stat stat -c '%u:%g:%a' /run/mpkg-bootstrap.started
value started_value cat /run/mpkg-bootstrap.started
value target_serial lsblk -dn -o SERIAL /dev/vda
value target_size blockdev --getsize64 /dev/vda
value input_serial lsblk -dn -o SERIAL /dev/vdb
value mnt_default findmnt -n -o MAJ:MIN --target /mnt
value mnt_raw findmnt -rn -o MAJ:MIN --target /mnt
value vda2 cat /sys/class/block/vda2/dev
value boot_default findmnt -n -o MAJ:MIN --target /mnt/boot
value boot_raw findmnt -rn -o MAJ:MIN --target /mnt/boot
value vda1 cat /sys/class/block/vda1/dev
value inputs_default findmnt -n -o MAJ:MIN --target /run/mpkg-inputs
value inputs_raw findmnt -rn -o MAJ:MIN --target /run/mpkg-inputs
value vdb cat /sys/class/block/vdb/dev
value inputs_options findmnt -n -o OPTIONS --target /run/mpkg-inputs
value mnt_entries find /mnt -mindepth 1 -maxdepth 1 -printf '%f\n'
value boot_entry find /mnt/boot -mindepth 1 -maxdepth 1 -print -quit
value lost_found_entry find /mnt/lost+found -mindepth 1 -maxdepth 1 -print -quit
value previous_payload_sha256 sha256sum /run/mpkg-fixture-input.sh
if [[ -e /mnt/var/lib/pacman/local ]]; then printf 'target_local_database=present\n'; else printf 'target_local_database=absent\n'; fi
if [[ -e /run/mpkg-bootstrap-resume.log ]]; then printf 'resume_log=present\n'; else printf 'resume_log=absent\n'; fi
