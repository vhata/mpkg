#!/usr/bin/env bash
# Read only package database path metadata after the completed ISO install.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
[[ $EUID == 0 ]]
[[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]]
[[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]]
[[ $(findmnt -rn -o MAJ:MIN --target /mnt) == $(cat /sys/class/block/vda2/dev) ]]
[[ $(cat /mnt/var/lib/mpkg-fixture/bootstrap-complete) == "$MPKG_GUEST_ID" ]]
for path in /mnt /mnt/var /mnt/var/lib /mnt/var/lib/pacman /mnt/var/lib/pacman/local; do
    stat -c '%n %F %u:%g:%a' "$path"
done
printf 'LOCAL_DATABASE_METADATA_COUNTS\n'
find /mnt/var/lib/pacman/local -xdev -printf '%y %U:%G:%m %f\n' | awk '{count[$1" "$2]++} END {for (key in count) print key,count[key]}' | LC_ALL=C sort
printf 'LOCAL_DATABASE_SPECIAL_PATHS\n'
find /mnt/var/lib/pacman/local -xdev ! -type d ! -type f -printf '%P %y\n'
printf 'LOCAL_DATABASE_FILENAMES\n'
find /mnt/var/lib/pacman/local -xdev -type f -printf '%f\n' | LC_ALL=C sort -u
printf 'LOCAL_DATABASE_TOP_LEVEL\n'
find /mnt/var/lib/pacman/local -mindepth 1 -maxdepth 1 -type f -printf '%f %U:%G:%m\n'
printf 'LOCAL_DATABASE_SAMPLE\n'
find /mnt/var/lib/pacman/local -xdev -printf '%P %y %U:%G:%m\n' | LC_ALL=C sort | awk 'NR <= 12'
