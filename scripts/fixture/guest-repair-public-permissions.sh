#!/usr/bin/env bash
# Correct only known public bootstrap paths after the completed ISO install.
set -euo pipefail
umask 077
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
[[ $EUID == 0 && $MPKG_GUEST_ID =~ ^[0-9a-f-]{36}$ ]]
[[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]]
[[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]]
compact=${MPKG_GUEST_ID//-/}
[[ $(lsblk -dn -o SERIAL /dev/vda | tr -d '[:space:]') == "mpkg${compact:0:16}" ]]
[[ $(blockdev --getsize64 /dev/vda) == 42949672960 ]]
[[ $(findmnt -rn -o MAJ:MIN --target /mnt) == $(cat /sys/class/block/vda2/dev) ]]
[[ $(cat /mnt/var/lib/mpkg-fixture/bootstrap-complete) == "$MPKG_GUEST_ID" ]]
[[ $(cat /run/mpkg-bootstrap-resume.exit) == 0 ]]
[[ $(findmnt -rn -o MAJ:MIN --target /run/mpkg-inputs) == $(cat /sys/class/block/vdb/dev) ]]
cmp /mnt/etc/mpkg-fixture/identity.json /run/mpkg-inputs/identity.json
[[ ! -e /mnt/var/lib/mpkg-fixture/public-permissions-repaired ]]
# Exact package directory expectations: public-directory-modes.json.
# /boot is a FAT mount; private paths and virtual mounts are excluded.
paths=(
    /etc
    /etc/pacman.d
    /usr
    /usr/bin
    /usr/lib
    /var
    /var/cache
    /var/cache/pacman
    /var/cache/pacman/pkg
    /var/lib
    /var/lib/pacman
    /etc/systemd/network
    /etc/systemd/system/serial-getty@ttyS0.service.d
)
files=(
    /etc/fstab /etc/hostname /etc/locale.gen /etc/locale.conf
    /etc/systemd/network/20-fixture.network
    /etc/systemd/system/serial-getty@ttyS0.service.d/fixture.conf
)
# Validate every path before making the first correction. Resolve each path
# lexically and physically so no intermediate symlink redirects chmod.
for path in "${paths[@]}" "${files[@]}"; do
    target=/mnt$path
    [[ $(realpath -e "$target") == "$target" && ! -L $target ]]
    [[ $(stat -c '%u:%g' "$target") == 0:0 ]]
    [[ $(findmnt -rn -o MAJ:MIN --target "$target") == $(cat /sys/class/block/vda2/dev) ]]
done
for path in "${paths[@]}"; do [[ -d /mnt$path ]]; done
for path in "${files[@]}"; do [[ -f /mnt$path ]]; done
for path in "${paths[@]}"; do
    printf 'directory %s %s -> 755\n' "$path" "$(stat -c '%a' "/mnt$path")"
    chmod 0755 "/mnt$path"
done
for path in "${files[@]}"; do
    printf 'public-config %s %s -> 644\n' "$path" "$(stat -c '%a' "/mnt$path")"
    chmod 0644 "/mnt$path"
done
[[ $(stat -c '%a' /mnt/etc/mpkg-fixture) == 700 ]]
[[ $(stat -c '%a' /mnt/opt/mpkg-proof-inputs) == 700 ]]
[[ $(stat -c '%a' /mnt/etc/mpkg-fixture/identity.json) == 600 ]]
arch-chroot /mnt pacman -Q | LC_ALL=C sort > /run/mpkg-permission-packages.txt
diff -u /run/mpkg-inputs/baseline-versions.txt /run/mpkg-permission-packages.txt
# The recorded audit found every package directory/file already 755/644.
# Only this generated public DB root and version file inherited 700/600.
database=/mnt/var/lib/pacman/local
version=$database/ALPM_DB_VERSION
[[ $(realpath -e "$database") == "$database" && -d $database && ! -L $database ]]
[[ $(realpath -e "$version") == "$version" && -f $version && ! -L $version ]]
[[ $(stat -c '%u:%g:%h' "$version") == 0:0:1 ]]
[[ $(stat -c '%u:%g' "$database") == 0:0 ]]
[[ $(findmnt -rn -o MAJ:MIN --target "$database") == $(cat /sys/class/block/vda2/dev) ]]
chmod 0755 "$database"
chmod 0644 "$version"
# Prove ordinary unprivileged package queries can traverse the public DB.
arch-chroot /mnt runuser -u nobody -- pacman -Q | LC_ALL=C sort > /run/mpkg-unprivileged-packages.txt
diff -u /run/mpkg-inputs/baseline-versions.txt /run/mpkg-unprivileged-packages.txt
printf '%s\n' "$MPKG_GUEST_ID" > /mnt/var/lib/mpkg-fixture/public-permissions-repaired
sync
printf 'MPKG_PUBLIC_PERMISSIONS_REPAIRED=%s\n' "$MPKG_GUEST_ID"
