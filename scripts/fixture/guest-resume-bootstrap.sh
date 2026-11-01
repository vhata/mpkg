#!/usr/bin/env bash
# Resume only the observed formatted/mounted, pre-pacstrap fixture failure.
set -euo pipefail
umask 077
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
[[ $EUID == 0 ]]
[[ $MPKG_GUEST_ID =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
[[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]]
[[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]]
compact=${MPKG_GUEST_ID//-/}
[[ $(lsblk -dn -o SERIAL /dev/vda | tr -d '[:space:]') == "mpkg${compact:0:16}" ]]
[[ $(blockdev --getsize64 /dev/vda) == 42949672960 ]]
[[ $(lsblk -dn -o SERIAL /dev/vdb | tr -d '[:space:]') == "mpkgin${compact:0:14}" ]]
[[ -f /run/mpkg-bootstrap.started && ! -L /run/mpkg-bootstrap.started ]]
[[ $(stat -c '%u:%g:%a' /run/mpkg-bootstrap.started) == 0:0:600 ]]
[[ $(cat /run/mpkg-bootstrap.started) == "$MPKG_GUEST_ID" ]]
[[ $(findmnt -rn -o MAJ:MIN --target /mnt) == $(cat /sys/class/block/vda2/dev) ]]
[[ $(findmnt -rn -o MAJ:MIN --target /mnt/boot) == $(cat /sys/class/block/vda1/dev) ]]
[[ $(findmnt -rn -o MAJ:MIN --target /run/mpkg-inputs) == $(cat /sys/class/block/vdb/dev) ]]
[[ ,$(findmnt -rn -o OPTIONS --target /run/mpkg-inputs), == *,ro,* ]]
[[ $(find /mnt -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort) == $'boot\nlost+found' ]]
[[ -z $(find /mnt/boot -mindepth 1 -maxdepth 1 -print -quit) ]]
[[ -z $(find /mnt/lost+found -mindepth 1 -maxdepth 1 -print -quit) ]]
[[ ! -e /mnt/var/lib/pacman/local ]]
grep -Fx "  \"guest_id\": \"$MPKG_GUEST_ID\"," /run/mpkg-inputs/identity.json >/dev/null
(cd /run/mpkg-inputs && sha256sum --strict --check SHA256SUMS >/dev/null)
[[ ! -e /run/mpkg-bootstrap-resume.log ]]
exec > >(tee /run/mpkg-bootstrap-resume.log) 2>&1
trap 'code=$?; printf "MPKG_BOOTSTRAP_RESUME_EXIT=%s\n" "$code"; printf "%s\n" "$code" > /run/mpkg-bootstrap-resume.exit' EXIT
# No partitioning, formatting, remounting or deletion occurs in this continuation.
pacman-key --init
pacman-key --populate archlinux
mapfile -t packages < /run/mpkg-inputs/baseline-artifacts.list
for index in "${!packages[@]}"; do
    [[ ${packages[$index]} =~ ^[a-f0-9]{64}\.pkg\.tar\.zst$ ]] || exit 1
    packages[$index]="/run/mpkg-inputs/artifacts/${packages[$index]}"
done
[[ ${#packages[@]} == 207 ]] || { echo 'Unexpected baseline package count.' >&2; exit 1; }
pacstrap -C /run/mpkg-inputs/pacman.conf -M -U /mnt "${packages[@]}"
mapfile -t dependencies < /run/mpkg-inputs/baseline-dependencies.list
arch-chroot /mnt pacman -D --asdeps "${dependencies[@]}"
arch-chroot /mnt pacman -Q | LC_ALL=C sort > /run/mpkg-installed.txt
diff -u /run/mpkg-inputs/baseline-versions.txt /run/mpkg-installed.txt
for missing in tmux ripgrep libutempter gitstatus cmake zsh; do
    if arch-chroot /mnt pacman -Q "$missing" >/dev/null 2>&1; then
        echo "Required initial absence lost: $missing" >&2; exit 1
    fi
done
install -d -m 0700 /mnt/etc/mpkg-fixture /mnt/opt/mpkg-proof-inputs
install -m 0600 /run/mpkg-inputs/identity.json /mnt/etc/mpkg-fixture/identity.json
cp -R /run/mpkg-inputs/artifacts /mnt/opt/mpkg-proof-inputs/
cp -R /run/mpkg-inputs/databases /mnt/opt/mpkg-proof-inputs/
install -m 0600 /run/mpkg-inputs/source-inventory.json /mnt/opt/mpkg-proof-inputs/source-inventory.json
install -m 0644 /run/mpkg-inputs/pacman.conf /mnt/etc/pacman.conf
genfstab -U /mnt > /mnt/etc/fstab
printf 'mpkg-fixture\n' > /mnt/etc/hostname
ln -sf /usr/share/zoneinfo/America/Los_Angeles /mnt/etc/localtime
printf 'en_US.UTF-8 UTF-8\n' > /mnt/etc/locale.gen
printf 'LANG=en_US.UTF-8\n' > /mnt/etc/locale.conf
arch-chroot /mnt locale-gen
install -d /mnt/etc/systemd/network
cat > /mnt/etc/systemd/network/20-fixture.network <<'NETWORK'
[Match]
Name=en*
[Network]
DHCP=yes
NETWORK
systemctl --root=/mnt enable systemd-networkd systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf /mnt/etc/resolv.conf
install -d /mnt/etc/systemd/system/serial-getty@ttyS0.service.d
cat > /mnt/etc/systemd/system/serial-getty@ttyS0.service.d/fixture.conf <<'GETTY'
[Service]
ExecStart=
ExecStart=-/usr/bin/agetty --autologin root --noclear %I 115200 vt220
GETTY
systemctl --root=/mnt enable serial-getty@ttyS0.service
arch-chroot /mnt bootctl --esp-path=/boot --no-variables install
root_uuid=$(blkid -s UUID -o value /dev/vda2)
cat > /mnt/boot/loader/loader.conf <<'LOADER'
default mpkg.conf
timeout 1
console-mode keep
LOADER
cat > /mnt/boot/loader/entries/mpkg.conf <<ENTRY
title mpkg disposable fixture
linux /vmlinuz-linux
initrd /initramfs-linux.img
options root=UUID=$root_uuid rw console=ttyS0,115200
ENTRY
install -d -m 0700 /mnt/var/lib/mpkg-fixture
arch-chroot /mnt pacman -Q > /mnt/var/lib/mpkg-fixture/bootstrap-packages.txt
arch-chroot /mnt pacman -Qe > /mnt/var/lib/mpkg-fixture/bootstrap-explicit.txt
printf '%s\n' "$MPKG_GUEST_ID" > /mnt/var/lib/mpkg-fixture/bootstrap-complete
sync
printf 'MPKG_BOOTSTRAP_COMPLETE=%s\n' "$MPKG_GUEST_ID"

install -m 0600 /run/mpkg-bootstrap-resume.log /mnt/var/lib/mpkg-fixture/bootstrap-resume.log
