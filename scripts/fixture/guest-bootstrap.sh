#!/usr/bin/env bash
# Run only through the bound disposable VM's private serial console.
set -euo pipefail
umask 077
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
[[ $EUID == 0 ]] || { echo 'Bootstrap requires guest root.' >&2; exit 1; }
[[ $MPKG_GUEST_ID =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 1
[[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]] || { echo 'Not the expected QEMU guest.' >&2; exit 1; }
[[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]] || { echo 'Guest UUID mismatch.' >&2; exit 1; }
compact=${MPKG_GUEST_ID//-/}
[[ $(lsblk -dn -o SERIAL /dev/vda | tr -d '[:space:]') == "mpkg${compact:0:16}" ]] || { echo 'Disposable disk serial mismatch.' >&2; exit 1; }
[[ $(blockdev --getsize64 /dev/vda) == 42949672960 ]] || { echo 'Disposable disk size mismatch.' >&2; exit 1; }
[[ $(lsblk -dn -o SERIAL /dev/vdb | tr -d '[:space:]') == "mpkgin${compact:0:14}" ]] || { echo 'Input disk serial mismatch.' >&2; exit 1; }
[[ -z $(lsblk -nr -o MOUNTPOINTS /dev/vda | tr -d '[:space:]') ]] || { echo 'Target disk is already mounted.' >&2; exit 1; }
[[ -z $(wipefs --no-act --noheadings --output TYPE /dev/vda) ]] || { echo 'Target disk already has filesystem metadata; preserve it.' >&2; exit 1; }
[[ ! -e /run/mpkg-bootstrap.started ]] || { echo 'Bootstrap already attempted in this boot.' >&2; exit 1; }
printf '%s\n' "$MPKG_GUEST_ID" > /run/mpkg-bootstrap.started
mkdir -p /run/mpkg-inputs
mount -o ro,nodev,nosuid,noexec /dev/vdb /run/mpkg-inputs
grep -Fx "  \"guest_id\": \"$MPKG_GUEST_ID\"," /run/mpkg-inputs/identity.json >/dev/null
(cd /run/mpkg-inputs && sha256sum --strict --check SHA256SUMS >/dev/null)
# All destructive operations follow UUID, disk serial/size and input checks.
sfdisk /dev/vda <<'PARTITIONS'
label: gpt
unit: sectors

start=2048,size=2097152,type=U
start=2099200,type=L
PARTITIONS
udevadm settle
mkfs.fat -F 32 -n MPKG_EFI /dev/vda1
mkfs.ext4 -L MPKG_ROOT /dev/vda2
mount /dev/vda2 /mnt
mkdir -p /mnt/boot
mount /dev/vda1 /mnt/boot
# The ISO keyring is seeded with the same accepted public Arch trust inputs.
install -m 0644 /run/mpkg-inputs/keyrings/archlinux* /usr/share/pacman/keyrings/
pacman-key --init
pacman-key --populate archlinux
mapfile -t packages < /run/mpkg-inputs/baseline-artifacts.list
for index in "${!packages[@]}"; do
    [[ ${packages[$index]} =~ ^[a-f0-9]{64}\.pkg\.tar\.zst$ ]] || exit 1
    packages[$index]="/run/mpkg-inputs/artifacts/${packages[$index]}"
done
[[ ${#packages[@]} == 207 ]] || { echo 'Unexpected baseline package count.' >&2; exit 1; }
(umask 022; pacstrap -C /run/mpkg-inputs/pacman.conf -M -U /mnt "${packages[@]}")
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
umask 022
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
umask 077
install -d -m 0700 /mnt/var/lib/mpkg-fixture
arch-chroot /mnt pacman -Q > /mnt/var/lib/mpkg-fixture/bootstrap-packages.txt
arch-chroot /mnt pacman -Qe > /mnt/var/lib/mpkg-fixture/bootstrap-explicit.txt
printf '%s\n' "$MPKG_GUEST_ID" > /mnt/var/lib/mpkg-fixture/bootstrap-complete
sync
printf 'MPKG_BOOTSTRAP_COMPLETE=%s\n' "$MPKG_GUEST_ID"
