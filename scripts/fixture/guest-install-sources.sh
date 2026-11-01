#!/usr/bin/env bash
# Install only the verified read-only source disk into the bound guest.
set -euo pipefail
umask 077
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
[[ $EUID == 0 && $MPKG_GUEST_ID =~ ^[0-9a-f-]{36}$ ]]
[[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]]
[[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]]
compact=${MPKG_GUEST_ID//-/}
[[ $(lsblk -dn -o SERIAL /dev/vda | tr -d '[:space:]') == "mpkg${compact:0:16}" ]]
[[ $(blockdev --getsize64 /dev/vda) == 42949672960 ]]
[[ $(findmnt -rn -o MAJ:MIN --target /) == $(cat /sys/class/block/vda2/dev) ]]
[[ -f /etc/mpkg-fixture/identity.json && ! -L /etc/mpkg-fixture/identity.json ]]
[[ $(stat -c '%u:%g:%a' /etc/mpkg-fixture/identity.json) == 0:0:600 ]]
[[ $(cat /var/lib/mpkg-fixture/bootstrap-complete) == "$MPKG_GUEST_ID" ]]
[[ $(lsblk -dn -o SERIAL /dev/vdc | tr -d '[:space:]') == "mpkgsrc${compact:0:13}" ]]
[[ $(blockdev --getro /dev/vdc) == 1 ]]
[[ ! -e /var/lib/mpkg-fixture/sources-installed && ! -L /var/lib/mpkg-fixture/sources-installed ]]
[[ ! -e /run/mpkg-sources && ! -L /run/mpkg-sources ]]
[[ ! -e /opt/mpkg-proofs && ! -L /opt/mpkg-proofs ]]
[[ -d /opt/mpkg-proof-inputs && ! -L /opt/mpkg-proof-inputs ]]
[[ $(stat -c '%u:%g:%a' /opt/mpkg-proof-inputs) == 0:0:700 ]]
for name in sources source-acquisition.json native-acquisition.json images.oci.tar acquisition.json proof-inputs.json; do
    [[ ! -e /opt/mpkg-proof-inputs/$name && ! -L /opt/mpkg-proof-inputs/$name ]]
done
install -d -m 0700 /run/mpkg-sources
mount -o ro,nodev,nosuid,noexec /dev/vdc /run/mpkg-sources
[[ $(findmnt -rn -o MAJ:MIN --target /run/mpkg-sources) == $(cat /sys/class/block/vdc/dev) ]]
[[ ,$(findmnt -rn -o OPTIONS --target /run/mpkg-sources), == *,ro,* ]]
cmp /etc/mpkg-fixture/identity.json /run/mpkg-sources/identity.json
(cd /run/mpkg-sources && sha256sum --strict --check SHA256SUMS >/dev/null)
[[ -z $(find /run/mpkg-sources/sources /run/mpkg-sources/proofs ! -type f ! -type d -print -quit) ]]
cp -R /run/mpkg-sources/sources /opt/mpkg-proof-inputs/
cp -R /run/mpkg-sources/proofs /opt/mpkg-proofs
find /opt/mpkg-proofs -type d -exec chmod 0755 {} +
find /opt/mpkg-proofs -type f -exec chmod 0644 {} +
for name in source-acquisition.json native-acquisition.json images.oci.tar acquisition.json proof-inputs.json; do
    install -m 0600 "/run/mpkg-sources/$name" "/opt/mpkg-proof-inputs/$name"
done
printf '%s  %s\n' b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c /opt/mpkg-proof-inputs/sources/python/Python-3.12.16.tar.xz | sha256sum --strict --check
install -m 0600 /run/mpkg-sources/SHA256SUMS /var/lib/mpkg-fixture/source-disk-SHA256SUMS
printf '%s\n' "$MPKG_GUEST_ID" > /var/lib/mpkg-fixture/sources-installed
sync
printf 'MPKG_SOURCES_INSTALLED=%s\n' "$MPKG_GUEST_ID"
