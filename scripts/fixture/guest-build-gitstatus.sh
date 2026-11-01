#!/usr/bin/env bash
# The output disk exists only after the host preserved native-change.
set -euo pipefail
umask 077
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
/opt/mpkg-python/3.12.16/bin/python3.12 -I -c 'import os,sys; sys.path.insert(0,"/opt/mpkg-proofs"); from core import require_guest; require_guest(os.environ["MPKG_GUEST_ID"])'
compact=${MPKG_GUEST_ID//-/}
[[ $(lsblk -dn -o SERIAL /dev/vdd | tr -d '[:space:]') == "mpkgout${compact:0:13}" ]]
[[ $(blockdev --getsize64 /dev/vdd) == 134217728 && $(blockdev --getro /dev/vdd) == 0 ]]
[[ ! -e /run/mpkg-build-output && ! -L /run/mpkg-build-output ]]
install -d -m 0700 /run/mpkg-build-output
mount -o nodev,nosuid,noexec /dev/vdd /run/mpkg-build-output
/opt/mpkg-python/3.12.16/bin/python3.12 -I /opt/mpkg-fixture/guest_aur.py --guest-id "$MPKG_GUEST_ID" --mode gitstatus
