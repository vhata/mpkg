#!/usr/bin/env bash
# Observe only fixed Python build metadata; never alter the running worker.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C SYSTEMD_PAGER=cat SYSTEMD_COLORS=0
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
[[ $EUID == 0 && $MPKG_GUEST_ID =~ ^[0-9a-f-]{36}$ ]]
[[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]]
[[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]]
[[ $(findmnt -rn -o MAJ:MIN --target /) == $(cat /sys/class/block/vda2/dev) ]]
compact=${MPKG_GUEST_ID//-/}
[[ $(cat /sys/class/block/vda/serial) == "mpkg${compact:0:16}" ]]
[[ $(blockdev --getsize64 /dev/vda) == 42949672960 ]]
marker=/etc/mpkg-fixture/identity.json
[[ -f $marker && ! -L $marker && ! -L /etc/mpkg-fixture ]]
[[ $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 ]]
jq -e --arg guest "$MPKG_GUEST_ID" --arg serial "mpkg${compact:0:16}" '
  . == {schema:1, guest_id:$guest, fixture_id:"first-release-2026-10-31",
        disposable:true, disk_serial:$serial, disk_bytes:42949672960}
' "$marker" >/dev/null
printf 'PYTHON_DIAGNOSTIC_GUEST=%s\n' "$MPKG_GUEST_ID"
systemctl --no-pager --plain show --property=ActiveState,SubState,Result,ExecMainStatus,ExecMainStartTimestamp,MainPID,ControlPID,ControlGroup,TasksCurrent mpkg-fixture-python-build.service
cgroup=/sys/fs/cgroup/system.slice/mpkg-fixture-python-build.service
if [[ -f $cgroup/cgroup.procs ]]; then
    printf 'PYTHON_CGROUP_PID_COMM_WCHAN\n'
    while IFS= read -r pid; do
        [[ $pid =~ ^[0-9]{1,10}$ ]] || exit 1
        if [[ -r /proc/$pid/comm && -r /proc/$pid/wchan ]]; then
            comm=$(head -c 64 "/proc/$pid/comm") || continue
            wchan=$(head -c 64 "/proc/$pid/wchan") || continue
            printf 'pid=%s comm=%q wchan=%q\n' "$pid" "$comm" "$wchan"
        fi
    done < <(head -n 32 "$cgroup/cgroup.procs")
else
    printf 'PYTHON_CGROUP_ABSENT\n'
fi
state=/var/lib/mpkg-fixture/python-3.12.16
for name in started staged-paths result.json complete exit; do
    if [[ -f $state/$name && ! -L $state/$name ]]; then
        stat -c "state=$name bytes=%s owner=%u:%g mode=%a" "$state/$name"
    else
        printf 'state=%s absent\n' "$name"
    fi
done
if [[ -f $state/staged-paths && ! -L $state/staged-paths && $(stat -c '%s' "$state/staged-paths") -le 8388608 ]]; then
    printf 'STAGED_LISTING_RECORDS='
    tr -cd '\000' < "$state/staged-paths" | wc -c
fi
stage=/var/lib/mpkg-python-build/stage/opt/mpkg-python/3.12.16
if [[ -d $stage && ! -L $stage && $(realpath -e "$stage") == "$stage" ]]; then
    # One native traversal, limited to five seconds; partial counts are labelled.
    if summary=$(timeout --kill-after=1 5s find "$stage" -xdev -printf '%y %s\n' |
        awk '{entries++; if ($1=="f") {files++; bytes+=$2}} END {printf "entries=%d regular_files=%d regular_bytes=%.0f\n",entries,files,bytes}'); then
        printf 'STAGED_TREE_COMPLETE %s\n' "$summary"
    else
        printf 'STAGED_TREE_INCOMPLETE %s\n' "$summary"
    fi
else
    printf 'STAGED_TREE_ABSENT_OR_CHANGED\n'
fi
prefix=/opt/mpkg-python/3.12.16
if [[ -d $prefix && ! -L $prefix ]]; then
    stat -c 'INSTALLED_PREFIX_PRESENT owner=%u:%g mode=%a' "$prefix"
    if [[ -f $prefix/bin/python3.12 && ! -L $prefix/bin/python3.12 ]]; then
        stat -c 'INSTALLED_BINARY_PRESENT bytes=%s owner=%u:%g mode=%a' "$prefix/bin/python3.12"
    fi
else
    printf 'INSTALLED_PREFIX_ABSENT\n'
fi
