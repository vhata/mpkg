#!/usr/bin/env bash
# Read only fixed nonsecret fixture status; do not print command arguments.
set -euo pipefail
: "${MPKG_GUEST_ID:?expected guest UUID is required}"
[[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]]
[[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]]
printf 'MPKG_STATUS_GUEST=%s\n' "$MPKG_GUEST_ID"
for path in /run/mpkg-bootstrap.started /run/mpkg-bootstrap-resume.exit /mnt/var/lib/mpkg-fixture/bootstrap-complete /var/lib/mpkg-fixture/bootstrap-complete /var/lib/mpkg-fixture/python-3.12.16/started /var/lib/mpkg-fixture/python-3.12.16/exit /var/lib/mpkg-fixture/python-3.12.16/complete /var/lib/mpkg-fixture/python-3.12.16/result.json; do
    if [[ -f $path && ! -L $path ]]; then
        printf 'present %s\n' "$path"
    else
        printf 'absent %s\n' "$path"
    fi
done
if [[ -f /run/mpkg-bootstrap-resume.exit && ! -L /run/mpkg-bootstrap-resume.exit ]]; then
    code=$(cat /run/mpkg-bootstrap-resume.exit)
    [[ $code =~ ^[0-9]{1,3}$ ]] && printf 'resume_exit=%s\n' "$code"
fi
if [[ -f /var/lib/mpkg-fixture/python-3.12.16/exit && ! -L /var/lib/mpkg-fixture/python-3.12.16/exit ]]; then
    code=$(cat /var/lib/mpkg-fixture/python-3.12.16/exit)
    [[ $code =~ ^[0-9]{1,3}$ ]] && printf 'python_build_exit=%s\n' "$code"
fi
if [[ -f /var/lib/mpkg-fixture/python-3.12.16/started && ! -L /var/lib/mpkg-fixture/python-3.12.16/started ]]; then
    SYSTEMD_COLORS=0 systemctl --no-pager --plain show --property=ActiveState,SubState,Result,ExecMainStatus,MainPID,ControlPID,ControlGroup,TasksCurrent mpkg-fixture-python-build.service
    if [[ -f /var/lib/mpkg-fixture/python-3.12.16/build.log && ! -L /var/lib/mpkg-fixture/python-3.12.16/build.log ]]; then
        printf 'PYTHON_BUILD_LOG_TAIL\n'
        tail -n 8 /var/lib/mpkg-fixture/python-3.12.16/build.log
    fi
    if [[ -f /var/lib/mpkg-fixture/python-3.12.16/complete && ! -L /var/lib/mpkg-fixture/python-3.12.16/complete ]]; then
        [[ $(stat -c '%u:%g:%a' /var/lib/mpkg-fixture/python-3.12.16/complete) == 0:0:600 ]]
        complete=$(head -c 128 /var/lib/mpkg-fixture/python-3.12.16/complete)
        [[ $complete == "$MPKG_GUEST_ID" ]]
        printf 'PYTHON_COMPLETE_UUID=%s\n' "$complete"
        builder=/var/lib/mpkg-fixture/python-3.12.16/builder.txt
        [[ -f $builder && ! -L $builder && $(stat -c '%u:%g:%a' "$builder") == 0:0:600 ]]
        [[ $(stat -c '%s' "$builder") -le 1024 ]]
        printf 'PYTHON_BUILDER_RECORDED\n'
        head -c 1024 "$builder"
        printf 'PYTHON_BUILDER_CURRENT\n'
        id mpkg-pybuild
        { ps -u mpkg-pybuild -o pid=,comm= || [[ $? == 1 ]]; } | awk 'NR <= 16 {print} END {printf "PYTHON_BUILDER_PROCESS_COUNT=%d\n", NR}'
        result=/var/lib/mpkg-fixture/python-3.12.16/result.json
        [[ -f $result && ! -L $result && $(stat -c '%u:%g:%a' "$result") == 0:0:600 ]]
        [[ $(stat -c '%s' "$result") -le 16384 ]]
        printf 'PYTHON_RESULT_JSON\n'
        head -c 16384 "$result"
        sha256sum "$result"
        if [[ -f /sys/fs/cgroup/system.slice/mpkg-fixture-python-build.service/cgroup.events ]]; then
            printf 'PYTHON_CGROUP_EVENTS\n'
            head -c 256 /sys/fs/cgroup/system.slice/mpkg-fixture-python-build.service/cgroup.events
            printf 'PYTHON_CGROUP_PIDS\n'
            head -c 1024 /sys/fs/cgroup/system.slice/mpkg-fixture-python-build.service/cgroup.procs
        else
            printf 'PYTHON_CGROUP_ABSENT\n'
        fi
    fi
fi
for kind in ack gitstatus; do
    state=/var/lib/mpkg-fixture/aur-$kind
    if [[ -f $state/started && ! -L $state/started ]]; then
        printf 'AUR_BUILD_STATUS=%s\n' "$kind"
        SYSTEMD_COLORS=0 systemctl --no-pager --plain show --property=ActiveState,SubState,Result,ExecMainStatus "mpkg-fixture-aur-$kind.service"
        for name in exit complete; do
            if [[ -f $state/$name && ! -L $state/$name ]]; then
                printf 'present %s/%s\n' "$state" "$name"
            fi
        done
        if [[ -f $state/exit && ! -L $state/exit ]]; then
            code=$(cat "$state/exit")
            [[ $code =~ ^[0-9]{1,3}$ ]] && printf 'aur_build_exit=%s\n' "$code"
        fi
        if [[ -f $state/build.log && ! -L $state/build.log ]]; then
            tail -n 8 "$state/build.log"
        fi
    fi
done
for kind in native-adoption native-update-before; do
  state=/var/lib/mpkg-fixture/$kind
  if [[ -f $state/started && ! -L $state/started ]]; then
    printf 'NATIVE_FIXTURE_STATUS=%s\n' "$kind"
    SYSTEMD_COLORS=0 systemctl --no-pager --plain show --property=ActiveState,SubState,Result,ExecMainStatus "mpkg-fixture-$kind.service"
    for name in exit complete; do
        if [[ -f $state/$name && ! -L $state/$name ]]; then
            printf 'present %s/%s\n' "$kind" "$name"
        fi
    done
    if [[ -f $state/build.log && ! -L $state/build.log ]]; then
        tail -n 8 "$state/build.log"
    fi
  fi
done
ps -eo pid=,comm= | awk '$2 ~ /^(pacstrap|pacman|gpg|gpg-agent|make|cc1|ld|ldconfig|mkinitcpio)$/ {print}'
lsblk -o NAME,SIZE,TYPE,SERIAL,MOUNTPOINTS
if [[ -f /var/lib/mpkg-fixture/bootstrap-complete ]]; then
    printf 'installed_packages='
    pacman -Q | wc -l
    pacman -Q pacman systemd docker docker-compose openssh gnupg
fi
