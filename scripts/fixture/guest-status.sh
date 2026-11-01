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
    SYSTEMD_COLORS=0 systemctl --no-pager --plain show --property=ActiveState,SubState,Result,ExecMainStatus mpkg-fixture-python-build.service
    if [[ -f /var/lib/mpkg-fixture/python-3.12.16/build.log && ! -L /var/lib/mpkg-fixture/python-3.12.16/build.log ]]; then
        printf 'PYTHON_BUILD_LOG_TAIL\n'
        tail -n 8 /var/lib/mpkg-fixture/python-3.12.16/build.log
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
if [[ -f /var/lib/mpkg-fixture/native-adoption/started && ! -L /var/lib/mpkg-fixture/native-adoption/started ]]; then
    printf 'NATIVE_ADOPTION_STATUS\n'
    SYSTEMD_COLORS=0 systemctl --no-pager --plain show --property=ActiveState,SubState,Result,ExecMainStatus mpkg-fixture-native-adoption.service
    for name in exit complete; do
        if [[ -f /var/lib/mpkg-fixture/native-adoption/$name && ! -L /var/lib/mpkg-fixture/native-adoption/$name ]]; then
            printf 'present native-adoption/%s\n' "$name"
        fi
    done
    if [[ -f /var/lib/mpkg-fixture/native-adoption/build.log && ! -L /var/lib/mpkg-fixture/native-adoption/build.log ]]; then
        tail -n 8 /var/lib/mpkg-fixture/native-adoption/build.log
    fi
fi
ps -eo pid=,comm= | awk '$2 ~ /^(pacstrap|pacman|gpg|gpg-agent|make|cc1|ld|ldconfig|mkinitcpio)$/ {print}'
lsblk -o NAME,SIZE,TYPE,SERIAL,MOUNTPOINTS
if [[ -f /var/lib/mpkg-fixture/bootstrap-complete ]]; then
    printf 'installed_packages='
    pacman -Q | wc -l
    pacman -Q pacman systemd docker docker-compose openssh gnupg
fi
