#!/usr/bin/env bash
# Build the pinned interpreter only in the installed disposable fixture.
set -Eeuo pipefail
export PATH=/usr/bin:/bin LC_ALL=C

readonly PREFIX=/opt/mpkg-python/3.12.16
readonly SOURCE=/opt/mpkg-proof-inputs/sources/python/Python-3.12.16.tar.xz
readonly SOURCE_SHA=b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c
readonly STATE=/var/lib/mpkg-fixture/python-3.12.16
readonly WORK=/var/lib/mpkg-python-build
readonly BUILDER=mpkg-pybuild
readonly INSTALLED=/usr/local/libexec/mpkg-fixture/python-build.sh
readonly UNIT=mpkg-fixture-python-build.service

refuse() { printf 'MPKG_PYTHON_REFUSED=%s\n' "$1" >&2; exit 1; }

guest_guard() {
    [[ $EUID == 0 ]] || refuse root_required
    [[ ${MPKG_GUEST_ID:-} =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || refuse uuid_required
    [[ $(cat /sys/class/dmi/id/sys_vendor) == QEMU ]] || refuse vendor_mismatch
    [[ $(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid) == "$MPKG_GUEST_ID" ]] || refuse uuid_mismatch
    [[ $(findmnt -rn -o MAJ:MIN --target /) == $(cat /sys/class/block/vda2/dev) ]] || refuse installed_root_required
    local compact=${MPKG_GUEST_ID//-/}
    [[ $(cat /sys/class/block/vda/serial) == "mpkg${compact:0:16}" ]] || refuse disk_serial_mismatch
    [[ $(blockdev --getsize64 /dev/vda) == 42949672960 ]] || refuse disk_size_mismatch
    local marker=/etc/mpkg-fixture/identity.json
    [[ -f $marker && ! -L $marker && ! -L /etc/mpkg-fixture ]] || refuse marker_shape
    [[ $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 ]] || refuse marker_permissions
    jq -e --arg guest "$MPKG_GUEST_ID" --arg serial "mpkg${compact:0:16}" '
        . == {schema:1, guest_id:$guest,
              fixture_id:"first-release-2026-10-31", disposable:true,
              disk_serial:$serial, disk_bytes:42949672960}
    ' "$marker" >/dev/null || refuse marker_mismatch
}

root_directory() {
    local path=$1 mode
    [[ -d $path && ! -L $path && $(stat -c %u "$path") == 0 ]] || refuse directory_owner
    mode=$(stat -c %a "$path")
    (( (8#$mode & 0022) == 0 )) || refuse directory_writable
}

source_guard() {
    local path
    for path in /opt /opt/mpkg-proof-inputs /opt/mpkg-proof-inputs/sources /opt/mpkg-proof-inputs/sources/python; do
        root_directory "$path"
    done
    [[ -f $SOURCE && ! -L $SOURCE && $(stat -c '%u:%g:%h' "$SOURCE") == 0:0:1 ]] || refuse source_shape
    printf '%s  %s\n' "$SOURCE_SHA" "$SOURCE" | sha256sum --strict --check >/dev/null || refuse source_digest
}

stage_guard() {
    # The builder has exited. Publish only a bounded tree of ordinary files,
    # directories and links resolving within this exact staged prefix.
    local stage=$1 listing=$2 path mode resolved count=0 bytes=0
    [[ -d $stage && ! -L $stage ]] || refuse stage_missing
    [[ $(realpath -e -- "$stage") == "$stage" ]] || refuse stage_parent_link
    find "$stage" -xdev -print0 > "$listing"
    while IFS= read -r -d '' path; do
        ((count+=1))
        ((count <= 20000)) || refuse stage_entry_bound
        if [[ -L $path ]]; then
            resolved=$(realpath -e -- "$path") || refuse stage_broken_link
            [[ $resolved == "$stage" || $resolved == "$stage/"* ]] || refuse stage_link_escape
        elif [[ -f $path || -d $path ]]; then
            mode=$(stat -c %a "$path")
            (( (8#$mode & 06022) == 0 )) || refuse stage_mode
            if [[ -f $path ]]; then
                [[ $(stat -c %h "$path") == 1 ]] || refuse stage_hardlink
                bytes=$((bytes + $(stat -c %s "$path")))
                ((bytes <= 1073741824)) || refuse stage_byte_bound
            fi
        else
            refuse stage_special_file
        fi
    done < "$listing"
}

worker() {
    [[ $(realpath -e -- "$0") == "$INSTALLED" ]] || refuse installed_worker_required
    [[ $(stat -c '%u:%g:%a' "$INSTALLED") == 0:0:700 ]] || refuse worker_permissions
    root_directory "$STATE"
    [[ ! -e $STATE/started && ! -e $STATE/exit && ! -e $PREFIX && ! -L $PREFIX ]] || refuse previous_build_state
    umask 077
    exec > "$STATE/build.log" 2>&1
    trap 'code=$?; printf "%s\n" "$code" > "$STATE/exit"; printf "MPKG_PYTHON_BUILD_EXIT=%s\n" "$code"' EXIT
    printf '%s\n' "$MPKG_GUEST_ID" > "$STATE/started"
    source_guard
    [[ ! -e $WORK && ! -L $WORK ]] || refuse work_exists
    if getent passwd "$BUILDER" >/dev/null || getent group "$BUILDER" >/dev/null; then
        refuse builder_identity_exists
    fi
    useradd --system --user-group --home-dir "$WORK" --shell /usr/bin/nologin "$BUILDER"
    install -d -m 0700 -o "$BUILDER" -g "$BUILDER" "$WORK"
    install -m 0400 -o "$BUILDER" -g "$BUILDER" "$SOURCE" "$WORK/Python-3.12.16.tar.xz"
    printf '%s  %s\n' "$SOURCE_SHA" "$WORK/Python-3.12.16.tar.xz" | sha256sum --strict --check
    id "$BUILDER" > "$STATE/builder.txt"
    gcc --version > "$STATE/compiler.txt"
    printf '%s\n' './configure --prefix=/opt/mpkg-python/3.12.16 --with-ensurepip=no' 'make -j4' 'make DESTDIR=<private-stage> install' > "$STATE/commands.txt"
    # Extraction, configure, compilation and make install all run unprivileged.
    runuser -u "$BUILDER" -- env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
        bash --noprofile --norc -c '
            set -euo pipefail
            umask 022
            cd /var/lib/mpkg-python-build
            tar --extract --xz --file Python-3.12.16.tar.xz --no-same-owner
            cd Python-3.12.16
            ./configure --prefix=/opt/mpkg-python/3.12.16 --with-ensurepip=no
            make -j4
            make DESTDIR=/var/lib/mpkg-python-build/stage install
        '
    if pgrep -u "$BUILDER" >/dev/null; then refuse builder_process_survives; fi
    local stage=$WORK/stage$PREFIX
    stage_guard "$stage" "$STATE/staged-paths"
    if [[ ! -e /opt/mpkg-python ]]; then install -d -m 0755 /opt/mpkg-python; fi
    root_directory /opt/mpkg-python
    [[ ! -e $PREFIX && ! -L $PREFIX ]] || refuse prefix_appeared
    cp -a --no-preserve=ownership -- "$stage" "$PREFIX"
    "$PREFIX/bin/python3.12" -I -B - "$STATE" "$SOURCE_SHA" <<'PYTHON'
import bz2, ctypes, dbm.gnu, hashlib, json, lzma, os
from pathlib import Path
import readline, sqlite3, ssl, stat, sys, sysconfig, zlib
state = Path(sys.argv[1])
prefix = Path('/opt/mpkg-python/3.12.16')
assert sys.version_info[:3] == (3, 12, 16)
assert Path(sys.prefix) == prefix and Path(sys.executable) == prefix / 'bin/python3.12'
assert sqlite3.connect(':memory:').execute('select 1').fetchone() == (1,)
assert bz2.decompress(bz2.compress(b'fixture')) == b'fixture'
assert lzma.decompress(lzma.compress(b'fixture')) == b'fixture'
assert zlib.decompress(zlib.compress(b'fixture')) == b'fixture'
assert ctypes.CDLL(None).getpid() == os.getpid()
ssl.create_default_context()
tree = hashlib.sha256()
for path in sorted(prefix.rglob('*')):
    info = path.lstat()
    assert info.st_uid == 0 and info.st_gid == 0
    if not path.is_symlink():
        assert not info.st_mode & 0o6022
    row = [str(path.relative_to(prefix)), stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode)]
    if path.is_symlink():
        assert path.resolve().is_relative_to(prefix)
        row.append(os.readlink(path))
    elif path.is_file():
        row.append(hashlib.sha256(path.read_bytes()).hexdigest())
    tree.update(json.dumps(row, separators=(',', ':')).encode() + b'\n')
record = dict(schema=1, python_version=sys.version, prefix=str(prefix),
              source_sha256=sys.argv[2], installed_tree_sha256=tree.hexdigest(),
              configure_args=sysconfig.get_config_var('CONFIG_ARGS'),
              openssl=ssl.OPENSSL_VERSION, sqlite=sqlite3.sqlite_version,
              modules=['ssl', 'sqlite3', 'bz2', 'lzma', 'zlib', 'ctypes', 'readline', 'dbm.gnu'])
(state / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
PYTHON
    ldd "$PREFIX/bin/python3.12" > "$STATE/linked-libraries.txt"
    find "$PREFIX/lib/python3.12/lib-dynload" -maxdepth 1 -type f -name '*.so' -print0 |
        xargs -0 -r ldd >> "$STATE/linked-libraries.txt"
    printf '%s\n' "$MPKG_GUEST_ID" > "$STATE/complete"
}

launch() {
    source_guard
    root_directory /var/lib/mpkg-fixture
    [[ ! -e $STATE && ! -L $STATE && ! -e $INSTALLED && ! -L $INSTALLED ]] || refuse previous_job
    [[ ! -e $PREFIX && ! -L $PREFIX ]] || refuse prefix_exists
    [[ $(systemctl show --property=LoadState --value "$UNIT") == not-found ]] || refuse unit_exists
    umask 077
    mkdir -m 0700 "$STATE"
    root_directory /usr
    root_directory /usr/local
    if [[ ! -e /usr/local/libexec ]]; then install -d -m 0755 /usr/local/libexec; fi
    root_directory /usr/local/libexec
    install -d -m 0755 /usr/local/libexec/mpkg-fixture
    root_directory /usr/local/libexec/mpkg-fixture
    install -m 0700 -- "$0" "$INSTALLED"
    systemd-run --quiet --unit="$UNIT" --service-type=exec \
        --property=RuntimeMaxSec=3600 --property=TimeoutStopSec=30 \
        --property=KillMode=control-group --property=Restart=no \
        --property=RemainAfterExit=yes --property=LimitCORE=0 \
        --property=StandardOutput=null --property=StandardError=null \
        --setenv="MPKG_GUEST_ID=$MPKG_GUEST_ID" \
        /usr/bin/bash "$INSTALLED" --worker
    printf 'MPKG_PYTHON_JOB_STARTED=%s\n' "$UNIT"
}

main() {
    guest_guard
    case ${1:-launch} in
        launch) [[ $# == 0 ]] || refuse arguments; launch ;;
        --worker) [[ $# == 1 ]] || refuse arguments; worker ;;
        *) refuse arguments ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
