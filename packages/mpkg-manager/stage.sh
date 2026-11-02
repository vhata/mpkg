#!/usr/bin/env bash
# Stage an inert package tree; this does not install or activate the helper.
set -euo pipefail
[ "$#" -eq 1 ] || { echo 'Usage: stage.sh EMPTY_PACKAGE_DIRECTORY' >&2; exit 2; }
root="$(cd "$(dirname "$0")/../.." && pwd)"
target="$1"
[ -d "$target" ] && [ ! -L "$target" ] || { echo 'Expected an existing empty package directory.' >&2; exit 2; }
target="$(cd "$target" && pwd -P)"
[ "$target" != / ] && [ -z "$(find "$target" -mindepth 1 -maxdepth 1 -print -quit)" ] \
  || { echo 'Expected an existing empty package directory.' >&2; exit 2; }
install -d -m755 "$target/usr/lib/mpkg/mpkg_manager"
for source in "$root"/mpkg_manager/*.py; do
  [ -f "$source" ] && [ ! -L "$source" ] || { echo 'Invalid module source.' >&2; exit 1; }
  install -m644 "$source" "$target/usr/lib/mpkg/mpkg_manager/$(basename "$source")"
done
install -m755 "$root/packages/mpkg-manager/host-helper.py" "$target/usr/lib/mpkg/host-helper.py"
install -Dm644 "$root/packages/mpkg-manager/mpkg.conf" "$target/usr/lib/tmpfiles.d/mpkg.conf"
