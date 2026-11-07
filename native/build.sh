#!/usr/bin/env bash
# Build only; no installation, package operation or native bridge execution.
set -euo pipefail
[ "$#" -eq 1 ] || { echo 'Usage: native/build.sh NEW_OUTPUT_FILE' >&2; exit 2; }
root="$(cd "$(dirname "$0")/.." && pwd)"
[ ! -e "$1" ] && [ ! -L "$1" ] || { echo 'Output must not exist.' >&2; exit 2; }
/usr/bin/cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$root/native/alpm_prepare.c" -lalpm -o "$1"
chmod 755 "$1"
