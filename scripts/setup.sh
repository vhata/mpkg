#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
# A different hook manager must be resolved explicitly, never overwritten.
hooks="$(git config --get core.hooksPath || true)"
if [ -n "$hooks" ] && [ "$hooks" != .githooks ]; then
  echo "Existing core.hooksPath=$hooks; resolve it before installing .githooks." >&2
  exit 1
fi
if [ ! -e .venv ]; then
  interpreter="${MPKG_PYTHON:-/Users/jonathan.hitchcock/.venv/3.12/bin/python}"
  if [ -z "${MPKG_PYTHON:-}" ] && [ ! -x "$interpreter" ]; then
    interpreter=python3.12
  fi
  if ! command -v "$interpreter" >/dev/null 2>&1; then
    echo 'Python 3.12 is required. Set MPKG_PYTHON to its executable and rerun.' >&2
    exit 1
  fi
  "$interpreter" -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else "Setup requires Python 3.12.")'
  "$interpreter" -m venv --without-pip .venv
fi
source "$root/scripts/env.sh"
git config --local core.hooksPath .githooks
echo 'Python 3.12 venv ready; tracked hooks enabled for this clone.'
