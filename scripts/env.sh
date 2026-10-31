#!/usr/bin/env bash
# Sourced by the project checks; keep subprocess interpreters in the venv too.
set -euo pipefail
MPKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$MPKG_ROOT"
if [ ! -x .venv/bin/python ]; then
  echo 'Run bash scripts/setup.sh to create the Python 3.12 environment.' >&2
  exit 1
fi
export PATH="$MPKG_ROOT/.venv/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
.venv/bin/python -c 'import pathlib, sys; required = tuple(map(int, pathlib.Path(".python-version").read_text().strip().split("."))); sys.exit(0 if sys.version_info[:2] == required and sys.prefix != sys.base_prefix else "A Python 3.12 project venv is required; see scripts/setup.sh.")'
