#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/env.sh"
exec .venv/bin/python scripts/check_syntax.py "$@"
