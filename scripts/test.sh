#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/env.sh"
if [ "$#" -ne 0 ]; then
  echo 'Usage: bash scripts/test.sh (runs the complete suite)' >&2
  exit 2
fi
# Hooks export Git variables that would redirect the fixture repositories.
while IFS= read -r variable; do
  unset "$variable"
done < <(git rev-parse --local-env-vars)
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TEMPLATE_DIR=
exec .venv/bin/python - <<'PY'
import sys
import unittest

suite = unittest.defaultTestLoader.discover("tests", pattern="test_*.py")
if suite.countTestCases() == 0:
    sys.exit("No tests collected; refusing an empty pass.")
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.skipped:
    sys.exit("Skipped tests are not a passing gate.")
sys.exit(0 if result.wasSuccessful() else 1)
PY
