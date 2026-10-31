#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
for check in lint test; do
  echo "==> $check"
  bash "scripts/$check.sh"
done
bash docket/scripts/check-queues.sh --strict
bash docket/scripts/check-links.sh
