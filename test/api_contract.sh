#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

run_check() {
  local label="$1"
  local status
  shift
  printf '\n==> %s\n' "$label"
  if "$@"; then
    printf 'PASS: %s\n' "$label"
  else
    status=$?
    printf 'FAIL: %s (exit %d)\n' "$label" "$status" >&2
    return "$status"
  fi
}

# Test the six outbound routes, authentication, and the documented endpoint list.
run_check 'Agent HTTP contract' "${GO:-go}" test ./internal/enroll -count=1

# Test compressed batches, retries, stable IDs, and bounded queues.
run_check 'Batch shipping' "${GO:-go}" test ./internal/controlplane -count=1

# Test upgrade artifact URLs and download errors without installing packages.
run_check 'Upgrade client' "${GO:-go}" test ./internal/upgrade -count=1

# When available, exercise Coordinator route handlers with in-memory dependencies.
if [[ -f ../xdr-coordinator/scripts/test_api.cjs ]]; then
  run_check 'Coordinator route handlers' node --test ../xdr-coordinator/scripts/test_api.cjs
else
  printf 'SKIP: Coordinator route handlers (sibling checkout missing)\n'
fi
