#!/usr/bin/env bash
set -Eeuo pipefail

log() {
  printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "$1 is required" >&2; exit 1; }
}

require_cmd curl
require_cmd cp
require_cmd chmod

OPENSEARCH_URL="${OPENSEARCH_URL:-http://localhost:9200}"
OPENSEARCH_INDEX="${OPENSEARCH_INDEX:-.xdr-agent-security-*}"
SEARCH_POLL_SECONDS="${SEARCH_POLL_SECONDS:-5}"
SEARCH_TIMEOUT_SECONDS="${SEARCH_TIMEOUT_SECONDS:-120}"

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)-$$"
SCRIPT_START_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
RULE_ID="capa-memory-dev-shm-exec"
TRIGGER_BIN="/dev/shm/xdr-memory-safe-${RUN_TS}.bin"

cleanup() {
  rm -f "${TRIGGER_BIN}" || true
}
trap cleanup EXIT INT TERM

log "Creating safe trigger executable under /dev/shm"
cp /bin/sleep "${TRIGGER_BIN}"
chmod 700 "${TRIGGER_BIN}"

log "Executing /dev/shm trigger binary to match rule ${RULE_ID}"
setsid "${TRIGGER_BIN}" 2 </dev/null >/dev/null 2>&1 || true
sleep 2

query_count() {
  local response
  local count
  response="$(curl -sS -X POST "${OPENSEARCH_URL%/}/${OPENSEARCH_INDEX}/_count?ignore_unavailable=true&allow_no_indices=true" \
    -H 'Content-Type: application/json' \
    -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"event.kind\":\"alert\"}},{\"term\":{\"event.module\":\"detection.memory.rules\"}},{\"match_phrase\":{\"payload.rule.id\":\"${RULE_ID}\"}},{\"range\":{\"@timestamp\":{\"gte\":\"${SCRIPT_START_UTC}\"}}}]}}}")" || {
    echo -1
    return
  }
  count="$(printf '%s' "$response" | sed -n 's/.*"count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)"
  [[ -n "$count" ]] && echo "$count" || echo -1
}

log "Polling OpenSearch for memory detection alert"
found=0
elapsed=0
while (( elapsed <= SEARCH_TIMEOUT_SECONDS )); do
  found="$(query_count)"
  log "OpenSearch memory count=${found} elapsed=${elapsed}s"
  if [[ "$found" =~ ^[0-9]+$ ]] && (( found > 0 )); then
    break
  fi
  sleep "${SEARCH_POLL_SECONDS}"
  elapsed=$((elapsed + SEARCH_POLL_SECONDS))
done

printf '\n'
echo "=== Memory Detection Test Results ==="
echo "Run ID: ${RUN_TS}"
echo "Rule ID: ${RULE_ID}"
echo "Trigger path: ${TRIGGER_BIN}"
echo "OpenSearch index: ${OPENSEARCH_INDEX}"
echo "Matches: ${found}"

if [[ ! "$found" =~ ^[0-9]+$ ]] || (( found == 0 )); then
  log "ERROR: expected memory detection alert was not found"
  exit 1
fi

log "Success: memory detection alert observed"
