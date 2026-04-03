#!/usr/bin/env bash
set -Eeuo pipefail

log() {
  printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "This script must run as root. Example: sudo bash test/scripts/test_ransomware_protection_safe.sh" >&2
    exit 1
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "$1 is required" >&2; exit 1; }
}

require_root
require_cmd curl
require_cmd cp
require_cmd chmod
require_cmd systemctl

OPENSEARCH_URL="${OPENSEARCH_URL:-http://localhost:9200}"
OPENSEARCH_INDEX="${OPENSEARCH_INDEX:-.xdr-agent-security-*}"
SEARCH_POLL_SECONDS="${SEARCH_POLL_SECONDS:-5}"
SEARCH_TIMEOUT_SECONDS="${SEARCH_TIMEOUT_SECONDS:-120}"
SERVICE_NAME="${SERVICE_NAME:-xdr-agent}"
RULE_DIR="${RULE_DIR:-/etc/xdr-agent/rules/ransomware}"

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)-$$"
SCRIPT_START_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
RULE_ID="xdr-ransom-safe-${RUN_TS}"
RULE_NAME="xdr_ransom_safe_${RUN_TS}"
TRIGGER_BIN="/tmp/xdr-ransom-safe-${RUN_TS}.bin"
RULE_FILE="${RULE_DIR}/${RULE_ID}.yml"

cleanup() {
  rm -f "${TRIGGER_BIN}" "${RULE_FILE}" || true
  systemctl restart "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

log "Creating safe ransomware trigger binary"
cp /bin/sleep "${TRIGGER_BIN}"
chmod 700 "${TRIGGER_BIN}"

log "Writing temporary ransomware rule ${RULE_ID}"
cat >"${RULE_FILE}" <<EOF_RULE
rules:
  - id: ${RULE_ID}
    name: "${RULE_NAME}"
    description: "Safe ransomware module test rule for process executable path"
    severity: low
    condition:
      event_type: "process.start"
      file_path: "${TRIGGER_BIN}"
    action: alert
    enabled: true
    tags: ["ransomware", "safe-test"]
EOF_RULE
chmod 600 "${RULE_FILE}"

log "Restarting ${SERVICE_NAME}.service to load temporary rule"
systemctl restart "${SERVICE_NAME}.service"
sleep 6

log "Executing trigger binary to produce ransomware alert"
setsid "${TRIGGER_BIN}" 20 </dev/null >/dev/null 2>&1 || true
sleep 2

query_count() {
  local response
  local count
  response="$(curl -sS -X POST "${OPENSEARCH_URL%/}/${OPENSEARCH_INDEX}/_count?ignore_unavailable=true&allow_no_indices=true" \
    -H 'Content-Type: application/json' \
    -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"event.kind\":\"alert\"}},{\"term\":{\"event.module\":\"detection.ransomware\"}},{\"match_phrase\":{\"payload.rule.id\":\"${RULE_ID}\"}},{\"range\":{\"@timestamp\":{\"gte\":\"${SCRIPT_START_UTC}\"}}}]}}}")" || {
    echo -1
    return
  }
  count="$(printf '%s' "$response" | sed -n 's/.*"count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)"
  [[ -n "$count" ]] && echo "$count" || echo -1
}

log "Polling OpenSearch for ransomware detection alert"
found=0
elapsed=0
while (( elapsed <= SEARCH_TIMEOUT_SECONDS )); do
  found="$(query_count)"
  log "OpenSearch ransomware count=${found} elapsed=${elapsed}s"
  if [[ "$found" =~ ^[0-9]+$ ]] && (( found > 0 )); then
    break
  fi
  sleep "${SEARCH_POLL_SECONDS}"
  elapsed=$((elapsed + SEARCH_POLL_SECONDS))
done

printf '\n'
echo "=== Ransomware Detection Test Results ==="
echo "Run ID: ${RUN_TS}"
echo "Rule ID: ${RULE_ID}"
echo "Trigger path: ${TRIGGER_BIN}"
echo "OpenSearch index: ${OPENSEARCH_INDEX}"
echo "Matches: ${found}"

if [[ ! "$found" =~ ^[0-9]+$ ]] || (( found == 0 )); then
  log "ERROR: expected ransomware detection alert was not found"
  exit 1
fi

log "Success: ransomware detection alert observed"
