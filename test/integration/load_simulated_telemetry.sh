#!/usr/bin/env bash
# =============================================================================
# load_simulated_telemetry.sh
#
# Bulk-loads simulated XDR agent telemetry events into OpenSearch so you can
# develop and test dashboards without a running xdr-agent instance.
#
# Covers all 11 telemetry event modules:
#   host · process · network · file/fim · dns · session
#   library · kernel · tty · scheduled · injection
#
# Usage:
#   ./test/integration/load_simulated_telemetry.sh [OPENSEARCH_URL]
#
# Examples:
#   ./test/integration/load_simulated_telemetry.sh
#   ./test/integration/load_simulated_telemetry.sh http://localhost:9200
#
# The script re-uses whichever date is embedded in the NDJSON fixture
# (today's date at the time of the last file regeneration).  If you want
# events under today's date simply re-generate the fixture or inline the
# date into the index name via REINDEX_DATE below.
# =============================================================================
set -euo pipefail

OPENSEARCH_URL="${1:-http://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE="${SCRIPT_DIR}/../fixtures/simulated_telemetry.ndjson"

# ── helpers ──────────────────────────────────────────────────────────────────
info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
err()   { echo "[ERROR] $*" >&2; exit 1; }

# ── pre-flight ───────────────────────────────────────────────────────────────
[[ -f "$FIXTURE" ]] || err "Fixture not found: $FIXTURE"
command -v curl &>/dev/null   || err "curl is required but not installed."
command -v python3 &>/dev/null || err "python3 is required but not installed."

info "Target:  $OPENSEARCH_URL"
info "Fixture: $FIXTURE"

# Check OpenSearch is reachable
health=$(curl -sf "${OPENSEARCH_URL}/_cluster/health" || true)
[[ -n "$health" ]] || err "OpenSearch not reachable at $OPENSEARCH_URL"
ok "OpenSearch is reachable."

# ── optional: redate events to today ─────────────────────────────────────────
# Uncomment and set REINDEX_DATE to today's date to write into today's index:
# REINDEX_DATE="$(date -u +%Y.%m.%d)"
# TMP="$(mktemp)"
# sed "s/\.xdr-agent-telemetry-[0-9.]*/.xdr-agent-telemetry-${REINDEX_DATE}/g" \
#   "$FIXTURE" > "$TMP"
# FIXTURE="$TMP"

# ── bulk load ────────────────────────────────────────────────────────────────
info "Sending bulk request ..."
RESPONSE=$(curl -sf \
  -X POST "${OPENSEARCH_URL}/_bulk" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary "@${FIXTURE}")

ERRORS=$(echo "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
errs = [i for i in d.get('items', []) if list(i.values())[0].get('error')]
print(len(errs))
" 2>/dev/null || echo "?")

TOTAL=$(echo "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(len(d.get('items', [])))
" 2>/dev/null || echo "?")

if [[ "$ERRORS" == "0" || "$ERRORS" == "?" ]]; then
  ok "Bulk load complete. Documents indexed: ${TOTAL}. Errors: ${ERRORS}."
else
  echo "[WARN]  Bulk load finished with ${ERRORS} error(s) out of ${TOTAL} items."
  echo "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for item in d.get('items', []):
  val = list(item.values())[0]
  if val.get('error'):
    print(f'  {val[\"_id\"]}: {val[\"error\"][\"type\"]} — {val[\"error\"][\"reason\"]}')
"
fi

# ── summary ──────────────────────────────────────────────────────────────────
echo ""
info "Indices written:"
curl -sf "${OPENSEARCH_URL}/_cat/indices/.xdr-agent-telemetry-*?v&h=index,docs.count" \
  | sort || true
echo ""
info "Done. Open OpenSearch Dashboards and navigate to the XDR Manager dashboards."
