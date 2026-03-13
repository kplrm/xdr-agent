#!/usr/bin/env bash
# =============================================================================
# telemetry_verify.sh — Verify all 13 xdr-agent telemetry collectors
#
# Starts a local HTTP listener, reconfigures the agent to ship events there,
# generates real OS events that each collector should detect, then runs a
# deep analysis of every captured event:
#
#   1. ECS envelope compliance
#   2. Per-collector field validation (required + optional fields, types)
#   3. MITRE ATT&CK consistency
#   4. Timestamp sanity
#   5. Payload nesting correctness
#   6. Field completeness (empty/zero required fields)
#   7. event.severity range
#   8. Type correctness (numbers vs strings, arrays vs scalars)
#   9. Duplicate / misnamed / misparsed fields
#  10. All 13 collector coverage
#
# Requirements: sudo, python3, bash, curl
# All generated files are cleaned up on exit.
#
# Usage:
#   sudo bash test/telemetry_verify.sh
# =============================================================================
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
LISTEN_PORT=19876
LISTEN_ADDR="127.0.0.1"
CONFIG_PATH="/etc/xdr-agent/config.json"
CAPTURE_DIR="$(mktemp -d /tmp/xdr-telemetry-test.XXXXXX)"
CAPTURE_FILE="${CAPTURE_DIR}/captured_events.json"
LISTENER_PID_FILE="${CAPTURE_DIR}/listener.pid"
LISTENER_LOG="${CAPTURE_DIR}/listener.log"
TEST_DIR="${CAPTURE_DIR}/test_artifacts"
WAIT_SECONDS=45                  # time to let the agent collect + ship events
ORIGINAL_CONFIG="${CAPTURE_DIR}/config.json.bak"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[PASS]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

# ── Cleanup handler ──────────────────────────────────────────────────────────
cleanup() {
    info "Cleaning up..."

    # Kill listener
    if [[ -f "$LISTENER_PID_FILE" ]]; then
        kill "$(cat "$LISTENER_PID_FILE")" 2>/dev/null || true
        rm -f "$LISTENER_PID_FILE"
    fi

    # Restore original config
    if [[ -f "$ORIGINAL_CONFIG" ]]; then
        cp "$ORIGINAL_CONFIG" "$CONFIG_PATH"
        info "Restored original config"
    fi

    # Restart agent with original config
    systemctl restart xdr-agent 2>/dev/null || true

    # Remove test artifacts
    rm -rf "$TEST_DIR" 2>/dev/null || true

    # Remove test files
    rm -f /etc/xdr-test-fim-verify 2>/dev/null || true
    rm -f /usr/local/lib/xdr-test-lib.so 2>/dev/null || true
    rm -f /etc/cron.d/xdr-test-verify 2>/dev/null || true
    rm -f /tmp/xdr_test_pipe 2>/dev/null || true
    rm -f /tmp/xdr_test_socket.sock 2>/dev/null || true

    # Remove capture dir (keep if --keep-logs)
    if [[ "${KEEP_LOGS:-0}" != "1" ]]; then
        rm -rf "$CAPTURE_DIR"
    else
        info "Logs kept at: $CAPTURE_DIR"
    fi

    info "Cleanup complete"
}
trap cleanup EXIT

# ── Pre-flight checks ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "This test must be run as root (sudo)." >&2
    exit 1
fi

command -v python3 &>/dev/null || { echo "python3 is required" >&2; exit 1; }

if ! systemctl is-active --quiet xdr-agent; then
    echo "xdr-agent service is not running. Start it first." >&2
    exit 1
fi

[[ -f "$CONFIG_PATH" ]] || { echo "Config not found: $CONFIG_PATH" >&2; exit 1; }

mkdir -p "$TEST_DIR"

info "Capture dir: $CAPTURE_DIR"
info "Test artifacts dir: $TEST_DIR"

# ── Step 1: Start HTTP listener ─────────────────────────────────────────────
info "Starting telemetry capture listener on ${LISTEN_ADDR}:${LISTEN_PORT}..."

cat > "${CAPTURE_DIR}/listener.py" << 'PYEOF'
#!/usr/bin/env python3
"""Minimal HTTP server that captures gzip-compressed telemetry batches."""
import gzip
import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

CAPTURE_FILE = sys.argv[1]
events_collected = []

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length)

        # Decompress if gzip
        encoding = self.headers.get("Content-Encoding", "")
        if "gzip" in encoding:
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass

        # Parse JSON
        try:
            payload = json.loads(raw)
            batch_events = payload.get("events", [])
            events_collected.extend(batch_events)

            # Write accumulated events to file
            with open(CAPTURE_FILE, "w") as f:
                json.dump(events_collected, f, indent=2)

        except Exception as e:
            print(f"Parse error: {e}", file=sys.stderr)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_GET(self):
        # Respond OK for heartbeat/enrollment health checks
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        # Suppress default request logging
        pass

port = int(sys.argv[2])
server = HTTPServer(("127.0.0.1", port), Handler)
print(f"Listening on 127.0.0.1:{port}", flush=True)
server.serve_forever()
PYEOF

python3 "${CAPTURE_DIR}/listener.py" "$CAPTURE_FILE" "$LISTEN_PORT" \
    > "$LISTENER_LOG" 2>&1 &
LISTENER_PID=$!
echo "$LISTENER_PID" > "$LISTENER_PID_FILE"
sleep 1

if ! kill -0 "$LISTENER_PID" 2>/dev/null; then
    fail "Listener failed to start. Check $LISTENER_LOG"
    exit 1
fi
ok "Listener started (PID $LISTENER_PID)"

# ── Step 2: Reconfigure agent to ship to our listener ───────────────────────
info "Backing up and reconfiguring agent..."
cp "$CONFIG_PATH" "$ORIGINAL_CONFIG"

# Patch config: point telemetry_url to our listener, fast intervals
python3 -c "
import json, sys
with open('$CONFIG_PATH') as f:
    cfg = json.load(f)
cfg['telemetry_url'] = 'http://${LISTEN_ADDR}:${LISTEN_PORT}'
cfg['telemetry_interval_seconds'] = 1
cfg['telemetry_ship_interval_seconds'] = 1
with open('$CONFIG_PATH', 'w') as f:
    json.dump(cfg, f, indent=2)
"
ok "Config patched (telemetry → http://${LISTEN_ADDR}:${LISTEN_PORT})"

# ── Step 3: Restart agent with new config ────────────────────────────────────
info "Restarting xdr-agent..."
systemctl restart xdr-agent
sleep 3

if ! systemctl is-active --quiet xdr-agent; then
    fail "xdr-agent failed to restart"
    exit 1
fi
ok "xdr-agent restarted"

# ── Step 4: Generate events for all 13 collectors ───────────────────────────
info "Generating telemetry trigger events..."
echo ""

# 4.1  Process — spawn a short-lived process
info "  [1/13] Process: spawning test process..."
/bin/echo "xdr-telemetry-test-process" > /dev/null

# 4.2  FIM — create and modify a file in a monitored path
info "  [2/13] FIM: creating file in /etc/..."
echo "xdr-test-fim-$(date +%s)" > /etc/xdr-test-fim-verify
sleep 1
echo "modified" >> /etc/xdr-test-fim-verify
# Will be cleaned up by removing test_artifacts and this file
TEST_FIM_FILE="/etc/xdr-test-fim-verify"

# 4.3  File Access — read a sensitive file
info "  [3/13] File Access: reading /etc/shadow..."
cat /etc/shadow > /dev/null 2>&1 || true

# 4.4  Network — make a TCP connection
info "  [4/13] Network: making TCP connection..."
(echo "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n" | timeout 2 bash -c "cat > /dev/tcp/127.0.0.1/${LISTEN_PORT}" 2>/dev/null) || true

# 4.5  DNS — perform a DNS lookup
info "  [5/13] DNS: resolving example.com..."
host example.com > /dev/null 2>&1 || nslookup example.com > /dev/null 2>&1 || true

# 4.6  Session — generate auth log entries the session collector can parse
#       The collector tails auth.log for sudo/ssh/su patterns (2s poll).
#       If syslog is not running, we inject entries directly.
info "  [6/13] Session: generating session events..."
AUTH_LOG=""
if [[ -f /var/log/auth.log ]]; then
    AUTH_LOG=/var/log/auth.log
elif [[ -f /var/log/secure ]]; then
    AUTH_LOG=/var/log/secure
fi

if [[ -n "$AUTH_LOG" ]]; then
    # Try normal sudo first
    sudo -u nobody true 2>/dev/null || true
    # If syslog isn't writing to auth.log, inject a realistic entry
    AUTH_MTIME_BEFORE=$(stat -c %Y "$AUTH_LOG")
    sleep 3
    AUTH_MTIME_AFTER=$(stat -c %Y "$AUTH_LOG")
    if [[ "$AUTH_MTIME_BEFORE" == "$AUTH_MTIME_AFTER" ]]; then
        warn "  auth.log not being updated (syslog not running?) — injecting test entries"
        TS=$(date '+%b %e %H:%M:%S')
        HN=$(hostname)
        echo "$TS $HN sudo:    root : TTY=pts/99 ; PWD=/tmp ; USER=nobody ; COMMAND=/usr/bin/true" >> "$AUTH_LOG"
        echo "$TS $HN sshd[99999]: Failed password for invalid user xdr_test from 127.0.0.1 port 55555 ssh2" >> "$AUTH_LOG"
    fi
else
    warn "  No auth.log or secure log found — session auth events cannot be tested"
fi

# 4.7  System Metrics — always collected, just wait
info "  [7/13] System Metrics: (collected every interval automatically)"

# 4.8  Library — create a .so file in a watched directory
info "  [8/13] Library: creating test .so in /usr/local/lib/..."
printf '\x7fELF\x02\x01\x01\x00' > /usr/local/lib/xdr-test-lib.so
chmod 644 /usr/local/lib/xdr-test-lib.so
TEST_SO_FILE="/usr/local/lib/xdr-test-lib.so"

# 4.9  Kernel Modules — load and unload a safe test module
#       The kernel module collector polls /proc/modules every 10s.
#       Keep the module loaded for 15s to ensure detection.
info "  [9/13] Kernel Modules: loading/unloading dummy module..."
if ! lsmod | grep -q "^dummy "; then
    modprobe dummy numdummies=0 2>/dev/null && {
        ok "    dummy module loaded — keeping alive for 15s"
        sleep 15
        modprobe -r dummy 2>/dev/null || true
    } || {
        # Try nbd as fallback
        if ! lsmod | grep -q "^nbd "; then
            modprobe nbd 2>/dev/null && {
                ok "    nbd module loaded — keeping alive for 15s"
                sleep 15
                modprobe -r nbd 2>/dev/null || true
            } || warn "  Could not load any test kernel module"
        fi
    }
else
    warn "  dummy module already loaded — skipping"
fi

# 4.10 TTY — current TTY sessions are detected via /proc scanning
info "  [10/13] TTY: (existing PTY sessions detected automatically)"

# 4.11 Scheduled Tasks — create a temporary cron entry
info "  [11/13] Scheduled Tasks: creating test cron file..."
echo "# xdr-test: telemetry verification" > /etc/cron.d/xdr-test-verify
echo "# 0 0 * * * root echo test" >> /etc/cron.d/xdr-test-verify

# 4.12 Injection — ptrace detection is passive (TracerPid monitoring)
info "  [12/13] Injection: (passive ptrace/maps monitoring)"

# 4.13 IPC — create a named pipe AND a unix domain socket (keep alive for polls)
info "  [13/13] IPC: creating named pipe and unix socket in /tmp/..."
mkfifo /tmp/xdr_test_pipe 2>/dev/null || true
# Create a unix domain socket listener and keep it alive through the wait period
# so the /proc/net/unix poller (15s interval) can see it
python3 -c "
import socket, os, time, signal
sock_path = '/tmp/xdr_test_socket.sock'
if os.path.exists(sock_path):
    os.unlink(sock_path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(1)
# Keep alive for 30 seconds (longer than the poll interval)
time.sleep(30)
s.close()
try:
    os.unlink(sock_path)
except OSError:
    pass
" &
IPC_SOCKET_PID=$!

echo ""
info "All trigger events generated. Waiting ${WAIT_SECONDS}s for collection + shipping..."
# Wait for unix socket python helper to finish
wait "$IPC_SOCKET_PID" 2>/dev/null || true
sleep "$WAIT_SECONDS"

# ── Step 5: Stop listener ────────────────────────────────────────────────────
# Stop the listener BEFORE reading the file to avoid race conditions
# (the listener rewrites the file on every batch)
if [[ -f "$LISTENER_PID_FILE" ]]; then
    kill "$(cat "$LISTENER_PID_FILE")" 2>/dev/null || true
    sleep 1          # let final write complete
fi

# ── Step 6: Restore original config and restart agent ────────────────────────
info "Restoring original agent configuration..."
if [[ -f "$ORIGINAL_CONFIG" ]]; then
    cp "$ORIGINAL_CONFIG" "$CONFIG_PATH"
    rm -f "$ORIGINAL_CONFIG"   # prevent double-restore in cleanup
    ok "Config restored: $CONFIG_PATH"
else
    warn "Original config backup not found — skipping restore"
fi
info "Restarting xdr-agent with original config..."
systemctl restart xdr-agent 2>/dev/null && ok "xdr-agent restarted" || warn "xdr-agent restart failed"
echo ""

# ── Step 7: Analyze captured events ──────────────────────────────────────────
info "Analyzing captured events..."
echo ""

if [[ ! -f "$CAPTURE_FILE" ]]; then
    fail "No events captured! Check $LISTENER_LOG"
    echo ""
    echo "=== Listener log ==="
    cat "$LISTENER_LOG"
    exit 1
fi

EVENT_COUNT=$(python3 -c "
import json
with open('$CAPTURE_FILE') as f:
    events = json.load(f)
print(len(events))
")
info "Total events captured: $EVENT_COUNT"
echo ""

if [[ "$EVENT_COUNT" -eq 0 ]]; then
    fail "Zero events captured. Agent may not be shipping."
    exit 1
fi

# Run deep analysis
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="${SCRIPT_DIR}/telemetry_analyze.py"

if [[ ! -f "$ANALYZER" ]]; then
    fail "Analyzer script not found: $ANALYZER"
    exit 1
fi

JSON_REPORT="${CAPTURE_DIR}/analysis_report.json"

python3 "$ANALYZER" "$CAPTURE_FILE" --json "$JSON_REPORT"
ANALYSIS_EXIT=$?

echo ""
info "Captured events: $CAPTURE_FILE"
info "Analysis report: $JSON_REPORT"
info "Set KEEP_LOGS=1 to preserve all output after the test."
exit $ANALYSIS_EXIT
