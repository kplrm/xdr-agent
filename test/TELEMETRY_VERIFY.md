# telemetry_verify.sh — Telemetry Verification Test

Verifies all **13 xdr-agent telemetry collectors** end-to-end by:

1. Redirecting agent telemetry to a local HTTP listener (captures batches in-process).
2. Generating real OS events for each collector.
3. Restoring the original agent config and restarting the service.
4. Running deep analysis on captured events (see details below).

---

## Requirements

- Root / `sudo`
- `python3`
- `xdr-agent` service **running** before the test starts
- Agent config at `/etc/xdr-agent/config.json`

---

## How to run

```bash
sudo bash test/telemetry_verify.sh
```

To preserve logs and captured events after the test:

```bash
sudo KEEP_LOGS=1 bash test/telemetry_verify.sh
```

Logs are written to a temp dir `/tmp/xdr-telemetry-test.XXXXXX/` and printed at the end.

---

## What each collector triggers

| # | Collector | Command | Description |
|---|-----------|---------|-------------|
| 1 | Process | `/bin/echo "xdr-telemetry-test-process" > /dev/null` | Spawns a short-lived child process for the process collector to detect |
| 2 | FIM | `echo "xdr-test-fim-$(date +%s)" > /etc/xdr-test-fim-verify` then `echo "modified" >> /etc/xdr-test-fim-verify` | Creates then modifies a file in `/etc/` to trigger a create + write inotify event |
| 3 | File Access | `cat /etc/shadow > /dev/null` | Reads a sensitive file to trigger a monitored file-access event |
| 4 | Network | `echo "..." \| timeout 2 bash -c "cat > /dev/tcp/127.0.0.1/${LISTEN_PORT}"` | Opens a raw TCP connection to the local listener port |
| 5 | DNS | `host example.com` (fallback: `nslookup example.com`) | Performs a DNS resolution that the collector captures from `/proc/net/udp` or resolver hooks |
| 6 | Session | `sudo -u nobody true`; if `auth.log` is not updated, appends realistic `sudo`/`sshd` lines directly to it | Generates auth-log entries matching the patterns the session collector tails (2 s poll) |
| 7 | System Metrics | *(none)* | Passive — CPU/mem/disk metrics are collected automatically every interval |
| 8 | Library | `printf '\x7fELF\x02\x01\x01\x00' > /usr/local/lib/xdr-test-lib.so && chmod 644 ...` | Writes a minimal ELF magic-header file into a watched library directory |
| 9 | Kernel Modules | `modprobe dummy numdummies=0` (fallback: `modprobe nbd`), kept loaded 15 s, then `modprobe -r dummy` | Loads and removes a safe built-in kernel module; collector polls `/proc/modules` every 10 s |
| 10 | TTY | *(none)* | Passive — existing PTY sessions are detected automatically via `/proc` scanning |
| 11 | Scheduled Tasks | `echo "# ..." > /etc/cron.d/xdr-test-verify` | Creates a cron drop-in file in `/etc/cron.d/` for the scheduled-task collector to pick up |
| 12 | Injection | *(none)* | Passive — monitors `TracerPid` in `/proc/<pid>/status` and suspicious `/proc/<pid>/maps` entries |
| 13 | IPC | `mkfifo /tmp/xdr_test_pipe` + inline Python: `socket.AF_UNIX` bound to `/tmp/xdr_test_socket.sock`, kept open 30 s | Creates a named pipe and a Unix domain socket so the `/proc/net/unix` poller (15 s interval) can observe them |

---

## Deep analysis — what the analyzer checks

When running deep analysis on captured events, captured logs are loaded as **read-only** and runs 10 checks. Exit code is `0` only if there are zero errors and all 13 collectors are covered.

| # | Check | What it validates |
|---|-------|------------------|
| 1 | **ECS envelope compliance** | Every event must have `id`, `@timestamp`, `event.type/category/kind/severity/module`, `agent.id`, `host.hostname`, and `payload` (dict), each with the correct type. `event.kind` and `event.category` must be known ECS values. |
| 2 | **`event.severity` range** | Must be an integer `0–4`. Booleans and strings are rejected as errors. |
| 3 | **Timestamp sanity** | `@timestamp` must be valid RFC 3339 and within the last 24 hours (1 hour future drift allowed). |
| 4 | **Per-collector field validation** | Each event is matched to its `CollectorSpec` by `event.module` + `event.type`. Validates that `event.category`, `event.kind`, and `event.severity` match the spec, that all required tags are present, and that every required payload field exists, has the correct type, and is non-empty. |
| 5 | **MITRE ATT&CK consistency** | Collectors that declare a tactic/technique (File Access, Library, Kernel Modules, TTY, Scheduled Tasks, Injection, IPC) must have matching `threat.tactic.name` and `threat.technique.id`. Missing fields are errors; wrong values are warnings. |
| 6 | **Payload nesting** | Flags payload keys using literal dot-notation (e.g. `"process.pid": 42`) instead of proper nested objects — indicates a serialization bug. |
| 7 | **Duplicate envelope fields in payload** | Warns if envelope fields (`event.type`, `event.category`, etc.) are redundantly copied inside the `payload` object. |
| 8 | **Type correctness** | Validates a hardcoded cross-collector list: fields like `process.pid`, `source.port`, `file.size` must be numeric; fields like `process.name`, `source.ip`, `file.hash.sha256` must be strings. |
| 9 | **Field completeness** | Flags values that are present but meaningless: `process.pid = 0` in a process event, SHA-256 equal to the empty-file hash, empty path strings, or blank `agent.id`/`host.hostname`. |
| 10 | **Collector coverage** | Confirms at least one event was received from each of the 13 expected `event.module` values. Any missing collector is an error. |

The analyzer also writes a machine-readable `analysis_report.json` with all findings and a `"pass": true/false` summary field.

---

## Captured events vs. production

The listener captures the same JSON event objects the agent would ship to OpenSearch.
The only structural difference is that `CAPTURE_FILE` stores them as a **flat JSON array**,
whereas OpenSearch receives them via the `_bulk` API. Individual event fields are identical.

---

## Cleanup

All test artifacts, injected cron files, kernel modules, sockets, and pipes are removed on exit.
The original `/etc/xdr-agent/config.json` is restored and `xdr-agent` is restarted automatically,
whether the test succeeds, fails, or is interrupted (via `trap cleanup EXIT`).
