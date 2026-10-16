# Agent architecture

The Linux agent collects process, file, connection, and DNS events and scans files with release-bundled YARA Forge Core rules. [Telemetry](telemetry.md) defines monitored sources and emitted fields; [HTTP contract](api-endpoints.md) defines external requests. Coordinator policies group agents; protection configuration stays local.

## Runtime and configuration

[`internal/service/run.go`](../internal/service/run.go) loads config and persistent identity, starts event dispatch, initializes YARA, starts five collectors, then enrolls or retries enrollment. Collection and protection continue during Coordinator outages; periodic shipping starts after enrollment. Scanner initialization failure stops startup; individual collector or execution-blocking failures report separate health.

The installed service reads `/etc/xdr-agent/config.json`. Enrollment copies the supplied config there; reinstalls preserve it. Restart after edits. [`config.default.json`](../config/config.default.json) lists packaged settings.

| Setting | Default / effect |
| --- | --- |
| `telemetry_interval_seconds` | Process/network polling: minimum and default 5 s |
| `heartbeat_interval_seconds`, `enroll_interval_seconds` | Health and enrollment retries: 30 s each |
| `command_poll_interval_seconds` | Upgrade polling: 5 s |
| `telemetry_ship_interval_seconds`, `security_ship_interval_seconds`, `logging.ship.ship_interval_seconds` | Separate batches: 30 s each |
| `request_timeout_seconds` | HTTP timeout and shared final-flush deadline: 10 s |
| `max_cpu_cores` | 1 logical CPU; 0 keeps inherited affinity. YARA inherits the limit |
| `detection_prevention.mode` | `detect`; `prevent` enables blocking and verified termination |
| `execution_watch_paths` | Execution watches only; file-integrity/access paths are fixed in code |
| `logging.level`, `logging.ship.enabled` | `INFO`, `true`; shipped diagnostics can be filtered or disabled |
| `state_path` | `/var/lib/xdr-agent/state.json`; persistent identity and enrollment state |

`fim_baseline.db` beside `state_path` persists file metadata, hashes, entropy, and header bytes. It is not an event queue. The packaged [systemd unit](../systemd/xdr-agent.service) runs as root, limits CPU to 75% of one CPU, lowers CPU priority, and sets memory pressure/hard limits of 350M/500M.

## Protection

The build filters explicitly Linux-targeted Core rules and dependencies and embeds compressed source/catalog. Rules change with agent releases. Startup runs native `yarac`; scanning runs native `yara`. There is no remote rule feed. Heartbeats report bundle source, version, digest, rule count, mode, collector health, YARA health, and execution-blocking health.

Process-start and file-change events trigger asynchronous scans; process-end and file-access events do not. Existing process/file baselines do not trigger a startup sweep. One worker consumes up to 256 queued scan events; overflow skips scans and degrades YARA health. A regular file scan has a 6 s context deadline. Successful scans can restore YARA health. [Telemetry](telemetry.md#protection-and-runtime-logs) lists scan inputs and result fields.

In `prevent` mode, fanotify checks executable opens under `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/tmp`, `/var/tmp`, and `/home` by default. Existing subdirectories are included only when the complete configured tree fits within 2,048 directory watches. Oversized trees install no blocking watches. Watches refresh every 30 s; new directories have a coverage gap. Two workers handle decisions with a 500 ms deadline including queue time. Overload, timeout, or response failure allows execution, disables blocking until restart, and reports degraded health. Kernel/filesystem support and `CAP_SYS_ADMIN` are required. Interpreted scripts and execution outside watched paths are not universally intercepted.

After a process YARA match, prevention uses a pidfd and rechecks start ticks plus executable device, inode, size, and modification time before `SIGKILL`. Failed identity checks skip termination. Detection mode produces alerts and `alert_only` outcomes. Execution-denial requests and confirmed outcomes are separate events.

## Event delivery and loss

Collectors/protection → 4,096-event memory pipeline → subscribers → telemetry/security shippers. Runtime logs use a separate 1,024-event writer queue. Alerts and `detection.*`/`prevention.*` modules go to security; collector events go to telemetry; diagnostics go to logs.

Each shipper holds up to 5,000 queued events and sends up to 500 per request on its interval, using gzip. Failures retain the unsent batch ahead of newer events. Transport/server errors and HTTP 429 receive up to three retries after 2/4/8 s within a flush; other client errors stop that attempt but remain queued for the next flush. OpenSearch item errors also retain the batch. Full queues drop new events; pipeline/shipper drops are logged, log-writer drops are silent. All event buffering is in memory: crashes, prolonged outages, and overload can lose data.

Shutdown stops collectors and protection, drains accepted pipeline/log events, stops periodic shippers, then attempts a final shipment within one shared timeout. It does not persist unsent events. Destination, authentication, and duplicate handling are defined once in the [HTTP contract](api-endpoints.md).
