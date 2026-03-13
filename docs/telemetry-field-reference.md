# Telemetry Field Reference

> **Version:** 0.3.1 — Phase 2 (Endpoint Telemetry)
>
> This document describes every field emitted by each of the 13 active
> telemetry collectors.  It is the single source of truth for field names,
> types, ECS compliance, and MITRE ATT&CK mappings.

---

## Event Envelope (all events)

Every event serialised by the shipper has these top-level JSON keys.

| JSON key | Go type | Required | Description |
|---|---|---|---|
| `id` | `string` | ✅ | Unique event identifier |
| `@timestamp` | `string` (RFC 3339) | ✅ | UTC time the event was generated |
| `event.type` | `string` | ✅ | Dot-notation event type (e.g. `process.start`) |
| `event.category` | `string` | ✅ | ECS category (e.g. `process`, `file`, `network`) |
| `event.kind` | `string` | ✅ | `event`, `alert`, `metric`, or `state` |
| `event.severity` | `int` (0–4) | ✅ | 0 = info, 1 = low, 2 = medium, 3 = high, 4 = critical |
| `event.module` | `string` | ✅ | Capability name (e.g. `telemetry.process`) |
| `agent.id` | `string` | ✅ | Enrolled agent identifier |
| `host.hostname` | `string` | ✅ | Hostname of the endpoint |
| `payload` | `object` | ✅ | Capability-specific nested data (see sections below) |
| `threat.tactic.name` | `string` | ⬚ | MITRE ATT&CK tactic (when applicable) |
| `threat.technique.id` | `string` | ⬚ | MITRE technique ID (when applicable) |
| `threat.technique.subtechnique.id` | `string` | ⬚ | MITRE sub-technique ID |
| `tags` | `[string]` | ⬚ | Filtering / routing tags |

---

## 1 — Process Collector (`telemetry.process`)

**Purpose:** Track process creation and termination across the endpoint.
Provides full ancestry trees, environment variables, script content capture,
and container-ID detection.

**Security value:** Process telemetry is the foundation for threat detection —
every execution, lateral movement, and persistence technique generates process
events.

| | Value |
|---|---|
| `event.category` | `process` |
| `event.kind` | `event` |
| `event.type` | `process.start` · `process.end` |
| `event.module` | `telemetry.process` |
| `tags` | `["process", "telemetry"]` |
| MITRE | — (raw telemetry; detection rules add MITRE in Phase 3) |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `process.pid` | `int` | ✅ | Process ID |
| `process.ppid` | `int` | ✅ | Parent process ID |
| `process.name` | `string` | ✅ | Short process name (comm) |
| `process.executable` | `string` | ✅ | Full path to executable |
| `process.command_line` | `string` | ✅ | Full command line |
| `process.args` | `[string]` | ✅ | Argument array |
| `process.working_directory` | `string` | ✅ | Current working directory |
| `process.state` | `string` | ✅ | R / S / D / Z / T |
| `process.start_time` | `int` | ✅ | Clock ticks since boot |
| `process.entity_id` | `string` | ✅ | SHA-256(host+pid+start)[:16] |
| `process.session_id` | `int` | ✅ | Session leader PID |
| `process.tty` | `int` | ✅ | Raw tty_nr |
| `process.user.id` | `int` | ✅ | UID |
| `process.user.name` | `string` | ✅ | Username (resolved; empty for baseline processes on end events) |
| `process.group.id` | `int` | ✅ | GID |
| `process.group.name` | `string` | ✅ | Group name (resolved; empty for baseline processes on end events) |
| `process.effective_user.id` | `int` | ✅ | Effective UID |
| `process.effective_group.id` | `int` | ✅ | Effective GID |
| `process.cap_eff` | `string` | ✅ | Hex capabilities bitmask |
| `process.hash.sha256` | `string` | ✅ | SHA-256 of executable binary (empty for baseline-era processes on end events — hash intentionally skipped at startup for performance; also empty for kernel threads with no executable) |
| `process.threads.count` | `int` | ✅ | Thread count |
| `process.fd_count` | `int` | ✅ | Open file-descriptor count |
| `process.memory.rss` | `int` | ✅ | Resident set size (bytes) |
| `process.memory.vms` | `int` | ✅ | Virtual memory size (bytes) |
| `process.io.read_bytes` | `int` | ✅ | Cumulative read bytes |
| `process.io.write_bytes` | `int` | ✅ | Cumulative write bytes |
| `process.cpu.pct` | `float` | ⬚ | Per-process CPU % (omitted when 0) |
| `process.parent.pid` | `int` | ✅ | Parent PID |
| `process.parent.ppid` | `int` | ✅ | Parent's parent PID |
| `process.parent.name` | `string` | ✅ | Parent name |
| `process.parent.executable` | `string` | ✅ | Parent executable |
| `process.parent.command_line` | `string` | ✅ | Parent command line |
| `process.parent.args` | `[string]` | ✅ | Parent argument array |
| `process.parent.entity_id` | `string` | ✅ | Parent entity ID |
| `process.ancestors` | `[object]` | ✅ | Up to 10 levels, each with pid/ppid/name/executable/entity_id |
| `process.group_leader.pid` | `int` | ✅ | Process group leader PID |
| `process.group_leader.name` | `string` | ✅ | Process group leader name |
| `process.group_leader.entity_id` | `string` | ✅ | Process group leader entity ID |
| `process.env` | `object` | start only | Filtered env vars: LD_PRELOAD, LD_LIBRARY_PATH, PATH, HOME, LOGNAME, SHELL, USER, SUDO_USER, SUDO_COMMAND, … |
| `process.script.path` | `string` | ⬚ | Script path (interpreters only) |
| `process.script.content` | `string` | ⬚ | First 4 KiB of script |
| `process.script.length` | `int` | ⬚ | Full script file size |
| `container.id` | `string` | ⬚ | 12-char container ID from cgroup |

---

## 2 — FIM Collector (`telemetry.file`)

**Purpose:** File Integrity Monitoring — detect creation, modification,
attribute changes, and deletion of security-critical files.

**Security value:** Detects tampering with system binaries, config files,
cron jobs, SSH keys, passwd/shadow, and tracks file hashes + entropy for
ransomware / packing indicators.

| | Value |
|---|---|
| `event.category` | `file` |
| `event.kind` | `event` |
| `event.type` | `file.created` · `file.modified` · `file.attrs_changed` · `file.deleted` |
| `event.severity` | `2` (created/attrs_changed) · `2` or `3` (modified/deleted — `3` for critical paths or entropy > 7.5) |
| `event.module` | `telemetry.file` |
| `tags` | `["fim", "file", "telemetry"]` + `"high-entropy"`, `"potentially-packed"` when entropy > 7.5 |
| MITRE | — |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `file.path` | `string` | ✅ | Absolute file path |
| `file.name` | `string` | ✅ | Base filename |
| `file.directory` | `string` | ✅ | Parent directory |
| `file.type` | `string` | ✅ | `file`, `dir`, `symlink` |
| `file.size` | `int` | ✅ | Size in bytes |
| `file.mode` | `string` | ✅ | Octal permission (e.g. `0644`) |
| `file.uid` | `int` | ✅ | Owner UID |
| `file.gid` | `int` | ✅ | Owner GID |
| `file.owner` | `string` | ✅ | Owner username |
| `file.group` | `string` | ✅ | Owner group name |
| `file.hash.sha256` | `string` | ✅ | SHA-256 hex digest (files ≤ 256 MiB) |
| `file.entropy` | `float` | ✅ | Shannon entropy [0, 8] bits/byte |
| `file.header_bytes` | `string` | ✅ | Base64-encoded first 256 bytes |
| `file.mtime` | `string` | ✅ | RFC 3339 modification time |
| `file.ctime` | `string` | ✅ | RFC 3339 change time |
| `fim.action` | `string` | ✅ | `created`, `modified`, `attributes_modified`, `deleted` |
| `fim.previous.hash.sha256` | `string` | modified only | Previous SHA-256 — **omitted if hash unchanged** |
| `fim.previous.size` | `int` | modified only | Previous size — **omitted if size unchanged** |
| `fim.previous.mode` | `string` | modified only | Previous mode — **omitted if mode unchanged** |
| `fim.previous.uid` | `int` | modified only | Previous UID — **omitted if uid unchanged** |
| `fim.previous.gid` | `int` | modified only | Previous GID — **omitted if gid unchanged** |

---

## 3 — File Access Collector (`telemetry.file.access`)

**Purpose:** Detect read access to sensitive credential and SSH files.

**Security value:** Detects credential-access attacks (T1003.008 — /etc/shadow,
T1552.004 — private keys).  High severity by default.

| | Value |
|---|---|
| `event.category` | `file` |
| `event.kind` | `event` |
| `event.type` | `file.access` |
| `event.severity` | `3` (high) |
| `event.module` | `telemetry.file.access` |
| `tags` | `["file", "access", "credential-access", "telemetry"]` |
| MITRE | T1003.008 (shadow/gshadow paths), T1552.004 (SSH paths) |

The envelope `threat.technique.id` is set per accessed path: shadow/gshadow/opasswd files
emit T1003.008; SSH key paths (`/root/.ssh`, `/etc/ssh`) emit T1552.004.

### Monitored paths (default)

`/etc/shadow`, `/etc/gshadow`, `/etc/security/opasswd`, `/root/.ssh`, `/etc/ssh`

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `file.path` | `string` | ✅ | Accessed file path |
| `file.name` | `string` | ✅ | Base filename |
| `file.directory` | `string` | ✅ | Parent directory |
| `file.event.action` | `string` | ✅ | `access` |
| `event.action` | `string` | ✅ | `file-accessed` |

---

## 4 — Network Collector (`telemetry.network`)

**Purpose:** Track TCP/UDP connections — opened, closed, and listening sockets.

**Security value:** Detects C2 beacons, lateral movement, data exfiltration,
reverse shells.  Community ID enables cross-tool correlation.

| | Value |
|---|---|
| `event.category` | `network` |
| `event.kind` | `event` |
| `event.severity` | `0` (informational) |
| `event.type` | `network.connection_opened` · `network.connection_closed` |
| `event.module` | `telemetry.network` |
| `tags` | `["network", "telemetry"]` |
| MITRE | — |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `source.ip` | `string` | ✅ | Local IP address |
| `source.port` | `int` | ✅ | Local port |
| `source.user.id` | `string` | ✅ | UID (string) |
| `source.user.name` | `string` | ✅ | Resolved username |
| `destination.ip` | `string` | ✅ | Remote IP address |
| `destination.port` | `int` | ✅ | Remote port |
| `network.transport` | `string` | ✅ | `tcp` or `udp` |
| `network.type` | `string` | ✅ | `ipv4` or `ipv6` |
| `network.direction` | `string` | ✅ | `inbound`, `outbound`, `listening`, `internal` |
| `network.community_id` | `string` | ✅ | Community ID v1 (`1:<base64>`) |
| `network.state` | `string` | ✅ | TCP state: ESTABLISHED, SYN_SENT, LISTEN, etc. |
| `network.inode` | `int` | ✅ | Socket inode number |
| `process.pid` | `int` | opened; if PID resolved | PID resolved from socket inode |
| `process.name` | `string` | opened; if PID resolved | Process name |
| `process.executable` | `string` | opened; if PID resolved | Executable path |

---

## 5 — DNS Collector (`telemetry.dns`)

**Purpose:** Capture DNS queries and answers via UDP packet sniffing (port 53).

**Security value:** Detects DNS tunneling, DGA domains, C2-over-DNS,
DNS-based data exfiltration.  Community ID links DNS to network flows.

| | Value |
|---|---|
| `event.category` | `network` |
| `event.kind` | `event` |
| `event.severity` | `0` (informational) |
| `event.type` | `dns.query` · `dns.answer` |
| `event.module` | `telemetry.dns` |
| `tags` | `["dns", "network", "telemetry"]` |
| MITRE | — |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `dns.id` | `int` | ✅ | DNS transaction ID |
| `dns.type` | `string` | ✅ | `query` or `answer` |
| `dns.question.name` | `string` | ✅ | Queried domain (FQDN) |
| `dns.question.type` | `string` | ✅ | A, AAAA, MX, CNAME, … |
| `dns.question.class` | `string` | ✅ | IN, CH, HS, ANY |
| `dns.question.registered_domain` | `string` | ✅ | Last 2 labels (e.g. `example.com`) |
| `dns.op_code` | `string` | ✅ | QUERY, IQUERY, STATUS, NOTIFY, UPDATE |
| `dns.recursion_desired` | `bool` | ✅ | RD flag |
| `dns.recursion_available` | `bool` | answers only | RA flag |
| `dns.authoritative` | `bool` | answers only | AA flag |
| `dns.header_flags` | `[string]` | ✅ | Active flags: qr, aa, tc, rd, ra |
| `dns.response_code` | `string` | answers only | NOERROR, NXDOMAIN, SERVFAIL, … |
| `dns.answers` | `[object]` | answers only | Array of {name, type, ttl, data} |
| `dns.answers_count` | `int` | answers only | Number of answer RRs |
| `dns.resolved_ips` | `[string]` | answers only | A/AAAA addresses |
| `source.ip` | `string` | ✅ | Source IP |
| `source.port` | `int` | ✅ | Source port |
| `destination.ip` | `string` | ✅ | Destination IP |
| `destination.port` | `int` | ✅ | Destination port |
| `network.transport` | `string` | ✅ | `udp` |
| `network.type` | `string` | ✅ | `ipv4` or `ipv6` |
| `network.community_id` | `string` | ✅ | Community ID v1 |
| `process.pid` | `int` | ◫ | PID (best-effort): queries via socket inode; answers via pending-query correlation |
| `process.name` | `string` | ⬚ | Process name |
| `process.executable` | `string` | ⬚ | Executable path |

---

## 6 — Session Collector (`telemetry.session`)

**Purpose:** Monitor user logins, logouts, SSH sessions, sudo, and su
activity by watching utmp/wtmp and auth logs.

**Security value:** Detects brute-force SSH, privilege escalation via
sudo/su, unauthorized logins, lateral movement via SSH.

| | Value |
|---|---|
| `event.category` | `authentication` |
| `event.kind` | `event` |
| `event.severity` | `0` (info, success events) · `2` (medium, failure events) |
| `event.type` | `session.logged-in` · `session.logged-out` · `session.sudo` · `session.ssh-accepted` · `session.ssh-failed` · `session.su` |
| `event.module` | `telemetry.session` |
| `tags` | `["session", "authentication", "telemetry"]` + `"ssh"` on SSH events, `"privilege"` on su events |
| MITRE | — |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `event.action` | `string` | ✅ | `logged-in`, `logged-out`, `sudo`, `ssh-accepted`, `ssh-failed`, `su` |
| `event.outcome` | `string` | ✅ | `success` or `failure` |
| `user.name` | `string` | ✅ | Originating username |
| `user.effective.name` | `string` | sudo/su only | Target user |
| `session.type` | `string` | ✅ | `tty`, `pts`, `ssh` |
| `source.ip` | `string` | ssh only | Remote IP |
| `source.port` | `int` | ssh only | Remote port |
| `process.pid` | `int` | ⬚ | PID from auth log |
| `process.tty.name` | `string` | utmp only | TTY name |
| `process.command_line` | `string` | sudo only | Full COMMAND= string |
| `related.user` | `[string]` | ✅ | All distinct usernames |
| `related.ip` | `[string]` | ssh only | All IPs |

---

## 7 — System Collector (`telemetry.system`)

**Purpose:** Periodic system-wide metrics — CPU, memory, swap, disk I/O,
network I/O, disk usage.

**Security value:** Baseline behaviour profiling, anomaly detection
(crypto-mining → CPU spike, exfiltration → net I/O spike), capacity monitoring.

| | Value |
|---|---|
| `event.category` | `host` |
| `event.kind` | `metric` |
| `event.severity` | `0` (informational) |
| `event.type` | `system.metrics` |
| `event.module` | `telemetry.system` |
| `tags` | `["system", "metric"]` + `"memory"`, `"cpu"`, `"diskio"`, `"netio"`, `"disk"` |
| MITRE | — |

### Payload fields

#### Memory

| Field path | Type | Description |
|---|---|---|
| `system.memory.total` | `int` | MemTotal (bytes) |
| `system.memory.free` | `int` | MemFree |
| `system.memory.cached` | `int` | Cached |
| `system.memory.buffer` | `int` | Buffers |
| `system.memory.used.bytes` | `int` | Total − Free − Buffers − Cached |
| `system.memory.used.pct` | `float` | Usage percent (0–100) |
| `system.memory.actual.free` | `int` | MemAvailable |
| `system.memory.swap.total` | `int` | SwapTotal |
| `system.memory.swap.free` | `int` | SwapFree |
| `system.memory.swap.used.bytes` | `int` | SwapTotal − SwapFree |
| `system.memory.swap.used.pct` | `float` | Swap usage percent |

#### CPU

| Field path | Type | Description |
|---|---|---|
| `system.cpu.total.pct` | `float` | Total CPU % (0–100) |
| `system.cpu.user.pct` | `float` | User-mode CPU % |
| `system.cpu.system.pct` | `float` | Kernel-mode CPU % |
| `system.cpu.idle.pct` | `float` | Idle % |
| `system.cpu.iowait.pct` | `float` | I/O wait % |
| `system.cpu.steal.pct` | `float` | Steal % |
| `system.cpu.cores` | `int` | Online core count |

#### Disk I/O

| Field path | Type | Description |
|---|---|---|
| `system.diskio.read.bytes` | `int` | Read bytes (delta) |
| `system.diskio.read.ops` | `int` | Read operations (delta) |
| `system.diskio.write.bytes` | `int` | Write bytes (delta) |
| `system.diskio.write.ops` | `int` | Write operations (delta) |

#### Network I/O

| Field path | Type | Description |
|---|---|---|
| `system.netio.in.bytes` | `int` | RX bytes (delta, all interfaces) |
| `system.netio.in.packets` | `int` | RX packets |
| `system.netio.in.errors` | `int` | RX errors |
| `system.netio.in.dropped` | `int` | RX drops |
| `system.netio.out.bytes` | `int` | TX bytes |
| `system.netio.out.packets` | `int` | TX packets |
| `system.netio.out.errors` | `int` | TX errors |
| `system.netio.out.dropped` | `int` | TX drops |
| `system.netio.interfaces.<iface>.in.*` | `int` | Per-interface RX |
| `system.netio.interfaces.<iface>.out.*` | `int` | Per-interface TX |

#### Disk usage

| Field path | Type | Description |
|---|---|---|
| `system.disk.<mount>.total` | `int` | Total bytes |
| `system.disk.<mount>.free` | `int` | Available bytes |
| `system.disk.<mount>.used.bytes` | `int` | Used bytes |
| `system.disk.<mount>.used.pct` | `float` | Used percent |

Mount keys: `root` (/), `home` (/home), `var` (/var), `boot` (/boot).

### Per-process CPU sub-event

Emitted once per collection interval for each process with CPU ≥ 0.01% (top-N by usage).

| | Value |
|---|---|
| `event.category` | `process` |
| `event.kind` | `metric` |
| `event.severity` | `0` (informational) |
| `event.type` | `process.cpu` |
| `event.module` | `telemetry.system.cpu` |
| `tags` | `["cpu", "process", "metric"]` |

| Field path | Type | Required | Description |
|---|---|---|---|
| `process.pid` | `int` | ✅ | PID |
| `process.name` | `string` | ✅ | Process name |
| `process.executable` | `string` | ✅ | Executable path |
| `process.command_line` | `string` | ✅ | Command line |
| `process.cpu.pct` | `float` | ✅ | CPU usage percent |

---

## 8 — Library Collector (`telemetry.library`)

**Purpose:** Detect shared library (.so) loading — new libraries appearing
on disk, and libraries loaded into running processes.

**Security value:** Detects LD_PRELOAD hijacking (T1574.006), memfd-based
fileless execution (T1055.001), malicious SOloading.

| | Value |
|---|---|
| `event.category` | `library` |
| `event.kind` | `event` |
| `event.severity` | `2` (medium, `library.loaded`) · `3` (high, `library.loaded_into_process` or suspicious path) |
| `event.type` | `library.loaded` · `library.loaded_into_process` |
| `event.module` | `telemetry.library` |
| `tags` | `["library", "telemetry", "so-loading"]` |
| `threat.tactic.name` | `Defense Evasion` |
| `threat.technique.id` | `T1574.006` (disk) · `T1055.001` (memfd) |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `dll.name` | `string` | ✅ | Library base filename |
| `dll.path` | `string` | ✅ | Absolute library path |
| `dll.hash.sha256` | `string` | ✅ | SHA-256 hex digest (≤ 256 MiB) |
| `dll.size` | `int` | ✅ | File size in bytes |
| `process.pid` | `int` | loaded_into_process only | Owning PID |
| `process.name` | `string` | loaded_into_process only | Process name |
| `description` | `string` | ✅ | Human-readable description |

---

## 9 — Kernel Module Collector (`telemetry.kernel.modules`)

**Purpose:** Detect kernel module load and unload events.

**Security value:** Detects rootkit installation (T1547.006), LKM-based
persistence, and unauthorized driver loading.

| | Value |
|---|---|
| `event.category` | `driver` |
| `event.kind` | `event` |
| `event.type` | `kernel.module_load` · `kernel.module_unload` |
| `event.severity` | `3` (load) · `2` (unload) |
| `event.module` | `telemetry.kernel.modules` |
| `tags` | `["kernel", "module", "telemetry"]` |
| `threat.tactic.name` | `Persistence` |
| `threat.technique.id` | `T1547.006` |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `driver.name` | `string` | ✅ | Module name |
| `xdr.kernel_module.name` | `string` | ✅ | Module name (duplicate — see notes) |
| `xdr.kernel_module.size` | `int` | ✅ | Module size in bytes |
| `xdr.kernel_module.ref_count` | `int` | ✅ | Reference count |
| `xdr.kernel_module.deps` | `[string]` | ✅ | Dependent module names |
| `xdr.kernel_module.state` | `string` | ✅ | `Live`, `Loading`, `Unloading` |
| `xdr.kernel_module.address` | `string` | ✅ | Kernel load address (hex) |

> **Note:** `driver.name` and `xdr.kernel_module.name` carry the same value.
> `driver.name` follows ECS; the `xdr.*` namespace provides extended detail.
> This is intentional — both are kept for ECS compatibility and XDR-specific queries.

---

## 10 — TTY Collector (`telemetry.tty`)

**Purpose:** Detect terminal session start / end by monitoring /proc for
processes with active TTY allocations.

**Security value:** Detects interactive shell sessions (T1059.004),
post-exploitation interactive access, and helps correlate command execution
to real human sessions.

| | Value |
|---|---|
| `event.category` | `process` |
| `event.kind` | `event` |
| `event.severity` | `0` (informational) |
| `event.type` | `tty.session_start` · `tty.session_end` |
| `event.module` | `telemetry.tty` |
| `tags` | `["tty", "terminal", "session", "telemetry"]` |
| `threat.tactic.name` | `Execution` |
| `threat.technique.id` | `T1059.004` |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `process.pid` | `int` | ✅ | PID |
| `process.ppid` | `int` | ✅ | Parent PID |
| `process.name` | `string` | ✅ | Process name |
| `process.executable` | `string` | ✅ | Executable path |
| `process.command_line` | `string` | ✅ | Command line |
| `process.session_id` | `int` | ✅ | Kernel session ID |
| `process.user.id` | `int` | ✅ | UID |
| `process.group.id` | `int` | ✅ | GID |
| `process.tty.nr` | `int` | ✅ | Raw tty_nr from /proc/[pid]/stat |
| `process.tty.name` | `string` | ✅ | Resolved name (`pts/N` or `ttyN`) |

---

## 11 — Scheduled Task Collector (`telemetry.scheduled`)

**Purpose:** Detect creation, modification, and deletion of cron jobs and
systemd timers.

**Security value:** Detects persistence via cron (T1053.003) and systemd
timers (T1053.006) — one of the most common Linux persistence techniques.

| | Value |
|---|---|
| `event.category` | `configuration` |
| `event.kind` | `event` |
| `event.type` | `scheduled.task_created` · `scheduled.task_modified` · `scheduled.task_deleted` |
| `event.severity` | `3` (high) |
| `event.module` | `telemetry.scheduled` |
| `tags` | `["scheduled", "cron", "persistence", "telemetry"]` |
| `threat.tactic.name` | `Persistence` |
| `threat.technique.id` | `T1053.003` (cron) · `T1053.006` (systemd-timer) |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `file.path` | `string` | ✅ | Task file path |
| `file.name` | `string` | ✅ | Base filename |
| `xdr.scheduled_task.path` | `string` | ✅ | Task file path |
| `xdr.scheduled_task.type` | `string` | ✅ | `cron`, `crontab`, `user-crontab`, `systemd-timer`, `systemd-unit` |
| `xdr.scheduled_task.entries` | `[object]\|null` | ✅ | Parsed entries; `null` when file contains only comments or variable assignments |
| `xdr.scheduled_task.raw_content` | `string` | ✅ | Full file content (max 4096 chars) |
| `xdr.scheduled_task.previous_content` | `string` | ✅ | Previous content (max 4096); empty string on created/deleted events |

**Cron entry fields:** `line` (int), `raw` (string), `source` (string), `schedule` (string), `command` (string), `user` (string — /etc/crontab format).

**Timer entry fields:** `source` (string), `name` (string), plus lowercased keys: `oncalendar`, `onunitactivesec`, `onbootsec`, `unit`, `description`, `persistent`.

---

## 12 — Injection Collector (`telemetry.injection`)

**Purpose:** Detect process injection indicators — ptrace attachment and
anonymous executable memory regions.

**Security value:** Detects ptrace-based injection (T1055), reflective code
loading / fileless execution (T1620).  Emitted as alerts (`event.kind: alert`).

| | Value |
|---|---|
| `event.category` | `intrusion_detection` |
| `event.kind` | `alert` |
| `event.type` | `process_injection.ptrace_attach` · `process_injection.anon_exec_region` |
| `event.severity` | `3` (high) |
| `event.module` | `telemetry.injection` |
| `tags` | `["injection", "ptrace", "process", "telemetry"]` |
| `threat.tactic.name` | `Defense Evasion` |
| `threat.technique.id` | `T1055` (ptrace) · `T1620` (anon exec) |

### Payload fields

| Field path | Type | Required | Description |
|---|---|---|---|
| `process.pid` | `int` | ✅ | Target PID |
| `process.name` | `string` | ✅ | Target process name |
| `process.executable` | `string` | ✅ | Target executable path |
| `xdr.injection.indicator` | `string` | ✅ | `ptrace` or `anon_exec` |
| `xdr.injection.detail` | `string` | ✅ | Tracer PID or address+label |
| `xdr.injection.target.pid` | `int` | ✅ | Target PID |
| `xdr.injection.target.name` | `string` | ✅ | Target name |
| `xdr.injection.target.exe` | `string` | ✅ | Target executable |
| `xdr.injection.tracer.pid` | `int` | ptrace only | Tracer PID |
| `xdr.injection.tracer.name` | `string` | ptrace only | Tracer name |
| `xdr.injection.tracer.exe` | `string` | ptrace only | Tracer executable |
| `description` | `string` | ✅ | Human-readable description |

---

## 13 — IPC Collector (`telemetry.ipc`)

**Purpose:** Monitor Inter-Process Communication — Unix domain socket
creation (/proc/net/unix polling) and named pipe (FIFO) creation (inotify).

**Security value:** Detects covert IPC channels (T1559) used for C2,
data staging, and inter-process coordination by malware.

### 13a — Unix Domain Socket

| | Value |
|---|---|
| `event.category` | `network` |
| `event.kind` | `event` |
| `event.type` | `ipc.unix_socket.created` |
| `event.severity` | `0` (info) |
| `event.module` | `telemetry.ipc` |
| `tags` | `["ipc", "unix-socket", "network", "telemetry"]` |
| MITRE | T1559 |

| Field path | Type | Required | Description |
|---|---|---|---|
| `network.unix_socket.path` | `string` | ✅ | Socket file path |
| `network.type` | `string` | ✅ | `unix` |
| `network.transport` | `string` | ✅ | `unix` |
| `event.action` | `string` | ✅ | `unix_socket.created` |

### 13b — Named Pipe (FIFO)

| | Value |
|---|---|
| `event.category` | `file` |
| `event.kind` | `event` |
| `event.type` | `ipc.pipe.created` |
| `event.severity` | `2` (medium) |
| `event.module` | `telemetry.ipc` |
| `tags` | `["ipc", "named-pipe", "file", "telemetry"]` |
| MITRE | T1559 |

| Field path | Type | Required | Description |
|---|---|---|---|
| `process.io.pipe_name` | `string` | ✅ | Pipe file path |
| `file.path` | `string` | ✅ | Pipe file path |
| `file.name` | `string` | ✅ | Base filename |
| `file.directory` | `string` | ✅ | Parent directory |
| `file.type` | `string` | ✅ | `pipe` |
| `event.action` | `string` | ✅ | `named_pipe.created` |

---

## Known Issues and Notes

1. **Kernel module name duplication:** `driver.name` and
   `xdr.kernel_module.name` carry the same value.  This is intentional — ECS
   uses `driver.name`, while the `xdr.*` namespace groups extended module
   metadata.

2. **Scheduled task `file.path` duplication:** Both `file.path` and
   `xdr.scheduled_task.path` hold the same value.  `file.path` provides ECS
   compatibility; `xdr.scheduled_task.path` groups task-specific data.

3. **`source.user.id` type in network collector:** Emitted as a `string`
   (not `int`).  This follows ECS `source.user.id` spec (ECS defines user.id
   as keyword/string).

---

*Generated: 2026-03-03 — xdr-agent v0.3.1 — Audited & corrected 2026-03-03*
