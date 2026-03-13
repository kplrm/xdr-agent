# XDR Agent Architecture

## Overview

The XDR Agent is a lightweight, modular endpoint security agent written in Go.
It provides comprehensive telemetry collection for Linux endpoints, with a
capability-based architecture designed for detection, prevention, and response
phases to follow.

**Current version:** 0.3.1 — Full endpoint telemetry (Phase 2 complete).

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           XDR Agent Process                                  │
│                                                                              │
│  ┌────────────┐    ┌───────────────────────────────────────────────────┐    │
│  │  CLI / CMD  │───▶│              Service Orchestrator                  │    │
│  └────────────┘    │  (enrollment, heartbeat, capability wiring)         │    │
│                    └──────────────────┬────────────────────────────────┘    │
│                                       │                                      │
│  ┌────────────────────────────────────┼────────────────────────────────┐    │
│  │                     Telemetry Capabilities (13 active)               │    │
│  │                                                                      │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │    │
│  │  │ Process  │ │   FIM    │ │ Network  │ │   DNS    │ │ Session  │ │    │
│  │  │ monitor  │ │ inotify  │ │  conns   │ │AF_PACKET │ │utmp+auth │ │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │    │
│  │  │  System  │ │ Library  │ │  Kernel  │ │   TTY    │ │Scheduled │ │    │
│  │  │ metrics  │ │ SO load  │ │ modules  │ │ sessions │ │cron/timer│ │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                           │    │
│  │  │Injection │ │  File    │ │   IPC    │   + env vars, script      │    │
│  │  │ ptrace   │ │  access  │ │ sockets  │   capture, entropy        │    │
│  │  └──────────┘ └──────────┘ └──────────┘   (integrated)            │    │
│  └───────┬────────────────────────────────────────────────────────────┘    │
│          │                                                                  │
│  ┌───────▼────────────────────────────────────────────────────────────┐    │
│  │                       Event Pipeline                                │    │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────────────────────────┐    │    │
│  │  │  Emit    │─▶│ Enrichment│─▶│  Subscribe → Shipper queue   │    │    │
│  │  └──────────┘  └───────────┘  └──────────────┬───────────────┘    │    │
│  └──────────────────────────────────────────────┼────────────────────┘    │
│                                                  │                          │
│  ┌──────────────────────────────────────────────▼────────────────────┐    │
│  │                    Control Plane Client                             │    │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────────────────────────┐    │    │
│  │  │  Enroll  │  │ Heartbeat │  │  Shipper (batch+gzip+retry)  │    │    │
│  │  └──────────┘  └───────────┘  └──────────────────────────────┘    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Future: Detection │ Prevention │ Response │ Compliance │ Cloud    │    │
│  │          (Phase 3)   (Phase 4)   (Phase 5)   (Phase 6)  (Phase 5) │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │   XDR Control Plane    │
                        │   (OpenSearch + OSD)   │
                        └───────────────────────┘
```

## Data Flow

1. **Telemetry collectors** gather OS events via Linux APIs (procfs, inotify, AF_PACKET, /proc/modules, utmp, etc.)
2. **Events** are structured into ECS-compatible format and emitted into the pipeline
3. **Event pipeline** distributes events to subscribers (currently: the shipper)
4. **Shipper** batches events, compresses with gzip, and ships to the control plane with retry
5. **Control plane** (OpenSearch + OSD xdr-manager plugin) stores and visualizes events

## Active Telemetry Collectors

All 13 collectors implement the `Capability` interface and are wired in `internal/service/run.go`.

| Collector | Package | Data Source | Key Events |
|---|---|---|---|
| **Process** | `telemetry/process/` | `/proc` polling | `process.start`, `process.end` with 30+ fields, ancestry, env vars, script content |
| **FIM** | `telemetry/file/fim.go` | inotify + BoltDB baseline | `file.created`, `file.modified`, `file.deleted` with SHA-256, entropy, header bytes |
| **File Access** | `telemetry/file/access.go` | inotify `IN_ACCESS\|IN_OPEN` | Credential harvesting detection on `/etc/shadow`, SSH keys |
| **Network** | `telemetry/network/connections.go` | `/proc/net/{tcp,udp}` polling | `network.open`, `network.close` with Community ID, PID, direction |
| **DNS** | `telemetry/network/dns.go` | AF_PACKET raw socket | DNS query/response with PID enrichment, transaction correlation |
| **Session** | `telemetry/session/` | utmp binary + auth log tail | Login/logoff, SSH, sudo, su events |
| **System Metrics** | `telemetry/system/` | `/proc/meminfo`, `/proc/stat`, `/proc/diskstats`, `/proc/net/dev` | Combined CPU, memory, disk I/O, network I/O per interval |
| **Library Loading** | `telemetry/library/` | inotify on lib dirs + `/proc/[pid]/maps` | SO file loads with SHA-256, LD_PRELOAD detection |
| **Kernel Modules** | `telemetry/kernel/modules.go` | `/proc/modules` polling | Module load/unload (rootkit detection) |
| **TTY Sessions** | `telemetry/tty/` | `/proc` PTY scanning | Terminal session start/end detection |
| **Scheduled Tasks** | `telemetry/scheduled/` | inotify on cron dirs + systemd timers | Cron/timer created, modified, deleted |
| **Injection** | `telemetry/injection/` | `/proc/[pid]/status` + `/proc/[pid]/maps` | ptrace attach, anonymous executable memory regions |
| **IPC** | `telemetry/ipc/` | `/proc/net/unix` + inotify | Unix domain sockets, named pipe (FIFO) creation |

**Integrated into Process collector** (no separate capability):
- Environment variable capture (`envvars.go`) — `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH`, etc.
- Script content capture (`script.go` + `telemetry/script/capture.go`) — first 4096 bytes of interpreter scripts

## Capability Interface

Every security module implements `capability.Capability`:

```go
type Capability interface {
    Name() string
    Init(deps Dependencies) error
    Start(ctx context.Context) error
    Stop() error
    Health() HealthStatus
}
```

## Core Infrastructure

| Package | Purpose |
|---|---|
| `cmd/xdr-agent/` | CLI entry point: `run`, `enroll`, `remove`, `version`, `completion` |
| `internal/service/` | Main orchestrator — loads config, enrolls, starts heartbeat, wires all telemetry collectors |
| `internal/config/` | JSON configuration loader with defaults |
| `internal/identity/` | Agent identity persistence (agent_id, machine_id, hostname, IPs) |
| `internal/enroll/` | Control plane enrollment and heartbeat HTTP client |
| `internal/controlplane/` | HTTP client wrapper + telemetry shipper (batch, gzip, retry) |
| `internal/events/` | Event pipeline (buffered channel, pub/sub), Event struct, Alert struct, enrichment chain |
| `internal/capability/` | Capability interface and HealthStatus enum |
| `internal/buildinfo/` | Build version injection via `-ldflags` |
| `internal/platform/common/` | File hashing utilities (SHA-256, MD5) |

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Go language | Low overhead, single binary, strong stdlib, cross-compilation |
| Capability pattern | Modular, independently testable, policy-controlled |
| ECS-compatible events | Interoperable with Elastic/OpenSearch ecosystem, standard field naming |
| Direct syscall usage | Telemetry collectors use `syscall` directly for inotify, AF_PACKET, etc. — no abstraction overhead |
| BoltDB for FIM baseline | Embedded, zero-config, crash-safe key-value store |
| Community ID v1 | Standard network flow identifier for cross-tool correlation |

## Scaffolded for Future Phases

The following packages contain architectural stubs ready for implementation:

| Domain | Packages | Target Phase |
|---|---|---|
| Detection | `internal/detection/` (malware, behavioral, memory, threatintel) | Phase 3 |
| Prevention | `internal/prevention/` (malware, ransomware, exploit, allowlist) | Phase 4 |
| Response | `internal/response/` (isolate, kill, remediate, shell, firewall, playbook) | Phase 5 |
| Cloud | `internal/cloud/` (container runtime, drift, K8s audit, metadata) | Phase 5 |
| Compliance | `internal/compliance/` (CIS, SCA, hardening, inventory, audit trail) | Phase 6 |
| Vulnerability | `internal/vulnerability/` (CVE, packages, patches, ports) | Phase 6 |
| Rules | `rules/` (behavioral YAML, malware hashes, YARA, compliance) | Phase 3+ |
| Public API | `pkg/eventschema/`, `pkg/ruleformat/` | Phase 3+ |
| Platform | `internal/platform/linux/` (eBPF, fanotify, seccomp, cgroups) | Phase 4–7 |
