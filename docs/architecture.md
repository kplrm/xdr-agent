# XDR Agent Architecture

## Overview

The XDR Agent is a lightweight, modular endpoint security agent written in Go.
It provides comprehensive threat detection, prevention, and response capabilities
for Linux endpoints.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           XDR Agent Process                                  │
│                                                                              │
│  ┌────────────┐    ┌───────────────────────────────────────────────────┐    │
│  │  CLI / CMD  │───▶│              Agent Orchestrator                   │    │
│  └────────────┘    │  (lifecycle, capability registry, health)          │    │
│                    └──────────────────┬────────────────────────────────┘    │
│                                       │                                      │
│  ┌────────────────────────────────────┼────────────────────────────────┐    │
│  │                        Capability Layer                              │    │
│  │                                                                      │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │    │
│  │  │Telemetry │ │Detection │ │Prevention│ │ Response │ │Compliance│ │    │
│  │  │          │ │          │ │          │ │          │ │          │ │    │
│  │  │• Process │ │• Malware │ │• Blocker │ │• Isolate │ │• CIS     │ │    │
│  │  │• File    │ │• Behavior│ │• R-ware  │ │• Kill    │ │• SCA     │ │    │
│  │  │• Network │ │• Memory  │ │• Exploit │ │• Shell   │ │• Harden  │ │    │
│  │  │• Session │ │• ThreatI │ │• Allow   │ │• Playbook│ │• Vuln    │ │    │
│  │  │• Kernel  │ │          │ │          │ │          │ │          │ │    │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │    │
│  └───────┼────────────┼────────────┼────────────┼────────────┼────────┘    │
│          │            │            │            │            │              │
│  ┌───────▼────────────▼────────────▼────────────▼────────────▼────────┐    │
│  │                       Event Pipeline                                │    │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────────────┐  │    │
│  │  │  Emit    │─▶│ Enrichment│─▶│  Filter  │─▶│  Buffer / Ship   │  │    │
│  │  └──────────┘  └───────────┘  └──────────┘  └────────┬─────────┘  │    │
│  └───────────────────────────────────────────────────────┼────────────┘    │
│                                                           │                  │
│  ┌───────────────────────────────────────────────────────▼────────────┐    │
│  │                    Control Plane Client                             │    │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────────────┐  │    │
│  │  │  Enroll  │  │ Heartbeat │  │  Policy  │  │  Event Shipper   │  │    │
│  │  └──────────┘  └───────────┘  └──────────┘  └──────────────────┘  │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Platform Abstraction                             │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │    │
│  │  │  procfs  │ │ fanotify │ │  netlink │ │   eBPF   │ │ seccomp │ │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └─────────┘ │    │
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

1. **Platform layer** collects raw OS events (process exec, file write, network connect)
2. **Telemetry capabilities** structure raw events into ECS-compatible format
3. **Detection engines** analyze telemetry events against rules and produce alerts
4. **Prevention modules** block threats in real-time (fanotify deny, process kill)
5. **Event pipeline** enriches, filters, and buffers all events
6. **Control plane client** ships events/alerts to the XDR backend
7. **Response manager** receives and executes commands from the control plane

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

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Go language | Low overhead, single binary, strong stdlib, go cross-compilation |
| Capability pattern | Modular, independently testable, policy-controlled |
| ECS-compatible events | Interoperable with Elastic ecosystem, standard field naming |
| eBPF preferred | Lowest overhead kernel telemetry, safe (verified programs) |
| YARA for signatures | Industry standard, huge existing rule collection |
| SIGMA for behaviors | Industry standard, 3000+ community rules |
| fanotify for blocking | Kernel-level file access control, no filesystem driver needed |

---

## Industry Telemetry Comparison

> **Last updated:** 2026-03-02

This section tracks what the leading EDR/XDR solutions collect at the endpoint
and compares it with our current telemetry coverage so we can prioritize gaps.

### Competitive Telemetry Matrix

| Telemetry Category | Elastic Defend | CrowdStrike Falcon | MS Defender for Endpoint | SentinelOne Singularity | **xdr-agent** |
|---|---|---|---|---|---|
| **Process lifecycle** (create/exec/exit) | ✅ kernel + eBPF/kprobe/Quark | ✅ kernel sensor | ✅ kernel driver | ✅ kernel agent | ✅ /proc polling |
| **Process tree / ancestry** | ✅ (configurable depth) | ✅ full tree | ✅ | ✅ | ✅ up to 10 ancestors |
| **Process hashing** (SHA-256/SHA-1/MD5) | ✅ all three (configurable) | ✅ | ✅ | ✅ | ✅ SHA-256 only |
| **Command-line capture** | ✅ (adv. setting for all events) | ✅ | ✅ | ✅ | ✅ |
| **Environment variable capture** | ✅ (up to 5 vars, Linux/macOS) | ✅ select vars | ✅ | ✅ | ❌ **GAP** |
| **File integrity (create/modify/delete)** | ✅ fanotify + kernel | ✅ kernel | ✅ kernel driver | ✅ kernel agent | ✅ inotify + rescan |
| **File access (read) events** | ✅ (configurable paths) | ✅ | ✅ | ✅ | ❌ **GAP** |
| **File hashing on events** | ✅ SHA-256 (async, configurable) | ✅ | ✅ | ✅ | ✅ SHA-256 on FIM |
| **File entropy / header bytes** | ✅ (Linux 9.3+, macOS) | ✅ | ✅ | ✅ | ❌ **GAP** |
| **File origin (download source)** | ✅ Mark of the Web (Win) | ✅ | ✅ | partial | N/A (Linux focus) |
| **Network connections** (TCP/UDP) | ✅ kernel events | ✅ kernel | ✅ kernel driver | ✅ | ✅ /proc/net polling |
| **DNS monitoring** | ✅ integrated | ✅ | ✅ | ✅ | ✅ AF_PACKET |
| **Network deduplication** | ✅ (8.15+, configurable) | ✅ | ✅ | ✅ | ❌ **GAP** |
| **Library / shared object loading** | ✅ image_load events (DLL/SO) | ✅ drivers + DLLs | ✅ DLL loads | ✅ | ❌ **GAP — CRITICAL** |
| **Kernel module load/unload** | ✅ | ✅ driver loading | ✅ | ✅ | ❌ **GAP — CRITICAL** |
| **User login / session tracking** | ✅ | ✅ all login types | ✅ user login activities | ✅ | ✅ utmp + auth log |
| **TTY / terminal I/O capture** | ✅ (Linux, configurable) | ✅ | partial | partial | ❌ **GAP** |
| **Registry monitoring** | ✅ (Windows) | ✅ | ✅ | ✅ | N/A (Linux only) |
| **Memory threat scanning** | ✅ YARA + shellcode detection | ✅ | ✅ | ✅ | ❌ **GAP** |
| **Script content capture** | ✅ (macOS 9.3+) | ✅ | ✅ (AMSI) | ✅ | ❌ **GAP** |
| **API / syscall monitoring** | ✅ ETW (Windows), eBPF (Linux) | ✅ | ✅ | ✅ | ❌ **GAP** |
| **ptrace / process injection** | ✅ behavioral rules | ✅ | ✅ | ✅ | ❌ **GAP** |
| **Scheduled task / persistence** | ✅ behavioral detection | ✅ | ✅ | ✅ | ❌ **GAP** (stub only) |
| **Auditd / audit log forwarding** | ✅ via Elastic Agent | ✅ | ✅ | ✅ | ❌ **GAP** (stub only) |
| **Container runtime events** | ✅ (cloud security) | ✅ Falcon Cloud | ✅ | ✅ | ❌ **GAP** (ID only) |
| **USB / removable media** | ✅ device control (9.2+) | ✅ device control | ✅ | partial | ❌ **GAP** |
| **Archive file operations** | partial | ✅ RAR/ZIP creation tracking | partial | partial | ❌ **GAP** |
| **Callstack collection** | ✅ (process/file/net/registry) | ✅ | ✅ | ✅ | ❌ **GAP** |
| **Named pipe / IPC** | ✅ | ✅ | ✅ | partial | ❌ **GAP** |
| **System metrics** (CPU/mem/disk) | ✅ Elastic Agent metrics | partial | partial | partial | ✅ full |
| **eBPF-based collection** | ✅ (auto kprobe/eBPF/Quark) | ✅ | N/A (Windows) | ✅ | ❌ **GAP** (planned Phase 7) |

### Gap Priority Classification

**CRITICAL — Must-have for competitive parity (Phase 2b):**

1. **Shared library / SO loading monitoring** — Detects `LD_PRELOAD` injection, `dlopen()` hijacking (T1574.006, T1055.001)
2. **Kernel module load/unload detection** — Detects rootkits, LKM-based persistence (T1547.006, T1014)
3. **TTY / terminal I/O capture** — Forensic session recording for incident reconstruction
4. **Scheduled task / cron monitoring** — Detects persistence via cron/at/systemd timers (T1053.003)
5. **ptrace / process injection monitoring** — Detects `ptrace`, `process_vm_writev`, `memfd_create` injection (T1055)

**HIGH — Significant security value (Phase 2c):**

6. **Environment variable capture** — Detects `LD_PRELOAD`, `LD_LIBRARY_PATH` manipulation (T1574.006)
7. **Script content capture** — Records shell/Python/Perl script bodies for forensic analysis
8. **File access (read) events on sensitive paths** — Detects credential access to `/etc/shadow`, SSH keys (T1003.008)
9. **Named pipe / Unix socket IPC monitoring** — Detects C2 channels via IPC (T1559)
10. **File entropy and header bytes** — Enables encrypted/packed file detection without full YARA scan

**MEDIUM — Enhances depth (Phase 2d):**

11. **Network event deduplication** — Reduces noise, improves storage efficiency
12. **USB / removable media monitoring** — Detects data exfiltration via USB (T1052.001)
13. **Archive file operation tracking** — Detects staging for exfiltration (T1560)
14. **Auditd / Linux audit integration** — Comprehensive syscall audit trail
15. **Container runtime event monitoring** — Detects container escape, drift, exec-into (T1610, T1611)

---

## Telemetry Data Flow (Expanded)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              PLATFORM LAYER                                      │
│                                                                                  │
│  ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐ │
│  │  procfs   │ │ inotify  │ │AF_PACKET │ │  utmp +  │ │kprobes/│ │proc_conn │ │
│  │  polling  │ │ watches  │ │  socket  │ │auth tail │ │  eBPF  │ │ netlink  │ │
│  └─────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘ └────┬─────┘ │
│        │             │            │             │            │           │        │
│  ┌─────▼─────────────▼────────────▼─────────────▼────────────▼───────────▼──┐    │
│  │                    TELEMETRY CAPABILITY LAYER                             │    │
│  │                                                                           │    │
│  │  ┌─────────┐ ┌──────┐ ┌─────────┐ ┌──────┐ ┌──────────┐ ┌───────────┐  │    │
│  │  │ Process │ │ FIM  │ │ Network │ │ DNS  │ │ Session  │ │  System   │  │    │
│  │  │         │ │      │ │  Conn   │ │      │ │  /Auth   │ │  Metrics  │  │    │
│  │  └────┬────┘ └──┬───┘ └────┬────┘ └──┬───┘ └────┬─────┘ └─────┬─────┘  │    │
│  │       │         │          │         │           │              │         │    │
│  │  ┌────▼─────────▼──────────▼─────────▼───────────▼──────────────▼──┐     │    │
│  │  │                  NEW TELEMETRY (Phase 2b/2c/2d)                  │     │    │
│  │  │                                                                  │     │    │
│  │  │ ┌─────────┐ ┌──────────┐ ┌───────┐ ┌─────────┐ ┌────────────┐ │     │    │
│  │  │ │ SO/Lib  │ │  Kernel  │ │  TTY  │ │Scheduled│ │  ptrace /  │ │     │    │
│  │  │ │ Loading │ │  Module  │ │  I/O  │ │  Tasks  │ │ Injection  │ │     │    │
│  │  │ └─────────┘ └──────────┘ └───────┘ └─────────┘ └────────────┘ │     │    │
│  │  │ ┌─────────┐ ┌──────────┐ ┌───────┐ ┌─────────┐ ┌────────────┐ │     │    │
│  │  │ │Env Vars │ │ Script   │ │File   │ │  IPC /  │ │ Entropy /  │ │     │    │
│  │  │ │ Capture │ │ Capture  │ │Access │ │  Pipe   │ │  Headers   │ │     │    │
│  │  │ └─────────┘ └──────────┘ └───────┘ └─────────┘ └────────────┘ │     │    │
│  │  └──────────────────────────────────────────────────────────────────┘     │    │
│  └──────────────────────────────┬────────────────────────────────────────────┘    │
│                                  │ ECS events                                     │
│  ┌───────────────────────────────▼──────────────────────────────────────────┐     │
│  │                         EVENT PIPELINE                                    │     │
│  │  Emit → Enrich (host, geo, threat) → Filter → Buffer (disk) → Ship       │     │
│  └───────────────────────────────┬──────────────────────────────────────────┘     │
│                                  │                                                │
│  ┌───────────────────────────────▼──────────────────────────────────────────┐     │
│  │                    CONTROL PLANE CLIENT → OpenSearch                      │     │
│  └──────────────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────────┘
```
