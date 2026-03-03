# XDR Agent — Development Roadmap

> **Last updated:** 2026-03-03

---

## Table of Contents

1. [Vision](#vision)
2. [Phase Summary](#phase-summary)
3. [Phase 1 — Foundation](#phase-1--foundation-v010--v020) ✅
4. [Phase 2 — Endpoint Telemetry](#phase-2--endpoint-telemetry-v030--v031) ✅
5. [Phase 3 — Detection](#phase-3--detection-v040) ← next
6. [Phase 4 — Prevention](#phase-4--prevention-v050)
7. [Phase 5 — Active Response & Cloud](#phase-5--active-response--cloud-v060)
8. [Phase 6 — Compliance & Vulnerability](#phase-6--compliance--vulnerability-v070)
9. [Phase 7 — Advanced Capabilities](#phase-7--advanced-capabilities-v080)
10. [Capability Registry & Policy Control](#capability-registry--policy-control)

---

## Vision

Evolve the xdr-agent from a telemetry collection service into a **full-featured,
open-source XDR endpoint agent** for Linux — competitive with CrowdStrike Falcon,
Elastic Defend, Microsoft Defender for Endpoint, and SentinelOne Singularity.

All security capabilities follow a **modular, capability-based architecture**: each
domain is a self-contained package that implements a common interface, is managed by
the service orchestrator, and will be enabled/disabled via policy from the control plane.

---

## Phase Summary

| Phase | Version | Status | Description |
|---|---|---|---|
| 1 | v0.1.0–v0.2.0 | ✅ Complete | Foundation: capability interface, event pipeline, enrollment, control plane |
| 2 | v0.3.0–v0.3.1 | ✅ Complete | Endpoint telemetry: 13 collectors covering process, file, network, session, kernel, and more |
| 3 | v0.4.0 | ❌ Next | Detection: malware (YARA, hash), behavioral (SIGMA rules), memory, threat intel |
| 4 | v0.5.0 | ❌ Planned | Prevention: malware blocking (fanotify), ransomware shield, exploit mitigation |
| 5 | v0.6.0 | ❌ Planned | Active response & cloud: network isolation, remote shell, container monitoring |
| 6 | v0.7.0 | ❌ Planned | Compliance & vulnerability: CIS benchmarks, CVE scanning, hardening checks |
| 7 | v0.8.0+ | ❌ Planned | Advanced: eBPF telemetry, fileless malware detection, autonomous playbooks |

---

## Phase 1 — Foundation (v0.1.0 → v0.2.0) ✅

**Goal:** Core agent infrastructure with pluggable capability architecture.

- ✅ Capability interface and registry pattern — `internal/capability/`
- ✅ Event pipeline (in-memory channel → enrichment → subscribe) — `internal/events/`
- ✅ Agent identity and enrollment — `internal/identity/`, `internal/enroll/`
- ✅ Heartbeat to control plane — `internal/enroll/heartbeat.go`
- ✅ Event shipping to control plane (batch, gzip, retry) — `internal/controlplane/shipper.go`
- ✅ JSON configuration loader — `internal/config/`
- ✅ CLI: `run`, `enroll`, `remove`, `version`, `completion` — `cmd/xdr-agent/`
- ✅ Service orchestrator wiring all capabilities — `internal/service/run.go`
- ✅ Packaging: deb, rpm, multi-arch, systemd service — `packaging/`, `systemd/`

---

## Phase 2 — Endpoint Telemetry (v0.3.0 → v0.3.1) ✅

**Goal:** Comprehensive endpoint visibility — collect and ship all telemetry to OpenSearch.

**13 active telemetry collectors:**

- ✅ **Process monitoring** — Netlink proc connector + procfs enrichment, 30+ fields per event, process tree (10 ancestors), env var capture, script content capture — `internal/telemetry/process/`
- ✅ **File integrity monitoring (FIM)** — inotify on critical paths + BoltDB baseline + SHA-256 rescan + Shannon entropy + file header bytes — `internal/telemetry/file/fim.go`
- ✅ **File access monitoring** — inotify `IN_ACCESS|IN_OPEN` on sensitive paths (`/etc/shadow`, SSH keys) for credential harvesting detection — `internal/telemetry/file/access.go`
- ✅ **Network connections** — `/proc/net/{tcp,tcp6,udp,udp6}` polling + diff-based open/close + Community ID v1 + PID/user enrichment — `internal/telemetry/network/connections.go`
- ✅ **DNS monitoring** — AF_PACKET raw socket, full DNS message parsing, query/response correlation, PID resolution — `internal/telemetry/network/dns.go`
- ✅ **Session monitoring** — utmp binary parsing (login/logoff) + auth log tailing (SSH, sudo, su) — `internal/telemetry/session/`
- ✅ **System metrics** — CPU, memory, disk I/O, network I/O in a single combined event per interval — `internal/telemetry/system/`
- ✅ **Shared library loading** — inotify on lib dirs + `/proc/[pid]/maps` scanning for new `.so` loads + SHA-256 — `internal/telemetry/library/`
- ✅ **Kernel module monitoring** — `/proc/modules` polling for load/unload (rootkit detection) — `internal/telemetry/kernel/modules.go`
- ✅ **TTY session monitoring** — `/proc` PTY scanning for terminal session start/end — `internal/telemetry/tty/`
- ✅ **Scheduled task monitoring** — inotify on cron dirs + systemd timer dirs, diff-based events — `internal/telemetry/scheduled/`
- ✅ **Process injection monitoring** — ptrace detection (`TracerPid`) + anonymous executable memory regions — `internal/telemetry/injection/`
- ✅ **IPC monitoring** — `/proc/net/unix` polling + inotify for named pipe creation — `internal/telemetry/ipc/`

**Integrated into process collector (no separate capability):**
- ✅ Environment variable capture — configurable allowlist (LD_PRELOAD, PATH, etc.) — `envvars.go`
- ✅ Script content capture — first N bytes of interpreter scripts — `script.go`

---

## Phase 3 — Detection (v0.4.0)

**Goal:** Detect threats using rules, signatures, and intelligence feeds.

**Malware & File Detection:**

- ❌ Hash-based malware detection (SHA256/MD5 blocklist) — `internal/detection/malware/hash.go`
- ❌ YARA rule engine integration — `internal/detection/malware/yara.go`
- ❌ Static ELF analysis (entropy, suspicious sections) — `internal/detection/malware/static.go`

**Behavioral Detection:**

- ❌ Behavioral rule engine (SIGMA-like YAML rules) — `internal/detection/behavioral/engine.go`
- ❌ Script / command-line analysis — `internal/detection/behavioral/script.go`
- ❌ LOLBin detection (curl, wget, python abuse) — `internal/detection/behavioral/lolbin.go`
- ❌ Credential access detection — `internal/detection/behavioral/credential.go`
- ❌ Lateral movement detection — `internal/detection/behavioral/lateral.go`
- ❌ Persistence detection (cron, systemd, shell profiles) — `internal/detection/behavioral/persistence.go`
- ❌ Ransomware behavior detection — `internal/detection/behavioral/ransomware.go`

**Threat Intelligence:**

- ❌ IoC matching (hashes, IPs, domains) — `internal/detection/threatintel/matcher.go`
- ❌ Threat feed ingestion (STIX/TAXII, MISP) — `internal/detection/threatintel/feed.go`
- ❌ Reputation scoring — `internal/detection/threatintel/reputation.go`
- ❌ SIGMA rule parser — `pkg/ruleformat/sigma.go`

**Exit criteria:** Agent generates alerts for known malware hashes, YARA hits, behavioral rule matches, and IoC matches. Alerts are indexed in OpenSearch with MITRE ATT&CK technique tags.

---

## Phase 4 — Prevention (v0.5.0)

**Goal:** Block threats in real-time before damage occurs.

**Malware Prevention:**

- ❌ Malware execution blocking (fanotify FAN_DENY) — `internal/prevention/malware/blocker.go`
- ❌ Quarantine vault (encrypted, non-executable storage) — `internal/prevention/malware/quarantine.go`
- ❌ Allowlist / blocklist management — `internal/prevention/allowlist/`

**Ransomware Prevention:**

- ❌ Canary / honeypot files — `internal/prevention/ransomware/canary.go`
- ❌ File backup and rollback — `internal/prevention/ransomware/rollback.go`
- ❌ Ransomware shield orchestrator — `internal/prevention/ransomware/shield.go`

**Exploit Mitigation:**

- ❌ ptrace restriction monitoring — `internal/prevention/exploit/ptrace.go`
- ❌ Exploit guard (ASLR, NX, stack canary) — `internal/prevention/exploit/guard.go`

**Exit criteria:** Agent blocks known malware execution, detects and halts ransomware encryption, and enforces exploit mitigations.

---

## Phase 5 — Active Response & Cloud (v0.6.0)

**Goal:** Remote incident response and cloud/container visibility.

**Active Response:**

- ❌ Network isolation (iptables/nftables) — `internal/response/isolate.go`
- ❌ Remote process termination — `internal/response/kill.go`
- ❌ File remediation (delete, quarantine, restore) — `internal/response/remediate.go`
- ❌ Remote shell execution — `internal/response/shell.go`
- ❌ Dynamic firewall rules — `internal/response/firewall.go`

**Cloud & Container:**

- ❌ Container runtime monitoring (Docker, containerd, CRI-O) — `internal/cloud/container/runtime.go`
- ❌ Cloud metadata collection (AWS/GCP/Azure) — `internal/cloud/metadata.go`
- ❌ Kubernetes audit log collection — `internal/cloud/kubernetes/audit.go`
- ❌ Container drift detection — `internal/cloud/container/drift.go`
- ❌ Container image inventory — `internal/cloud/container/inventory.go`

**Exit criteria:** Control plane can remotely isolate, kill, remediate, and execute commands. Container lifecycle and cloud context are captured.

---

## Phase 6 — Compliance & Vulnerability (v0.7.0)

**Goal:** Periodic security posture assessments.

**Compliance & Hardening:**

- ❌ CIS benchmark scanning — `internal/compliance/cis.go`
- ❌ SSH / system hardening checks — `internal/compliance/hardening.go`
- ❌ Security Configuration Assessment — `internal/compliance/sca.go`
- ❌ Software inventory (dpkg, rpm, apk) — `internal/compliance/inventory.go`
- ❌ Agent action audit trail — `internal/compliance/audit_trail.go`

**Vulnerability Management:**

- ❌ CVE scanning (NVD/OSV) — `internal/vulnerability/cve.go`
- ❌ OS patch assessment — `internal/vulnerability/patches.go`
- ❌ Open port / listening service detection — `internal/vulnerability/ports.go`

**Exit criteria:** Agent produces compliance and vulnerability reports indexed in OpenSearch.

---

## Phase 7 — Advanced Capabilities (v0.8.0+)

**Goal:** Deep kernel telemetry, advanced detection, and autonomous response.

- ❌ eBPF-based telemetry (low-overhead replacement for procfs polling) — `internal/telemetry/kernel/ebpf.go`
- ❌ Fileless malware detection (memfd_create, /dev/shm) — `internal/detection/memory/fileless.go`
- ❌ Automated response playbooks — `internal/response/playbook.go`

**Exit criteria:** Agent leverages eBPF for minimal-overhead kernel telemetry, detects fileless attacks, and executes automated response playbooks.

---

## Capability Registry & Policy Control

Every security module implements the `Capability` interface:

```go
type Capability interface {
    Name() string
    Init(deps Dependencies) error
    Start(ctx context.Context) error
    Stop() error
    Health() HealthStatus
}
```

Capabilities will be enabled or disabled via **policy** from the control plane:

```json
{
  "capabilities": {
    "telemetry.process":       { "enabled": true },
    "telemetry.file":          { "enabled": true, "fim_paths": ["/etc", "/usr/bin"] },
    "telemetry.network":       { "enabled": true },
    "detection.malware":       { "enabled": true, "mode": "detect" },
    "detection.behavioral":    { "enabled": true },
    "prevention.malware":      { "enabled": true, "mode": "prevent" },
    "prevention.ransomware":   { "enabled": true },
    "response":                { "enabled": true },
    "compliance":              { "enabled": true, "interval_hours": 24 },
    "vulnerability":           { "enabled": true, "interval_hours": 12 }
  }
}
```

The orchestrator lifecycle:

1. **Startup:** Load config → init capabilities → start in dependency order
2. **Policy change:** Stop disabled capabilities, start newly enabled ones
3. **Shutdown:** Stop capabilities in reverse order, flush event buffer
