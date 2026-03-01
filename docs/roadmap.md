# XDR Agent — Development Roadmap

> **Last updated:** 2026-02-26

---

## Table of Contents

1. [Vision](#vision)
2. [Current State](#current-state)
3. [Industry Comparison](#industry-comparison)
4. [Security Features & Roadmap](#security-features--roadmap)
5. [Capability Registry & Policy Control](#capability-registry--policy-control)
6. [Migration Path from v0.1.0](#migration-path-from-v010)

---

## Vision

Evolve the xdr-agent from a minimal identity/enrollment service into a **full-featured,
open-source XDR endpoint agent** for Linux — competitive with CrowdStrike Falcon,
Elastic Defend, Microsoft Defender for Endpoint, SentinelOne Singularity, and
Carbon Black Cloud.

All security capabilities follow a **modular, capability-based architecture**: each
domain is a self-contained package that implements a common interface, is managed by
the agent orchestrator, and is enabled/disabled via policy from the control plane.

---

## Current State

**v0.1.0** — Identity & Enrollment (working)

| Package | Purpose |
|---|---|
| `cmd/xdr-agent` | CLI entrypoint (`run`, `enroll`, `remove`, `version`, `completion`) |
| `internal/config` | JSON configuration loader and validation |
| `internal/identity` | Agent identity persistence (agent_id, machine_id, host metadata) |
| `internal/enroll` | Control-plane enrollment and heartbeat HTTP client |
| `internal/service` | Runtime loop — enrollment retry → heartbeat scheduling |
| `internal/buildinfo` | Build version injection via `-ldflags` |

**Scaffolded** — Full capability architecture is in place as packages with interfaces,
stubs, and TODO markers ready for implementation. See [architecture.md](architecture.md)
for details.

---

## Security Features & Roadmap

This section consolidates all security capabilities organized by development phase. Checkboxes indicate completion status: ✅ = completed; ⏳ = in progress; ❌ = not started. *Phase 7 features are optional advanced capabilities.*

### Phase 1 — Foundation (v0.1.0 → v0.2.0)

**Goal:** Restructure the agent to support pluggable capabilities.

- ✅ Implement capability interface and registry pattern — `internal/capability/`, `internal/agent/`
- ✅ Build event pipeline (in-memory bus → enrichment → buffer) — `internal/events/`
- ✅ Migrate enrollment + heartbeat into unified control-plane client — `internal/controlplane/`
- ✅ Add event shipping to control plane — `internal/controlplane/shipper.go`
- ✅ Expand config for hierarchical per-capability settings — `internal/config/`
- ✅ Wire agent orchestrator as the new runtime loop — `internal/agent/agent.go`

**Exit criteria:** Agent starts, enrolls, sends heartbeat, and ships events through the pipeline to the control plane. Capabilities can be registered and managed via the orchestrator.

---

### Phase 2 — Endpoint Visibility (v0.3.0)

**Goal:** Collect baseline telemetry from the endpoint.

**Telemetry Capabilities:**

- ✅ Process monitoring — Real-time process creation/termination (netlink proc connector + procfs enrichment) — `internal/telemetry/process/`
- ✅ File integrity monitoring (FIM) — inotify on critical paths with BoltDB baseline and SHA256 periodic rescan — `internal/telemetry/file/`
- ✅ Network connection monitoring — Track all inbound/outbound TCP/UDP connections with ECS source/destination fields, Community ID v1, username/PID enrichment — `internal/telemetry/network/`
- ✅ System/interface telemetry — Network interface stats (packets, drops, multicast) — `internal/telemetry/system/netio.go`
- ✅ DNS query monitoring — Captures UDP DNS queries+responses via raw AF_PACKET socket; PID enrichment via /proc/net/udp; ECS dns.* fields; transaction correlation — `internal/telemetry/network/dns.go`
- ✅ User / session monitoring — utmp binary polling (logon/logoff events) + auth log tailing (SSH, sudo, su) with ECS authentication fields — `internal/telemetry/session/`
- ❌ Auditd / syslog collection — Forward system logs and audit trail — `internal/telemetry/audit/`
- ❌ Scheduled task monitoring — Monitor cron, at, systemd timers for persistence — `internal/telemetry/scheduled/`
- ✅ Linux platform wrappers (procfs, netlink, inotify) — `internal/platform/linux/`

**Exit criteria:** Agent collects and ships process, file, network, and session telemetry events to OpenSearch. Events are ECS-compatible and visible in dashboards.

---

### Phase 3 — Detection (v0.4.0)

**Goal:** Detect threats using rules and intelligence feeds.

**Malware & File Detection:**

- ❌ Hash-based malware detection (SHA256/MD5 blocklist) — `internal/detection/malware/hash.go`
- ❌ YARA rule engine integration — `internal/detection/malware/yara.go`
- ❌ Static ELF analysis (entropy, suspicious sections) — `internal/detection/malware/static.go`

**Behavioral Detection & Analytics:**

- ❌ Process behavior monitoring — Track process trees, parent-child relationships, command-lines — `internal/detection/behavioral/process.go`
- ❌ Behavioral rule engine (SIGMA-like YAML rules) — `internal/detection/behavioral/engine.go`
- ❌ MITRE ATT&CK mapping — Tag all detections with ATT&CK technique/tactic IDs — `internal/detection/mapping/`
- ❌ Script / command-line analysis — Detect obfuscated shell commands, encoded payloads — `internal/detection/behavioral/script.go`
- ❌ LOLBin detection — Detect abuse of legitimate system tools (curl, wget, python, etc.) — `internal/detection/behavioral/lolbin.go`
- ❌ Credential access detection — Detect credential dumping, brute force, authentication abuse — `internal/detection/behavioral/cred_access.go`
- ❌ Lateral movement detection — Detect SSH tunneling, abnormal remote connections, pivoting — `internal/detection/behavioral/lateral_movement.go`
- ❌ Persistence detection — Detect cron jobs, systemd services, shell profile modifications — `internal/detection/behavioral/persistence.go`

**Threat Intelligence:**

- ❌ IoC matching — Match file hashes, IPs, domains, URLs against IoC databases — `internal/detection/threatintel/ioc.go`
- ❌ Threat feed ingestion — Consume STIX/TAXII, MISP, OpenCTI feeds — `internal/detection/threatintel/feed.go`
- ❌ Reputation scoring — File/IP/domain reputation lookups via external services — `internal/detection/threatintel/reputation.go`
- ❌ SIGMA rule parser — Support community SIGMA-like YAML rules — `pkg/ruleformat/sigma.go`

**Exit criteria:** Agent generates alerts for known malware hashes, YARA hits, behavioral rule matches, and IoC matches. Alerts are indexed in OpenSearch with MITRE ATT&CK technique tags.

---

### Phase 4 — Prevention (v0.5.0)

**Goal:** Block threats in real-time before damage occurs.

**Malware Prevention:**

- ❌ Malware execution blocking (fanotify FAN_DENY) — `internal/prevention/malware/blocker.go`
- ❌ Quarantine vault (encrypted, non-executable storage) — `internal/prevention/malware/quarantine.go`
- ❌ Allowlist / blocklist management (hash-based, path-based) — `internal/prevention/allowlist/`

**Ransomware Prevention:**

- ❌ Canary / honeypot files — Deploy decoy files to detect encryption activity — `internal/prevention/ransomware/canary.go`
- ❌ Mass file modification detection — Detect rapid rename/modify/delete patterns — `internal/prevention/ransomware/mass_mod.go`
- ❌ Entropy analysis — Detect sudden entropy increase (encryption signal) — `internal/prevention/ransomware/entropy.go`
- ❌ File backup and rollback — Maintain shadow copies of critical files — `internal/prevention/ransomware/rollback.go`

**Exploit Mitigation:**

- ❌ ptrace restriction monitoring — Monitor and restrict `ptrace` calls used for injection — `internal/prevention/exploit/ptrace.go`
- ❌ Exploit mitigation enforcement (ASLR, NX, stack canary verification) — `internal/prevention/exploit/`

**Exit criteria:** Agent blocks execution of known malware, detects and halts ransomware encryption, and enforces exploit mitigations.

---

### Phase 5 — Active Response & Cloud (v0.6.0)

**Goal:** Enable remote incident response and cloud/container visibility.

**Active Response:**

- ❌ Network isolation (iptables/nftables, keep control-plane connectivity) — `internal/response/isolate.go`
- ❌ Remote process termination / suspension — `internal/response/kill.go`
- ❌ File remediation (delete, quarantine, restore) — `internal/response/remediate.go`
- ❌ Remote shell execution — `internal/response/shell.go`
- ❌ Dynamic firewall rule management — `internal/response/firewall.go`

**Cloud & Container:**

- ❌ Container runtime monitoring (Docker, containerd, CRI-O) — `internal/cloud/container/monitor.go`
- ❌ Cloud metadata collection (AWS/GCP/Azure IMDSv2) — `internal/cloud/metadata.go`
- ❌ Kubernetes audit log collection — `internal/cloud/kubernetes/audit.go`
- ❌ Container drift detection — Detect runtime file changes vs. original image — `internal/cloud/container/drift.go`
- ❌ Container image inventory — Track running images, versions, layers — `internal/cloud/container/inventory.go`

**Exit criteria:** Control plane can remotely isolate, kill, remediate, and execute commands on endpoints. Container lifecycle events and cloud context are captured.

---

### Phase 6 — Compliance & Vulnerability (v0.7.0)

**Goal:** Periodic security posture assessments.

**Compliance & Hardening:**

- ❌ CIS benchmark scanning — Check OS config against CIS benchmarks — `internal/compliance/cis.go`
- ❌ Security Configuration Assessment (SSH hardening, firewall, users) — `internal/compliance/sca.go`
- ❌ System hardening checks (ASLR, SELinux/AppArmor, file permissions) — `internal/compliance/hardening.go`
- ❌ Software inventory (dpkg, rpm, apk packages) — `internal/compliance/inventory.go`
- ❌ Agent action audit trail — Immutable log of all agent actions — `internal/compliance/audit_trail.go`

**Vulnerability Management:**

- ❌ CVE scanning — Match installed packages against NVD/OSV databases — `internal/vulnerability/cve.go`
- ❌ OS patch assessment — Check for missing security updates — `internal/vulnerability/patches.go`
- ❌ Open port / listening service detection — `internal/vulnerability/ports.go`
- ❌ Weak configuration detection — Detect default credentials and insecure service configs — `internal/vulnerability/weak_config.go`

**Exit criteria:** Agent produces compliance reports against CIS benchmarks and vulnerability reports with CVE severity, affected package, and fix version—all indexed in OpenSearch.

---

### Phase 7 — Advanced Capabilities (v0.8.0+)

**Goal:** Deep kernel telemetry, advanced detection, and autonomous response. *Optional/Nice-to-have advanced features.*

**Advanced Telemetry:**

- ❌ eBPF-based process and file telemetry (low-overhead replacement) — `internal/telemetry/kernel/ebpf.go`
- ❌ Kernel module load/unload detection — `internal/telemetry/kernel/modules.go`

**Advanced Detection:**

- ❌ Fileless malware detection — Detect execution from `memfd_create`, `/dev/shm`, anonymous memory — `internal/detection/memory/fileless.go`
- ❌ Anomaly detection — Baseline normal behavior, detect statistical deviations — `internal/detection/behavioral/anomaly.go`

**Autonomous Response:**

- ❌ Automated response playbooks — Rule-triggered automatic action chains — `internal/response/playbook.go`

**Exit criteria:** Agent leverages eBPF for minimal-overhead kernel telemetry, detects fileless attacks, and can execute automated response playbooks without human intervention.


## Capability Registry & Policy Control

Every security module implements the `Capability` interface:

```go
type Capability interface {
    Name() string                       // e.g. "telemetry.process", "detection.malware"
    Init(deps Dependencies) error       // Receive config, event pipeline, logger
    Start(ctx context.Context) error    // Begin monitoring / scanning
    Stop() error                        // Graceful shutdown
    Health() HealthStatus               // running, degraded, failed, etc.
}
```

Capabilities are enabled or disabled via **policy** from the control plane:

```json
{
  "capabilities": {
    "telemetry.process":       { "enabled": true },
    "telemetry.file":          { "enabled": true, "fim_paths": ["/etc", "/usr/bin"] },
    "telemetry.network":       { "enabled": true },
    "detection.malware":       { "enabled": true, "mode": "detect" },
    "detection.behavioral":    { "enabled": true },
    "detection.memory":        { "enabled": false },
    "prevention.malware":      { "enabled": true, "mode": "prevent" },
    "prevention.ransomware":   { "enabled": true },
    "prevention.exploit":      { "enabled": false },
    "response":                { "enabled": true },
    "compliance":              { "enabled": true, "interval_hours": 24 },
    "vulnerability":           { "enabled": true, "interval_hours": 12 },
    "cloud.container":         { "enabled": "auto" }
  }
}
```

The agent orchestrator manages all capability lifecycles:

1. **Startup:** Register capabilities → read policy → init enabled ones → start in dependency order
2. **Policy change:** Stop disabled capabilities, start newly enabled ones
3. **Shutdown:** Stop capabilities in reverse order, flush event buffer, deregister

---

## Migration Path from v0.1.0

| Current (v0.1.0) | Target | Change |
|---|---|---|
| `internal/service/run.go` | `internal/agent/agent.go` + `lifecycle.go` | Split into orchestrator + lifecycle; add capability loop |
| `internal/enroll/client.go` | `internal/controlplane/enroll.go` | Move to controlplane package; extract shared HTTP client |
| `internal/enroll/heartbeat.go` | `internal/controlplane/heartbeat.go` | Same logic; shared HTTP client |
| `internal/config/config.go` | `internal/config/config.go` + `policy.go` | Expand with per-capability config sections and policy schema |
| `internal/identity/state.go` | `internal/identity/state.go` | **No change** — stays as-is |
| `internal/buildinfo/version.go` | `internal/buildinfo/version.go` | **No change** — stays as-is |
| `cmd/xdr-agent/main.go` | `cmd/xdr-agent/main.go` | Expand CLI commands (status, isolate, scan, etc.) |

The existing `internal/enroll/` and `internal/service/` packages remain functional
and are used by the current binary until the `internal/agent/` orchestrator and
`internal/controlplane/` client are fully implemented and wired up.
