# XDR Agent — Development Roadmap

> **Last updated:** 2026-02-26

---

## Table of Contents

1. [Vision](#vision)
2. [Current State](#current-state)
3. [Security Capability Matrix](#security-capability-matrix)
4. [Industry Comparison](#industry-comparison)
5. [Phased Development Plan](#phased-development-plan)
6. [Capability Registry & Policy Control](#capability-registry--policy-control)
7. [Migration Path from v0.1.0](#migration-path-from-v010)

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

## Security Capability Matrix

### 1. Malware Prevention & Detection

| Sub-capability | Description | Phase |
|---|---|---|
| Hash-based detection | Match file SHA256/MD5 against known malware databases | 3 |
| YARA rule scanning | Pattern-based static analysis using YARA rules | 3 |
| Static file analysis | Inspect ELF headers, entropy, imports for suspicious indicators | 3 |
| On-access scanning | Real-time scanning on file open/write/execute via `fanotify` | 4 |
| Quarantine vault | Isolate malicious files in encrypted, non-executable storage | 4 |
| Allowlist / Blocklist | Hash-based, path-based, or signer-based exception management | 4 |

### 2. Ransomware Prevention

| Sub-capability | Description | Phase |
|---|---|---|
| Canary / honeypot files | Deploy decoy files in key directories to detect encryption activity | 4 |
| Mass file modification detection | Detect rapid rename/modify/delete patterns across many files | 4 |
| Entropy analysis | Detect sudden entropy increase in modified files (encryption signal) | 4 |
| MBR / VBR protection | Prevent unauthorized modification of boot records | 4 |
| Shadow copy protection | Detect/prevent deletion of volume shadow copies | 4 |
| File backup & rollback | Maintain shadow copies of critical files for post-attack rollback | 4 |

### 3. Behavioral Detection & Analytics

| Sub-capability | Description | Phase |
|---|---|---|
| Process behavior monitoring | Track process trees, parent-child relationships, command-lines | 3 |
| Behavioral rule engine | Configurable rules matching process behavior patterns (SIGMA-like) | 3 |
| MITRE ATT&CK mapping | Tag all detections with ATT&CK technique/tactic IDs | 3 |
| Anomaly detection | Baseline normal behavior, detect statistical deviations | 7 |
| Script / command-line analysis | Detect obfuscated shell commands, encoded payloads | 3 |
| LOLBin detection | Detect abuse of legitimate system tools (curl, wget, python, etc.) | 3 |
| Credential access detection | Detect credential dumping, brute force, authentication abuse | 3 |
| Lateral movement detection | Detect SSH tunneling, abnormal remote connections, pivoting | 3 |
| Persistence detection | Detect cron jobs, systemd services, shell profile modifications | 3 |

### 4. Memory & Exploit Protection

| Sub-capability | Description | Phase |
|---|---|---|
| Shellcode injection detection | Detect code injection into running processes via `/proc/[pid]/mem` | 7 |
| Process hollowing detection | Detect when a process image is replaced in memory | 7 |
| DLL/SO injection detection | Monitor `LD_PRELOAD`, `dlopen()`, `/proc/[pid]/maps` | 7 |
| ptrace restriction | Monitor and restrict `ptrace` calls used for injection | 4 |
| Stack pivot / ROP detection | Detect Return-Oriented Programming chains | 7 |
| Fileless malware detection | Detect execution from `memfd_create`, `/dev/shm`, anonymous memory | 7 |

### 5. Endpoint Visibility & Telemetry

| Sub-capability | Description | Phase |
|---|---|---|
| Process monitoring | Real-time process creation/termination (eBPF, netlink, procfs) | 2 |
| File integrity monitoring (FIM) | Detect changes to critical system files and directories | 2 |
| Network connection monitoring | Track all inbound/outbound TCP/UDP connections | 2 |
| DNS query monitoring | Log and analyze DNS queries for C2, DGA, exfiltration | 2 |
| User / session monitoring | Track logons, logoffs, `su`/`sudo` usage, privilege changes | 2 |
| Kernel module monitoring | Detect loading/unloading of kernel modules | 7 |
| eBPF-based telemetry | Kernel-level event collection with minimal overhead | 7 |
| Syslog / auditd collection | Forward system logs and audit trail | 2 |
| Scheduled task monitoring | Monitor cron, at, systemd timers for persistence | 2 |

### 6. Active Response & Containment

| Sub-capability | Description | Phase |
|---|---|---|
| Network isolation | Isolate endpoint from LAN (keep control-plane connectivity) | 5 |
| Process kill / suspend | Remotely terminate or freeze malicious processes | 5 |
| File remediation | Delete, quarantine, or restore files remotely | 5 |
| Remote shell | Execute commands on endpoint for incident response | 5 |
| Automated playbooks | Rule-triggered automatic response action chains | 7 |
| Host firewall management | Dynamic iptables/nftables rule injection | 5 |

### 7. Threat Intelligence

| Sub-capability | Description | Phase |
|---|---|---|
| IoC matching | Match file hashes, IPs, domains, URLs against IoC databases | 3 |
| Threat feed ingestion | Consume STIX/TAXII, MISP, OpenCTI feeds | 3 |
| Reputation scoring | File/IP/domain reputation lookups via external services | 3 |

### 8. Cloud & Container Security

| Sub-capability | Description | Phase |
|---|---|---|
| Container runtime monitoring | Docker, containerd, CRI-O event monitoring | 5 |
| Kubernetes audit logs | K8s API server event collection | 5 |
| Container drift detection | Detect runtime file changes vs. original container image | 5 |
| Cloud metadata collection | AWS/GCP/Azure instance metadata, IAM, tags | 5 |
| Container image inventory | Track running images, versions, layers | 5 |

### 9. Compliance & Auditing

| Sub-capability | Description | Phase |
|---|---|---|
| CIS benchmark scanning | Check OS config against CIS benchmarks | 6 |
| Security Configuration Assessment | SSH hardening, firewall rules, user management checks | 6 |
| System hardening checks | Verify ASLR, SELinux/AppArmor, file permissions | 6 |
| Software inventory | Track installed packages, versions, sources | 6 |
| Audit trail | Immutable log of all agent actions and config changes | 6 |
| Regulatory frameworks | PCI DSS, HIPAA, SOC2, GDPR control mappings | 6 |

### 10. Vulnerability Detection

| Sub-capability | Description | Phase |
|---|---|---|
| CVE scanning | Match installed packages against CVE databases (NVD, OSV) | 6 |
| OS patch assessment | Check for missing security updates | 6 |
| Open port detection | Identify listening services and exposed ports | 6 |
| Weak configuration detection | Detect default credentials, insecure service configs | 6 |

---

## Industry Comparison

How the proposed XDR agent compares against industry-leading EDR/XDR products.

### Capability Coverage

| Capability Domain | CrowdStrike Falcon | Elastic Defend | Microsoft Defender for Endpoint | SentinelOne Singularity | Carbon Black Cloud | XDR Agent (Proposed) |
|---|---|---|---|---|---|---|
| **Malware Prevention** | ✅ ML + IoA + cloud | ✅ ML + YARA + signatures | ✅ ML + cloud + behavior | ✅ Static AI + behavioral AI | ✅ Reputation + ML | ✅ YARA + Hash + Static |
| **Ransomware Protection** | ✅ CryptoWall, behavioral | ✅ Behavioral rules | ✅ Controlled folder access | ✅ Rollback via Storyline | ✅ Behavioral | ✅ Canary + Behavioral + Rollback |
| **Behavioral Detection** | ✅ IoA engine (cloud) | ✅ EQL + prebuilt rules | ✅ Behavioral sensors | ✅ Storyline (process tree) | ✅ Behavioral analytics | ✅ SIGMA-like Rule Engine |
| **Memory / Exploit Protection** | ✅ Deep kernel inspection | ✅ Memory threat prevention | ✅ Exploit guard, ASR rules | ✅ Exploit shield | ✅ Memory scraping prevention | ✅ Injection + Fileless + ptrace |
| **Endpoint Visibility** | ✅ Full EDR telemetry | ✅ Full (process, file, net, DNS) | ✅ Full (advanced hunting) | ✅ Full (Deep Visibility) | ✅ Full (process, file, net) | ✅ Process + File + Net + Session |
| **Active Response** | ✅ Real Time Response (RTR) | ✅ Response actions + Osquery | ✅ Live Response | ✅ Remote shell + remediate | ✅ Live Response | ✅ Isolate + Kill + Shell + Playbooks |
| **Threat Intelligence** | ✅ Built-in (Falcon X) | ✅ Elastic Threat Intel | ✅ Microsoft TI | ✅ Built-in SentinelOne TI | ✅ CB Threat Intel | ✅ STIX/TAXII + IoC matching |
| **Cloud / Container** | ✅ Falcon Cloud Workload | ✅ Cloud Defend + K8s | ✅ Defender for Cloud | ✅ Cloud Workload Security | ✅ Container security | ✅ Container + K8s + Cloud metadata |
| **Compliance** | ⚠️ Separate (Falcon Spotlight) | ✅ CSPM + Benchmarks | ✅ Secure Score + Baselines | ⚠️ Ranger (network) | ✅ Audit & Remediation | ✅ CIS + SCA + Hardening |
| **Vulnerability Scanning** | ⚠️ Spotlight (add-on) | ✅ Vuln management | ✅ Threat & Vuln Management | ⚠️ Application vuln | ✅ Vuln assessment | ✅ CVE + Package + Patch scanning |
| **Open Source** | ❌ Proprietary | ⚠️ Partially open | ❌ Proprietary | ❌ Proprietary | ❌ Proprietary | ✅ Fully open source |

### Architecture Approach

| Aspect | CrowdStrike | Elastic | Microsoft | SentinelOne | Carbon Black | XDR Agent |
|---|---|---|---|---|---|---|
| **Agent language** | C/C++ | C/C++ + Go | C++ | C++ | C | Go |
| **Detection model** | Cloud AI + local IoA | Local rules + ML models | Cloud + local behavior | Local autonomous AI | Cloud reputation + local | Local rules + cloud IoC feeds |
| **Kernel integration** | Proprietary kernel driver | eBPF (Linux) | ETW (Windows), eBPF | Proprietary kernel hooks | Kernel driver | eBPF + fanotify + netlink |
| **Rule format** | Proprietary IoA | EQL + KQL + YARA | KQL | Proprietary Storyline | Proprietary | SIGMA-like YAML + YARA |
| **Offline capability** | Degraded (cloud-dependent) | Full local detection | Degraded | Full autonomous | Degraded | Full local detection |
| **Multi-OS** | Windows, macOS, Linux | Windows, macOS, Linux | Windows, macOS, Linux | Windows, macOS, Linux | Windows, macOS, Linux | Linux (planned: macOS) |
| **Deployment** | SaaS + agent | Self-hosted or Cloud | SaaS (Intune/MDE) | SaaS + agent | SaaS + agent | Self-hosted (OpenSearch) |

### Key Differentiators

| Our Advantage | Detail |
|---|---|
| **Fully open source** | Complete transparency — audit every detection rule, every kernel hook, every line of agent code |
| **Self-hosted backend** | Data never leaves your infrastructure (OpenSearch + Dashboards) |
| **Standard rule formats** | SIGMA + YARA — leverage thousands of community rules from day one |
| **No cloud dependency** | Full detection and prevention works offline; cloud enrichment is additive |
| **Extensible architecture** | Add custom capabilities via the standard `Capability` interface |
| **OpenSearch native** | Events indexed directly into OpenSearch for powerful search, dashboards, and alerting |

### Where Industry Leaders Excel (Our Gap)

| Gap Area | Industry Leader | What They Offer | Our Mitigation |
|---|---|---|---|
| **ML-based detection** | CrowdStrike, SentinelOne | Cloud-trained ML models for zero-day detection | YARA + behavioral heuristics; ML planned for Phase 7+ |
| **Autonomous operation** | SentinelOne | Fully autonomous remediation without cloud | Automated playbooks (Phase 7) provide similar capability |
| **Storyline / attack graph** | SentinelOne, CrowdStrike | Automatic attack chain reconstruction | Process tree + alert correlation (Phase 3+) |
| **Managed threat hunting** | CrowdStrike OverWatch | Human threat hunters watching your environment | Community-driven rules; org can run own threat hunting on OpenSearch |
| **Identity protection** | CrowdStrike Falcon Identity | AD/LDAP monitoring, identity-based detection | Linux PAM + session monitoring covers auth events |
| **macOS / Windows** | All leaders | Full multi-OS support | Linux-first; macOS planned; Windows via platform abstraction layer |

---

## Phased Development Plan

### Phase 1 — Foundation (v0.1.0 → v0.2.0)

**Goal:** Restructure the agent to support pluggable capabilities.

| # | Task | Packages |
|---|---|---|
| 1 | Implement capability interface and registry pattern | `internal/capability/`, `internal/agent/` |
| 2 | Build event pipeline (in-memory bus → enrichment → buffer) | `internal/events/` |
| 3 | Migrate enrollment + heartbeat into unified control-plane client | `internal/controlplane/` |
| 4 | Add event shipping to control plane | `internal/controlplane/shipper.go` |
| 5 | Expand config for hierarchical per-capability settings | `internal/config/` |
| 6 | Wire agent orchestrator as the new runtime loop | `internal/agent/agent.go` |

**Exit criteria:** Agent starts, enrolls, sends heartbeat, and ships events
through the pipeline to the control plane. Capabilities can be registered and
managed via the orchestrator.

### Phase 2 — Endpoint Visibility (v0.3.0)

**Goal:** Collect baseline telemetry from the endpoint.

| # | Task | Packages |
|---|---|---|
| 7 | Process monitoring (netlink proc connector + procfs enrichment) | `internal/telemetry/process/` |
| 8 | File integrity monitoring (inotify on critical paths) | `internal/telemetry/file/` |
| 9 | Network connection tracking (procfs + netlink SOCK_DIAG) | `internal/telemetry/network/` |
| 10 | User session and privilege monitoring (utmp/wtmp + PAM) | `internal/telemetry/session/` |
| 11 | Auditd / syslog collection | `internal/telemetry/audit/` |
| 12 | Scheduled task monitoring (cron, systemd timers) | `internal/telemetry/scheduled/` |
| 13 | Linux platform wrappers (procfs, netlink, inotify) | `internal/platform/linux/` |

**Exit criteria:** Agent collects and ships process, file, network, and session
telemetry events to OpenSearch. Events are ECS-compatible and visible in dashboards.

### Phase 3 — Detection (v0.4.0)

**Goal:** Detect threats using rules and intelligence feeds.

| # | Task | Packages |
|---|---|---|
| 14 | Hash-based malware detection (SHA256/MD5 blocklist) | `internal/detection/malware/hash.go` |
| 15 | YARA rule engine integration | `internal/detection/malware/yara.go` |
| 16 | Static ELF analysis (entropy, suspicious sections) | `internal/detection/malware/static.go` |
| 17 | Behavioral rule engine (SIGMA-like YAML rules) | `internal/detection/behavioral/` |
| 18 | Initial rule set (ransomware, persistence, cred access, LOLBins) | `rules/behavioral/` |
| 19 | IoC matching engine (hash, IP, domain) | `internal/detection/threatintel/` |
| 20 | STIX/TAXII feed ingestion | `internal/detection/threatintel/feed.go` |
| 21 | SIGMA rule parser for community rules | `pkg/ruleformat/sigma.go` |

**Exit criteria:** Agent generates alerts for known malware hashes, YARA hits,
behavioral rule matches, and IoC matches. Alerts are indexed in OpenSearch with
MITRE ATT&CK technique tags.

### Phase 4 — Prevention (v0.5.0)

**Goal:** Block threats in real-time before damage occurs.

| # | Task | Packages |
|---|---|---|
| 22 | Malware execution blocking (fanotify FAN_DENY) | `internal/prevention/malware/blocker.go` |
| 23 | Quarantine vault (encrypted, non-executable storage) | `internal/prevention/malware/quarantine.go` |
| 24 | Ransomware canary/honeypot files | `internal/prevention/ransomware/canary.go` |
| 25 | Ransomware behavioral shield (entropy + mass modification) | `internal/prevention/ransomware/shield.go` |
| 26 | File backup and rollback for ransomware recovery | `internal/prevention/ransomware/rollback.go` |
| 27 | Exploit mitigation enforcement (ASLR, NX, ptrace) | `internal/prevention/exploit/` |
| 28 | Allowlist / blocklist management | `internal/prevention/allowlist/` |

**Exit criteria:** Agent blocks execution of known malware, detects and halts
ransomware encryption in progress, and enforces exploit mitigations. False positive
rate below threshold set by allowlist.

### Phase 5 — Response & Cloud (v0.6.0)

**Goal:** Enable remote incident response and cloud/container visibility.

| # | Task | Packages |
|---|---|---|
| 29 | Network isolation (iptables/nftables allow only control plane) | `internal/response/isolate.go` |
| 30 | Remote process termination | `internal/response/kill.go` |
| 31 | File remediation (delete, quarantine, restore) | `internal/response/remediate.go` |
| 32 | Remote shell execution | `internal/response/shell.go` |
| 33 | Dynamic firewall rule management | `internal/response/firewall.go` |
| 34 | Container runtime monitoring (Docker, containerd, CRI-O) | `internal/cloud/container/` |
| 35 | Cloud metadata collection (AWS/GCP/Azure IMDSv2) | `internal/cloud/metadata.go` |
| 36 | Kubernetes audit log collection | `internal/cloud/kubernetes/` |
| 37 | Container drift detection | `internal/cloud/container/drift.go` |

**Exit criteria:** Control plane can remotely isolate, kill, remediate, and execute
commands on endpoints. Container lifecycle events and cloud context are captured.

### Phase 6 — Compliance & Vulnerability (v0.7.0)

**Goal:** Periodic security posture assessments.

| # | Task | Packages |
|---|---|---|
| 38 | CIS benchmark scanning (parsed from YAML rules) | `internal/compliance/cis.go` |
| 39 | Security Configuration Assessment (SSH, firewall, users) | `internal/compliance/sca.go` |
| 40 | System hardening checks (ASLR, SELinux, permissions) | `internal/compliance/hardening.go` |
| 41 | Software inventory (dpkg, rpm, apk) | `internal/compliance/inventory.go` |
| 42 | Agent action audit trail | `internal/compliance/audit_trail.go` |
| 43 | CVE scanning (match packages against NVD/OSV) | `internal/vulnerability/cve.go` |
| 44 | OS patch assessment | `internal/vulnerability/patches.go` |
| 45 | Open port / listening service detection | `internal/vulnerability/ports.go` |

**Exit criteria:** Agent produces compliance reports against CIS benchmarks and
vulnerability reports with CVE severity, affected package, and fix version —
all indexed in OpenSearch.

### Phase 7 — Advanced Capabilities (v0.8.0+)

**Goal:** Deep kernel telemetry, advanced detection, and autonomous response.

| # | Task | Packages |
|---|---|---|
| 46 | eBPF-based process and file telemetry (low-overhead replacement) | `internal/telemetry/kernel/`, `internal/platform/linux/ebpf.go` |
| 47 | Kernel module load/unload detection | `internal/telemetry/kernel/modules.go` |
| 48 | Memory scanning — shellcode injection detection | `internal/detection/memory/injection.go` |
| 49 | Process hollowing and fileless malware detection | `internal/detection/memory/hollowing.go`, `fileless.go` |
| 50 | Stack pivot / ROP chain detection | `internal/detection/memory/exploit.go` |
| 51 | Automated response playbooks (rule → action chains) | `internal/response/playbook.go` |
| 52 | Anomaly detection (statistical baselines) | `internal/detection/behavioral/` |
| 53 | Regulatory framework mappings (PCI DSS, HIPAA, SOC2) | `internal/compliance/` |

**Exit criteria:** Agent leverages eBPF for minimal-overhead kernel telemetry,
detects advanced memory-based attacks, and can execute automated response
playbooks without human intervention.

---

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
