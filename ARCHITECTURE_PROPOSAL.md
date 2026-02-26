# XDR Agent — Security Capabilities & Architecture Proposal

> **Date:** 2026-02-26  
> **Status:** Proposal  
> **Scope:** Full EDR/XDR capability matrix and codebase reorganization

---

## Table of Contents

1. [Current State Analysis](#1-current-state-analysis)
2. [EDR/XDR Security Capabilities Research](#2-edrxdr-security-capabilities-research)
3. [Proposed Architecture & Folder Structure](#3-proposed-architecture--folder-structure)
4. [Capability Detail Breakdown](#4-capability-detail-breakdown)
5. [Migration Path from Current Code](#5-migration-path-from-current-code)
6. [Capability Registry Pattern](#6-capability-registry-pattern)
7. [Implementation Priority](#7-implementation-priority)

---

## 1. Current State Analysis

The xdr-agent is a **minimal Go agent** (v0.1.0) focused exclusively on identity and enrollment:

| Package | Purpose | Files |
|---------|---------|-------|
| `cmd/xdr-agent` | CLI entrypoint (`run`, `enroll`, `remove`, `version`, `completion`) | `main.go` |
| `internal/buildinfo` | Build version injection via `-ldflags` | `version.go` |
| `internal/config` | JSON config loader + validation | `config.go` |
| `internal/enroll` | Control-plane enrollment + heartbeat HTTP client | `client.go`, `heartbeat.go` |
| `internal/identity` | Agent state persistence (agent_id, machine_id, host info) | `state.go` |
| `internal/service` | Main run-loop: enrollment retry → heartbeat ticker | `run.go` |

**Strengths of current code:**
- Clean, minimal, single-responsibility packages
- Proper signal handling (`SIGTERM`/`SIGINT`) with context cancellation
- Systemd integration with proper service unit
- DEB/RPM packaging pipeline already in place
- Enrollment token + heartbeat protocol established with control plane

**What needs to evolve:**
- `internal/service` is a monolithic run-loop — needs to become an orchestrator for N capabilities
- `internal/enroll` mixes control-plane communication with enrollment-specific logic
- No plugin/capability registration pattern
- No event/telemetry pipeline
- Config is flat — needs hierarchical structure for per-capability settings

---

## 2. EDR/XDR Security Capabilities Research

Based on deep analysis of **CrowdStrike Falcon**, **Elastic Defend**, **Microsoft Defender for Endpoint**, **Wazuh**, **SentinelOne**, and **Carbon Black**, here are the essential security capabilities grouped into **10 domains**:

### 2.1 Malware Prevention & Detection
| Sub-capability | Description | Reference |
|---|---|---|
| **Hash-based detection** | Match file SHA256/MD5 against known malware databases | Elastic, CrowdStrike |
| **YARA rule scanning** | Pattern-based static analysis using YARA rules | Elastic Defend, Wazuh |
| **Static file analysis** | Inspect PE/ELF headers, entropy, imports/exports for suspicious indicators | CrowdStrike, SentinelOne |
| **On-access scanning** | Real-time scanning on file open/write/execute (via `fanotify` on Linux) | All EDRs |
| **Quarantine vault** | Isolate malicious files in encrypted, non-executable storage | Elastic, CrowdStrike |
| **Allowlist/Blocklist** | Hash-based, path-based, or signer-based exception management | All EDRs |

### 2.2 Ransomware Prevention
| Sub-capability | Description | Reference |
|---|---|---|
| **Canary/honeypot files** | Deploy decoy files in key directories to detect encryption activity | CrowdStrike |
| **Mass file modification detection** | Detect rapid rename/modify/delete patterns across many files | Elastic, SentinelOne |
| **Entropy analysis** | Detect sudden entropy increase in modified files (encryption signal) | CrowdStrike |
| **MBR/VBR protection** | Prevent unauthorized modification of boot records | CrowdStrike, Carbon Black |
| **Shadow copy protection** | Detect/prevent deletion of volume shadow copies | All EDRs |
| **File backup & rollback** | Maintain shadow copies of critical files for rollback after attack | SentinelOne StoryLine |

### 2.3 Behavioral Detection & Analytics
| Sub-capability | Description | Reference |
|---|---|---|
| **Process behavior monitoring** | Track process trees, parent-child relationships, command-lines | All EDRs |
| **Behavioral rule engine** | Configurable rules matching process behavior patterns | Elastic EQL, SIGMA |
| **MITRE ATT&CK mapping** | Tag all detections with ATT&CK technique/tactic IDs | Elastic, CrowdStrike |
| **Anomaly detection** | Baseline normal behavior, detect statistical deviations | CrowdStrike, Darktrace |
| **Script/command-line analysis** | Detect obfuscated PowerShell, encoded bash, suspicious interpreters | Elastic, CrowdStrike |
| **LOLBin detection** | Detect abuse of legitimate system tools (curl, wget, python, etc.) | Elastic, LOLBAS Project |
| **Credential access detection** | Detect credential dumping, brute force, authentication abuse | CrowdStrike, Elastic |
| **Lateral movement detection** | Detect SSH tunneling, abnormal remote connections, pivoting | CrowdStrike |
| **Persistence detection** | Detect cron jobs, systemd services, shell profile modifications | Elastic, Wazuh |

### 2.4 Memory & Exploit Protection
| Sub-capability | Description | Reference |
|---|---|---|
| **Shellcode injection detection** | Detect code injection into running processes via `/proc/[pid]/mem` | CrowdStrike, Elastic |
| **Process hollowing detection** | Detect when a process image is replaced in memory | CrowdStrike |
| **DLL/SO injection detection** | Monitor `LD_PRELOAD`, `dlopen()`, `/proc/[pid]/maps` for suspicious loads | Elastic |
| **ptrace restriction** | Monitor and restrict `ptrace` calls used for process debugging/injection | Linux-specific |
| **Stack pivot detection** | Detect ROP (Return-Oriented Programming) chains | CrowdStrike |
| **JIT spray / heap spray** | Detect exploit techniques targeting heap memory | CrowdStrike |
| **Fileless malware detection** | Detect execution from `memfd_create`, `/dev/shm`, anonymous memory | Elastic, CrowdStrike |

### 2.5 Endpoint Visibility & Telemetry
| Sub-capability | Description | Reference |
|---|---|---|
| **Process monitoring** | Real-time process creation/termination (via eBPF, audit, or procfs) | All EDRs |
| **File integrity monitoring (FIM)** | Detect changes to critical system files and directories | Wazuh, Elastic |
| **Network connection monitoring** | Track all inbound/outbound TCP/UDP connections | All EDRs |
| **DNS query monitoring** | Log and analyze DNS queries for C2, DGA, exfiltration | CrowdStrike, Elastic |
| **User/session monitoring** | Track logons, logoffs, `su`/`sudo` usage, privilege changes | All EDRs |
| **Kernel module monitoring** | Detect loading/unloading of kernel modules (`insmod`/`modprobe`) | CrowdStrike, Elastic |
| **eBPF-based telemetry** | Kernel-level event collection with minimal overhead | Elastic Defend, Falco |
| **Syslog/auditd collection** | Forward system logs and audit trail | Wazuh |
| **Scheduled task monitoring** | Monitor cron, at, systemd timers for persistence | Elastic, Wazuh |

### 2.6 Active Response & Containment
| Sub-capability | Description | Reference |
|---|---|---|
| **Network isolation** | Isolate endpoint from LAN (keep control-plane connectivity) | CrowdStrike, Elastic |
| **Process kill/suspend** | Remotely terminate or freeze malicious processes | All EDRs |
| **File remediation** | Delete, quarantine, or restore files remotely | All EDRs |
| **Remote shell** | Execute commands on endpoint for incident response | CrowdStrike RTR |
| **Automated playbooks** | Rule-triggered automatic response actions | Elastic, SentinelOne |
| **Host firewall management** | Dynamic iptables/nftables rule injection | CrowdStrike, Wazuh |

### 2.7 Threat Intelligence
| Sub-capability | Description | Reference |
|---|---|---|
| **IoC matching** | Match file hashes, IPs, domains, URLs against IoC databases | All EDRs |
| **Threat feed ingestion** | Consume STIX/TAXII, MISP, OpenCTI feeds | Elastic, Wazuh |
| **Reputation scoring** | File/IP/domain reputation lookups via external services | CrowdStrike, Elastic |

### 2.8 Cloud & Container Security
| Sub-capability | Description | Reference |
|---|---|---|
| **Container runtime monitoring** | Docker, containerd, CRI-O event monitoring | Elastic, Falco |
| **Kubernetes audit logs** | K8s API server event collection | Elastic, Falco |
| **Container drift detection** | Detect runtime file changes vs. original image | CrowdStrike Falcon Cloud |
| **Cloud metadata collection** | AWS/GCP/Azure instance metadata, IAM, tags | CrowdStrike, Elastic |
| **Container image inventory** | Track running images, versions, layers | Elastic |

### 2.9 Compliance & Auditing
| Sub-capability | Description | Reference |
|---|---|---|
| **CIS benchmark scanning** | Check OS config against CIS benchmarks | Wazuh, Elastic |
| **Security configuration assessment** | SSH hardening, firewall rules, user mgmt checks | Wazuh SCA |
| **System hardening checks** | Verify ASLR, SELinux/AppArmor, permissions | Multiple |
| **Software inventory** | Track installed packages, versions, sources | Wazuh, Elastic |
| **Audit trail** | Immutable log of all agent actions and config changes | All EDRs |
| **Regulatory frameworks** | PCI DSS, HIPAA, SOC2, GDPR control mappings | Wazuh, Elastic |

### 2.10 Vulnerability Detection
| Sub-capability | Description | Reference |
|---|---|---|
| **CVE scanning** | Match installed packages against CVE databases | Wazuh, Elastic |
| **OS patch assessment** | Check for missing security updates | Wazuh |
| **Open port detection** | Identify listening services and exposed ports | Wazuh, Nessus |
| **Weak configuration detection** | Detect default credentials, insecure service configs | Wazuh SCA |

---

## 3. Proposed Architecture & Folder Structure

### Design Principles

1. **Capability-based architecture** — Each security domain is a self-contained capability that implements a common interface
2. **Plugin registry** — Capabilities register themselves; the agent orchestrator manages their lifecycle
3. **Event pipeline** — All capabilities emit events to a unified pipeline → shipped to control plane
4. **Platform abstraction** — OS-specific code isolated in `platform/` package
5. **Rules as data** — Detection rules stored as YAML/YARA files, loaded at runtime
6. **Configuration hierarchy** — Per-capability config sections within main config

### Complete Proposed Tree

```
xdr-agent/
├── cmd/
│   └── xdr-agent/
│       └── main.go                         # CLI entrypoint (expanded commands)
│
├── internal/
│   │
│   ├── agent/                              # ── CORE AGENT LIFECYCLE ──
│   │   ├── agent.go                        # Agent orchestrator — starts/stops all capabilities
│   │   ├── lifecycle.go                    # Startup, shutdown, reload, health-check
│   │   └── registry.go                     # Capability registration and dependency resolution
│   │
│   ├── buildinfo/                          # ── BUILD METADATA ── (exists)
│   │   └── version.go
│   │
│   ├── config/                             # ── CONFIGURATION ──
│   │   ├── config.go                       # Main config loader (expanded with capability sections)
│   │   ├── policy.go                       # Policy schema received from control plane
│   │   └── validate.go                     # Hierarchical config validation
│   │
│   ├── controlplane/                       # ── CONTROL PLANE COMMS ── (replaces enroll/)
│   │   ├── client.go                       # Shared HTTP client for all control-plane calls
│   │   ├── enroll.go                       # Enrollment logic (from current enroll/client.go)
│   │   ├── heartbeat.go                    # Heartbeat logic (from current enroll/heartbeat.go)
│   │   ├── policy.go                       # Policy pull/push sync with control plane
│   │   └── shipper.go                      # Event/alert/telemetry shipping to control plane
│   │
│   ├── identity/                           # ── AGENT IDENTITY ── (exists)
│   │   └── state.go                        # Agent state persistence
│   │
│   ├── events/                             # ── EVENT PIPELINE ──
│   │   ├── pipeline.go                     # Event bus: capabilities → enrichment → shipping
│   │   ├── event.go                        # Base event schema (ECS-compatible)
│   │   ├── alert.go                        # Alert/detection event schema
│   │   ├── enrichment.go                   # GeoIP, threat intel, MITRE ATT&CK enrichment
│   │   └── buffer.go                       # On-disk spooling when control plane unreachable
│   │
│   ├── capability/                         # ── CAPABILITY INTERFACE ──
│   │   └── capability.go                   # Interface: Name(), Init(), Start(), Stop(), Health()
│   │
│   │  ┌─────────────────────────────────────────────────────────────────┐
│   │  │              SECURITY CAPABILITY PACKAGES                       │
│   │  └─────────────────────────────────────────────────────────────────┘
│   │
│   ├── telemetry/                          # ── 1. ENDPOINT VISIBILITY & TELEMETRY ──
│   │   ├── manager.go                      # Telemetry capability manager
│   │   ├── process/
│   │   │   ├── monitor.go                  # Process creation/termination tracking
│   │   │   ├── tree.go                     # Process tree reconstruction
│   │   │   └── enrichment.go              # Process metadata (user, cwd, hashes, args)
│   │   ├── file/
│   │   │   ├── monitor.go                  # File system event monitoring (inotify/fanotify)
│   │   │   └── fim.go                      # File integrity monitoring (checksums of critical files)
│   │   ├── network/
│   │   │   ├── connections.go              # TCP/UDP connection tracking (/proc/net/tcp, netlink)
│   │   │   └── dns.go                      # DNS query logging
│   │   ├── session/
│   │   │   ├── monitor.go                  # User logon/logoff, su/sudo tracking
│   │   │   └── privilege.go               # Privilege escalation detection
│   │   ├── kernel/
│   │   │   ├── modules.go                  # Kernel module load/unload detection
│   │   │   └── ebpf.go                     # eBPF program management and event collection
│   │   ├── audit/
│   │   │   ├── collector.go               # auditd log parsing and forwarding
│   │   │   └── syslog.go                  # Syslog collection
│   │   └── scheduled/
│   │       └── tasks.go                    # Cron, at, systemd timer monitoring
│   │
│   ├── detection/                          # ── 2. DETECTION ENGINES ──
│   │   ├── engine.go                       # Detection orchestrator — feeds telemetry into rules
│   │   ├── alert.go                        # Alert generation and severity classification
│   │   │
│   │   ├── malware/                        # ── 2a. Malware Detection ──
│   │   │   ├── scanner.go                  # On-access & on-demand scan orchestrator
│   │   │   ├── hash.go                     # Hash-based detection (SHA256, MD5, fuzzy hashing)
│   │   │   ├── yara.go                     # YARA rule engine integration
│   │   │   └── static.go                   # Static analysis (ELF headers, entropy, strings)
│   │   │
│   │   ├── behavioral/                     # ── 2b. Behavioral Detection ──
│   │   │   ├── engine.go                   # Behavioral rule evaluation engine
│   │   │   ├── rules.go                    # Rule loading, parsing, and management
│   │   │   ├── ransomware.go              # Ransomware behavioral patterns
│   │   │   ├── persistence.go             # Persistence mechanism detection
│   │   │   ├── lolbin.go                   # Living-off-the-land binary abuse detection
│   │   │   ├── credential.go              # Credential access/dumping detection
│   │   │   ├── lateral.go                  # Lateral movement detection
│   │   │   └── script.go                   # Obfuscated/malicious script detection
│   │   │
│   │   ├── memory/                         # ── 2c. Memory & Exploit Detection ──
│   │   │   ├── scanner.go                  # Memory inspection orchestrator
│   │   │   ├── injection.go               # Shellcode/SO injection detection
│   │   │   ├── hollowing.go               # Process hollowing detection
│   │   │   ├── fileless.go                # Fileless malware (memfd_create, /dev/shm)
│   │   │   └── exploit.go                 # ROP, heap spray, stack pivot detection
│   │   │
│   │   └── threatintel/                    # ── 2d. Threat Intelligence ──
│   │       ├── matcher.go                  # IoC matching engine (hash, IP, domain, URL)
│   │       ├── feed.go                     # STIX/TAXII/MISP feed ingestion
│   │       └── reputation.go              # Reputation lookup service
│   │
│   ├── prevention/                         # ── 3. ACTIVE PREVENTION & BLOCKING ──
│   │   ├── manager.go                      # Prevention capability manager
│   │   │
│   │   ├── malware/
│   │   │   ├── blocker.go                  # Block execution of detected malware (fanotify deny)
│   │   │   └── quarantine.go              # Encrypted quarantine vault
│   │   │
│   │   ├── ransomware/
│   │   │   ├── shield.go                   # Ransomware prevention orchestrator
│   │   │   ├── canary.go                   # Canary/honeypot file deployment & monitoring
│   │   │   └── rollback.go                # File shadow-copy and rollback system
│   │   │
│   │   ├── exploit/
│   │   │   ├── guard.go                    # Exploit mitigation enforcement
│   │   │   └── ptrace.go                  # ptrace restriction via seccomp/BPF
│   │   │
│   │   └── allowlist/
│   │       └── manager.go                  # Allow/block list management (hash, path, signer)
│   │
│   ├── response/                           # ── 4. ACTIVE RESPONSE & CONTAINMENT ──
│   │   ├── manager.go                      # Response action manager
│   │   ├── isolate.go                      # Network isolation (iptables/nftables rules)
│   │   ├── kill.go                         # Process kill / suspend
│   │   ├── remediate.go                   # File remediation (delete, restore, quarantine)
│   │   ├── shell.go                        # Remote command execution (from control plane)
│   │   ├── firewall.go                    # Dynamic host firewall rule management
│   │   └── playbook.go                    # Automated response playbooks (rule → action chains)
│   │
│   ├── cloud/                              # ── 5. CLOUD & CONTAINER SECURITY ──
│   │   ├── metadata.go                     # Cloud provider metadata (AWS/GCP/Azure IMDSv2)
│   │   ├── container/
│   │   │   ├── runtime.go                  # Docker/containerd/CRI-O event monitoring
│   │   │   ├── drift.go                    # Container drift detection (runtime vs. image)
│   │   │   └── inventory.go               # Running container/image inventory
│   │   └── kubernetes/
│   │       ├── audit.go                    # Kubernetes audit log collection
│   │       └── pods.go                     # Pod security context monitoring
│   │
│   ├── compliance/                         # ── 6. COMPLIANCE & AUDITING ──
│   │   ├── manager.go                      # Compliance check orchestrator
│   │   ├── cis.go                          # CIS benchmark scanning
│   │   ├── sca.go                          # Security Configuration Assessment
│   │   ├── hardening.go                   # System hardening verification (ASLR, permissions, etc.)
│   │   ├── inventory.go                   # Software/package inventory
│   │   └── audit_trail.go                 # Immutable agent action audit log
│   │
│   ├── vulnerability/                      # ── 7. VULNERABILITY DETECTION ──
│   │   ├── scanner.go                      # Vulnerability scan orchestrator
│   │   ├── cve.go                          # CVE database matching
│   │   ├── packages.go                    # Installed package enumeration (dpkg, rpm, apk)
│   │   ├── patches.go                     # OS patch level assessment
│   │   └── ports.go                        # Open port / listening service detection
│   │
│   └── platform/                           # ── OS/PLATFORM ABSTRACTION ──
│       ├── linux/
│       │   ├── procfs.go                   # /proc filesystem utilities
│       │   ├── fanotify.go                # fanotify file access notification
│       │   ├── inotify.go                 # inotify file change notification
│       │   ├── netlink.go                 # Netlink socket (process events, network)
│       │   ├── auditd.go                  # auditd rule management and log parsing
│       │   ├── ebpf.go                     # eBPF program loading and management
│       │   ├── seccomp.go                 # seccomp-BPF filter management
│       │   └── cgroups.go                 # cgroup monitoring for container awareness
│       └── common/
│           ├── fs.go                       # Cross-platform file utilities
│           ├── process.go                 # Cross-platform process utilities
│           └── hash.go                     # File hashing (SHA256, MD5, fuzzy)
│
├── pkg/                                    # ── PUBLIC PACKAGES (importable) ──
│   ├── eventschema/
│   │   ├── event.go                        # Base event schema (ECS-compatible)
│   │   ├── process.go                     # Process event fields
│   │   ├── file.go                         # File event fields
│   │   ├── network.go                     # Network event fields
│   │   └── alert.go                        # Alert/detection fields
│   └── ruleformat/
│       ├── rule.go                         # Rule definition format
│       └── sigma.go                        # SIGMA rule parser
│
├── rules/                                  # ── DEFAULT DETECTION RULES (data files) ──
│   ├── behavioral/
│   │   ├── ransomware.yml                 # Ransomware behavioral patterns
│   │   ├── credential_access.yml          # Credential dumping/theft rules
│   │   ├── persistence.yml                # Persistence mechanism rules
│   │   ├── lateral_movement.yml           # Lateral movement rules
│   │   ├── defense_evasion.yml            # Defense evasion rules
│   │   └── execution.yml                  # Suspicious execution rules
│   ├── malware/
│   │   ├── known_hashes.yml               # Known malware hash blocklist
│   │   └── yara/
│   │       ├── linux_elf_malware.yar      # Linux ELF malware signatures
│   │       ├── webshells.yar              # Web shell detection
│   │       ├── cryptominers.yar           # Cryptominer detection
│   │       └── rootkits.yar               # Rootkit signatures
│   ├── compliance/
│   │   ├── cis_debian_linux.yml           # CIS benchmarks — Debian/Ubuntu
│   │   ├── cis_rhel_linux.yml             # CIS benchmarks — RHEL/CentOS
│   │   ├── ssh_hardening.yml              # SSH configuration checks
│   │   └── system_hardening.yml           # General hardening checks
│   └── threatintel/
│       └── README.md                       # Instructions for threat feed integration
│
├── config/                                 # ── CONFIGURATION ──
│   └── config.json                         # Default agent configuration
│
├── packaging/                              # ── PACKAGING (exists) ──
│   ├── bash_completion/
│   │   └── xdr-agent
│   ├── build_multi_arch.sh
│   ├── deb/
│   │   ├── build.sh
│   │   ├── postinst
│   │   └── prerm
│   ├── rpm/
│   │   ├── build.sh
│   │   └── xdr-agent.spec.template
│   └── systemd-preset/
│
├── systemd/                                # ── SYSTEMD (exists) ──
│   └── xdr-agent.service
│
├── docs/                                   # ── DOCUMENTATION ──
│   ├── architecture.md                    # High-level architecture overview
│   ├── event-pipeline.md                  # Event flow: telemetry → detection → shipping
│   ├── capabilities/
│   │   ├── 01-endpoint-visibility.md
│   │   ├── 02-malware-prevention.md
│   │   ├── 03-ransomware-prevention.md
│   │   ├── 04-behavioral-detection.md
│   │   ├── 05-memory-exploit-protection.md
│   │   ├── 06-active-response.md
│   │   ├── 07-threat-intelligence.md
│   │   ├── 08-cloud-container.md
│   │   ├── 09-compliance-auditing.md
│   │   └── 10-vulnerability-detection.md
│   └── development/
│       ├── adding-capability.md           # How to add a new capability
│       ├── rule-format.md                 # Detection rule authoring guide
│       └── event-schema.md                # Event schema reference
│
├── test/                                   # ── TESTS ──
│   ├── integration/                       # Integration tests
│   └── fixtures/                          # Test data and mock payloads
│
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── VERSION
└── .gitignore
```

---

## 4. Capability Detail Breakdown

### 4.1 Core Agent (`internal/agent/`)

Replaces the current `internal/service/` with a proper orchestrator:

```go
// internal/capability/capability.go
type Capability interface {
    Name() string                            // e.g. "telemetry.process", "detection.malware"
    Init(cfg config.Config, bus *events.Pipeline) error
    Start(ctx context.Context) error
    Stop() error
    Health() HealthStatus
}
```

```go
// internal/agent/agent.go
type Agent struct {
    cfg          config.Config
    identity     identity.State
    pipeline     *events.Pipeline
    capabilities []capability.Capability
    controlplane *controlplane.Client
}

func (a *Agent) Run(ctx context.Context) error {
    // 1. Load config
    // 2. Ensure identity
    // 3. Start event pipeline
    // 4. Enroll with control plane
    // 5. Register and start all capabilities
    // 6. Run heartbeat + policy sync loop
    // 7. Graceful shutdown on context cancellation
}
```

### 4.2 Event Pipeline (`internal/events/`)

Central nervous system — all capabilities emit events here:

```
┌────────────┐    ┌────────────┐    ┌────────────┐
│  Telemetry │    │ Detection  │    │ Compliance │
│ Collectors │    │  Engines   │    │  Scanners  │
└─────┬──────┘    └─────┬──────┘    └─────┬──────┘
      │                 │                 │
      ▼                 ▼                 ▼
  ┌──────────────────────────────────────────┐
  │            Event Pipeline                 │
  │  ┌──────────┐  ┌───────────┐  ┌────────┐│
  │  │ Enrichment│→│  Filtering │→│ Buffer  ││
  │  └──────────┘  └───────────┘  └────────┘│
  └──────────────────────┬───────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   Control Plane     │
              │   (Event Shipper)   │
              └─────────────────────┘
```

### 4.3 Telemetry (`internal/telemetry/`)

**Endpoint visibility** is the foundation — all other capabilities depend on telemetry data:

| Sub-package | Linux Implementation | Key Syscalls/APIs |
|---|---|---|
| `process/` | eBPF `tracepoint/sched/sched_process_exec`, `/proc` fallback | `execve`, `fork`, `exit` |
| `file/` | `fanotify` for access events, `inotify` for change events | `fanotify_init`, `inotify_add_watch` |
| `network/` | Netlink `SOCK_DIAG`, `/proc/net/tcp`, eBPF `kprobe/tcp_connect` | `connect`, `accept`, `bind` |
| `session/` | `utmp`/`wtmp` parsing, PAM module events, auditd | `setuid`, `setgid` |
| `kernel/` | `kprobe/do_init_module`, `/proc/modules` monitoring | `init_module`, `finit_module` |
| `audit/` | Auditd netlink socket, syslog file tailing | `audit_open`, `audit_add_rule` |
| `scheduled/` | inotify on `/etc/cron*`, `/etc/systemd/system/` | file watches |

### 4.4 Detection Engines (`internal/detection/`)

Detection consumes telemetry events and produces alerts:

| Engine | Input | Output | Technique |
|---|---|---|---|
| `malware/` | File write/exec events | Malware alert | Hash match, YARA, static analysis |
| `behavioral/` | Process, file, network events | Behavior alert | Rule engine (SIGMA-like) |
| `memory/` | Process events, `/proc` data | Exploit alert | Memory scanning, injection detection |
| `threatintel/` | All events with IoC fields | IoC match alert | Hash/IP/domain matching |

### 4.5 Prevention (`internal/prevention/`)

Prevention **blocks** threats in real-time (vs. detection which only alerts):

| Module | Mechanism | Linux API |
|---|---|---|
| `malware/blocker.go` | Block file execution | `fanotify` with `FAN_DENY` |
| `malware/quarantine.go` | Move to encrypted vault | File rename + encrypt |
| `ransomware/canary.go` | Deploy + monitor honeypot files | `inotify` on decoy files |
| `ransomware/rollback.go` | Shadow copies of modified files | Copy-on-write, `btrfs` snapshots |
| `exploit/ptrace.go` | Restrict ptrace | Seccomp-BPF filters |
| `allowlist/` | Skip scanning for trusted items | In-memory hash set |

### 4.6 Response (`internal/response/`)

Remote actions triggered by control plane or automated playbooks:

| Action | Implementation |
|---|---|
| `isolate.go` | Insert `iptables`/`nftables` rules allowing only control-plane IP |
| `kill.go` | `syscall.Kill(pid, SIGKILL)` with process tree traversal |
| `remediate.go` | Delete, quarantine, or restore files from backup |
| `shell.go` | Execute shell commands, stream output back |
| `firewall.go` | Dynamic firewall rule management |
| `playbook.go` | JSON-defined action chains triggered by alert rules |

### 4.7 Cloud & Container (`internal/cloud/`)

| Module | Implementation |
|---|---|
| `metadata.go` | HTTP to IMDSv2 (169.254.169.254), GCP metadata server |
| `container/runtime.go` | Docker socket `/var/run/docker.sock`, containerd gRPC |
| `container/drift.go` | Compare running FS against image layers |
| `kubernetes/audit.go` | K8s audit webhook or log file tailing |

### 4.8 Compliance & Vulnerability

`internal/compliance/` — Periodic configuration checks:
- CIS benchmarks parsed from YAML rule files
- SCA checks (SSH, firewall, permissions, users)
- Software inventory via package managers

`internal/vulnerability/` — CVE scanning:
- Enumerate installed packages (`dpkg -l`, `rpm -qa`, `apk list`)
- Match against CVE database (NVD, OSV)
- Report severity, affected package, fix version

---

## 5. Migration Path from Current Code

| Current | New Location | Changes |
|---|---|---|
| `internal/service/run.go` | `internal/agent/agent.go` + `lifecycle.go` | Split into orchestrator + lifecycle; add capability loop |
| `internal/enroll/client.go` | `internal/controlplane/enroll.go` | Move to controlplane package, extract shared HTTP client |
| `internal/enroll/heartbeat.go` | `internal/controlplane/heartbeat.go` | Same logic, shared client |
| `internal/config/config.go` | `internal/config/config.go` | Expand with per-capability config sections |
| `internal/identity/state.go` | `internal/identity/state.go` | **No change** — stays as-is |
| `internal/buildinfo/version.go` | `internal/buildinfo/version.go` | **No change** — stays as-is |
| `cmd/xdr-agent/main.go` | `cmd/xdr-agent/main.go` | Expand CLI commands (status, isolate, scan, etc.) |

---

## 6. Capability Registry Pattern

The agent discovers and starts capabilities via a registry:

```go
// internal/agent/registry.go
package agent

import "xdr-agent/internal/capability"

var defaultCapabilities = []func() capability.Capability{
    // Core (always enabled)
    telemetry.NewProcessMonitor,
    telemetry.NewFileMonitor,
    telemetry.NewNetworkMonitor,

    // Detection (enabled by policy)
    detection.NewMalwareScanner,
    detection.NewBehavioralEngine,
    detection.NewMemoryScanner,
    detection.NewThreatIntelMatcher,

    // Prevention (enabled by policy)
    prevention.NewMalwareBlocker,
    prevention.NewRansomwareShield,
    prevention.NewExploitGuard,

    // Response (always available, triggered remotely)
    response.NewManager,

    // Periodic checks
    compliance.NewManager,
    vulnerability.NewScanner,

    // Cloud (auto-detected)
    cloud.NewMetadataCollector,
    cloud.NewContainerMonitor,
}
```

Each capability is enabled/disabled via **policy** from the control plane:

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

---

## 7. Implementation Priority

### Phase 1 — Foundation (Current → v0.2.0)
1. Restructure into `agent/`, `controlplane/`, `capability/`, `events/` packages
2. Implement capability interface and registry
3. Build event pipeline (in-memory bus → control plane shipper)
4. Expand config for hierarchical per-capability settings
5. Migrate enrollment + heartbeat into `controlplane/`

### Phase 2 — Endpoint Visibility (v0.3.0)
6. `telemetry/process/` — Process monitoring via procfs + netlink
7. `telemetry/file/` — File integrity monitoring via inotify
8. `telemetry/network/` — Network connection tracking
9. `telemetry/session/` — User session monitoring
10. `platform/linux/` — Linux-specific syscall wrappers

### Phase 3 — Detection (v0.4.0)
11. `detection/malware/` — Hash-based + YARA scanning
12. `detection/behavioral/` — Rule engine + initial rule set
13. `detection/threatintel/` — IoC matching

### Phase 4 — Prevention (v0.5.0)
14. `prevention/malware/` — fanotify-based blocking + quarantine
15. `prevention/ransomware/` — Canary files + behavioral shield
16. `prevention/exploit/` — ptrace + memory protection

### Phase 5 — Response & Cloud (v0.6.0)
17. `response/` — Network isolation, process kill, remote shell
18. `cloud/` — Container monitoring, cloud metadata

### Phase 6 — Compliance & Vuln (v0.7.0)
19. `compliance/` — CIS benchmarks, SCA, hardening
20. `vulnerability/` — CVE scanning, package inventory

### Phase 7 — Advanced (v0.8.0+)
21. `detection/memory/` — Memory scanning, exploit detection
22. `telemetry/kernel/` — eBPF-based deep telemetry
23. Automated response playbooks
24. SIGMA rule parser

---

## Comparison with Industry Leaders

| Capability Domain | CrowdStrike Falcon | Elastic Defend | Our XDR Agent (Proposed) |
|---|---|---|---|
| Malware Prevention | ✅ ML + IoA | ✅ ML + YARA | ✅ YARA + Hash + Static |
| Ransomware Protection | ✅ Behavioral | ✅ Behavioral | ✅ Canary + Behavioral |
| Behavioral Detection | ✅ IoA Engine | ✅ EQL Rules | ✅ SIGMA-like Rule Engine |
| Memory Protection | ✅ Deep | ✅ Basic | ✅ Injection + Fileless |
| Endpoint Visibility | ✅ Full | ✅ Full | ✅ Process + File + Net + Session |
| Active Response | ✅ RTR | ✅ Basic | ✅ Isolate + Kill + Shell |
| Threat Intelligence | ✅ Built-in | ✅ Elastic TI | ✅ STIX/TAXII + IoC |
| Cloud/Container | ✅ Cloud Workload | ✅ Cloud Defend | ✅ Container + K8s |
| Compliance | ❌ Separate | ✅ CSPM | ✅ CIS + SCA |
| Vulnerability | ❌ Spotlight | ✅ Basic | ✅ CVE + Packages |
| Open Source | ❌ Proprietary | ⚠️ Partial | ✅ Fully open |

---

*This proposal provides a complete roadmap from the current identity-only agent to a full-featured XDR endpoint agent competitive with industry leaders.*
