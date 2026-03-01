# xdr-agent

Modular XDR endpoint security agent for Linux, written in Go.

Provides identity and enrollment (working today), with a full capability-based
architecture scaffolded for threat detection, prevention, active response,
compliance, and cloud/container security.

## Security capabilities

| Domain | Status | Description |
|---|---|---|
| **Identity & Enrollment** | ✅ Working | Agent ID, machine fingerprint, control-plane enrollment, heartbeat |
| **Telemetry** | 🔲 Scaffolded | Process, file, network, session, kernel module, and audit monitoring |
| **Malware Detection** | 🔲 Scaffolded | YARA rules, hash matching, static analysis |
| **Behavioral Detection** | 🔲 Scaffolded | SIGMA-like rules for ransomware, credential access, persistence, lateral movement |
| **Memory & Exploit** | 🔲 Scaffolded | Process injection, hollowing, fileless malware, ASLR/NX enforcement |
| **Threat Intelligence** | 🔲 Scaffolded | IoC feeds, hash/IP/domain reputation matching |
| **Malware Prevention** | 🔲 Scaffolded | fanotify-based exec blocking, quarantine vault |
| **Ransomware Prevention** | 🔲 Scaffolded | Canary files, entropy detection, automatic rollback |
| **Active Response** | 🔲 Scaffolded | Network isolation, process kill, file remediation, remote shell, playbooks |
| **Cloud & Container** | 🔲 Scaffolded | Docker/containerd/CRI-O monitoring, Kubernetes audit, drift detection |
| **Compliance** | 🔲 Scaffolded | CIS benchmarks, SCA, hardening checks, software inventory |
| **Vulnerability** | 🔲 Scaffolded | CVE matching, package scanning, open port audit |

## Project layout

```
xdr-agent/
├── cmd/xdr-agent/              # CLI entrypoint (run, enroll, remove, version)
├── internal/
│   ├── agent/                  # Central orchestrator, capability registry, lifecycle
│   ├── buildinfo/              # Build version injection
│   ├── capability/             # Capability interface (Init/Start/Stop/Health)
│   ├── config/                 # JSON config loader, validation, policy schema
│   ├── controlplane/           # Control-plane HTTP client (enroll, heartbeat, policy, shipper)
│   ├── enroll/                 # Current enrollment + heartbeat implementation
│   ├── events/                 # Event pipeline (emit → enrich → filter → buffer → ship)
│   ├── identity/               # Agent identity and local state persistence
│   ├── service/                # Current runtime loop (enrollment retry + heartbeat)
│   ├── telemetry/              # Endpoint visibility
│   │   ├── process/            #   Process creation/termination, process tree
│   │   ├── file/               #   File integrity monitoring (FIM)
│   │   ├── network/            #   TCP/UDP connections, DNS queries
│   │   ├── session/            #   User logon/logoff, privilege escalation
│   │   ├── kernel/             #   Kernel module loads, eBPF program monitoring
│   │   ├── audit/              #   Auditd/syslog collection
│   │   └── scheduled/          #   Cron/systemd timer monitoring
│   ├── detection/              # Threat detection engines
│   │   ├── malware/            #   YARA, hash, static analysis scanners
│   │   ├── behavioral/         #   Rule-based behavioral detection (ransomware, cred access, etc.)
│   │   ├── memory/             #   Injection, hollowing, fileless, exploit detection
│   │   └── threatintel/        #   IoC feed ingestion and matching
│   ├── prevention/             # Real-time threat blocking
│   │   ├── malware/            #   fanotify exec blocker, quarantine vault
│   │   ├── ransomware/         #   Canary files, entropy shield, rollback
│   │   ├── exploit/            #   ASLR/NX/ptrace enforcement
│   │   └── allowlist/          #   Exclusion management
│   ├── response/               # Active response (isolate, kill, remediate, shell, playbooks)
│   ├── cloud/                  # Cloud & container security
│   │   ├── container/          #   Docker/containerd/CRI-O runtime, drift, inventory
│   │   └── kubernetes/         #   K8s audit log, pod security
│   ├── compliance/             # CIS benchmarks, SCA, hardening, software inventory
│   ├── vulnerability/          # CVE matching, package scanning, open ports
│   └── platform/               # OS abstraction layer
│       ├── linux/              #   procfs, fanotify, inotify, netlink, eBPF, seccomp, cgroups, auditd
│       └── common/             #   Cross-platform filesystem, process, hash helpers
├── pkg/                        # Public Go packages (importable by external tools)
│   ├── eventschema/            #   ECS-compatible event schema (Event, Process, File, Network, Alert)
│   └── ruleformat/             #   Detection rule parsing (SIGMA-like YAML)
├── rules/                      # Detection and compliance rule files
│   ├── behavioral/             #   SIGMA-like YAML rules (ransomware, persistence, etc.)
│   ├── malware/                #   Known hash lists + YARA rules
│   │   └── yara/               #     .yar files (ELF malware, webshells, cryptominers, rootkits)
│   ├── compliance/             #   CIS/hardening check definitions
│   └── threatintel/            #   Threat intel feed configuration
├── config/                     # Default configuration files
│   └── config.json             #   Sample agent config
├── docs/                       # Project documentation
│   ├── architecture.md         #   Architecture overview and diagrams
│   ├── event-pipeline.md       #   Event pipeline design
│   └── development/
│       └── adding-capability.md  # Guide: how to add a new capability
├── test/                       # Integration tests and fixtures
│   ├── integration/
│   └── fixtures/
├── packaging/                  # OS package build scripts
│   ├── deb/                    #   Debian package builder + maintainer scripts
│   ├── rpm/                    #   RPM spec + build script
│   ├── bash_completion/        #   Shell completion snippet
│   ├── systemd-preset/         #   systemd preset for auto-enable
│   └── build_multi_arch.sh     #   Multi-arch packaging orchestrator
├── systemd/                    # systemd service unit
├── Makefile                    # Build, run, package targets
├── VERSION                     # Semantic version (e.g. 0.1.0)
└── go.mod                      # Go module definition
```

## Prerequisites

- **Go 1.22+** (`go version`)
- **Linux** (agent uses Linux-specific APIs: procfs, fanotify, netlink, eBPF)
- `dpkg-deb` for Debian packaging (part of `dpkg`)
- `rpm` / `rpmbuild` for RPM packaging

Install Go on Debian/Ubuntu:

```bash
sudo apt-get update && sudo apt-get install -y golang-go
```

## Build

```bash
cd xdr-agent
make build
```

This compiles the binary to `dist/xdr-agent` with version from the `VERSION` file
injected via `-ldflags`.

Verify:

```bash
./dist/xdr-agent version
# 0.1.0
```

Override version without editing `VERSION`:

```bash
make build VERSION=0.2.0
```

## Run

### Development (foreground)

```bash
make run
# equivalent to: ./dist/xdr-agent run --config ./config/config.json
```

### One-shot enrollment

```bash
./dist/xdr-agent enroll <enrollment_token> --config ./config/config.json
```

Exits after a single enrollment attempt. Use this to verify control-plane
connectivity before starting the long-running service.

### Long-running mode

```bash
./dist/xdr-agent run --config ./config/config.json
```

The agent will:
1. Load config and ensure agent identity.
2. Attempt enrollment (retry every `enroll_interval_seconds` until successful).
3. Send heartbeats every 30 seconds.
4. Shut down gracefully on `SIGTERM` or `SIGINT`.

### With make

```bash
# Run in foreground (builds first):
make run

# Enroll and exit:
make enroll ENROLLMENT_TOKEN=<token>
```

## Configuration

Default path: `/etc/xdr-agent/config.json`

Sample: `config/config.json`

```json
{
  "control_plane_url": "http://localhost:5601",
  "enrollment_path": "/api/v1/agents/enroll",
  "heartbeat_path": "/api/v1/agents/heartbeat",
  "enrollment_token": "",
  "policy_id": "default-endpoint",
  "tags": ["linux", "xdr-agent"],
  "enroll_interval_seconds": 30,
  "request_timeout_seconds": 10,
  "state_path": "/var/lib/xdr-agent/state.json",
  "insecure_skip_tls_verify": false,
  "telemetry_url": "",
  "telemetry_path": "/api/v1/agents/telemetry",
  "telemetry_interval_seconds": 60,
  "telemetry_ship_interval_seconds": 1
}
```

| Field | Required | Description |
|---|---|---|
| `control_plane_url` | Yes | XDR manager URL (e.g. `https://xdr-manager.example.com`) |
| `enrollment_path` | Yes | Enrollment API path |
| `heartbeat_path` | No | Heartbeat API path (default: `/api/v1/agents/heartbeat`) |
| `enrollment_token` | No | Bearer token for enrollment auth |
| `policy_id` | Yes | Security policy to apply |
| `tags` | No | Agent tags for grouping |
| `enroll_interval_seconds` | Yes | Retry interval for enrollment (> 0) |
| `request_timeout_seconds` | Yes | HTTP request timeout (> 0) |
| `state_path` | Yes | Path to persist agent identity state |
| `insecure_skip_tls_verify` | No | Skip TLS verification (keep `false` in prod) |
| `telemetry_url` | No | Telemetry shipping URL; defaults to `control_plane_url`. Set to route through Kafka, Logstash, etc. |
| `telemetry_path` | No | Telemetry API path (default: `/api/v1/agents/telemetry`) |
| `telemetry_interval_seconds` | No | Telemetry collection interval in seconds (default: `60`) |
| `telemetry_ship_interval_seconds` | No | Max linger before shipping buffered events (default: `1`). Events also ship immediately on arrival. |

## CLI commands

```
xdr-agent run        Run the long-lived agent process
xdr-agent enroll     Perform one enrollment attempt and exit
xdr-agent remove     Remove xdr-agent files and systemd service (requires root)
xdr-agent version    Print build version
xdr-agent completion bash   Output bash completion script
xdr-agent help       Show usage information
```

## Packaging

### Debian (.deb)

```bash
chmod +x packaging/deb/build.sh packaging/deb/postinst packaging/deb/prerm
make clean; make deb
ls -lh dist/*.deb
```

By default, staging directories are removed. To keep them for inspection/debugging:

```bash
make deb KEEP_STAGING=1
```

### RPM

```bash
sudo apt install rpm   # if building on Debian/Ubuntu
chmod +x packaging/rpm/build.sh
make rpm
```

### Multi-architecture (amd64 + arm64, deb + rpm)

```bash
chmod +x packaging/build_multi_arch.sh
bash ./packaging/build_multi_arch.sh "$(cat VERSION)"
```

Customize:

```bash
ARCHES="amd64 arm64" FORMATS="deb rpm" bash ./packaging/build_multi_arch.sh
```

## Install on Debian/Ubuntu

```bash
sudo dpkg -i dist/xdr-agent_$(cat VERSION)_amd64.deb
```

The package does **not** auto-start the service. Recommended flow:

1. Edit `/etc/xdr-agent/config.json` with your `control_plane_url`, `policy_id`, and `enrollment_token`.
2. Enroll:
   ```bash
   sudo xdr-agent enroll <token> --config /etc/xdr-agent/config.json
   ```
  On successful enrollment, this command automatically runs `systemctl enable xdr-agent` and `systemctl start xdr-agent`.
3. Verify:
   ```bash
   sudo systemctl status xdr-agent --no-pager -l
   sudo journalctl -u xdr-agent -f
   ```

## Update xdr-agent to latest version:
```bash
sudo systemctl stop xdr-agent.service
make clean; make deb
sudo dpkg -i dist/xdr-agent_$(cat VERSION)_amd64.deb
sudo systemctl start xdr-agent.service
sudo journalctl -u xdr-agent -f
```

## Bash completion

After `.deb` installation, completion is installed at `/usr/share/bash-completion/completions/xdr-agent` and is auto-loaded by `bash-completion` in new shell sessions.

From a local build:

```bash
source <(./dist/xdr-agent completion bash)
```

Supports `xdr-agent <TAB>` and `sudo xdr-agent <TAB>`.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full architecture overview
with diagrams, data flow, and design decisions.

See [docs/event-pipeline.md](docs/event-pipeline.md) for event pipeline design.

See [docs/development/adding-capability.md](docs/development/adding-capability.md)
for a step-by-step guide on adding new security capabilities.

### Capability interface

Every security module implements:

```go
type Capability interface {
    Name() string                       // e.g. "telemetry.process"
    Init(deps Dependencies) error       // receive config, pipeline, logger
    Start(ctx context.Context) error    // begin monitoring
    Stop() error                        // graceful shutdown
    Health() HealthStatus               // running, degraded, failed, etc.
}
```

The agent orchestrator manages all capability lifecycles, starts them in
dependency order, and stops them in reverse order on shutdown.

## Control-plane compatibility

### Enrollment request

```json
{
  "agent_id": "...",
  "machine_id": "...",
  "hostname": "...",
  "architecture": "amd64",
  "os_type": "linux",
  "ip_addresses": ["10.0.0.12"],
  "policy_id": "default-endpoint",
  "tags": ["linux", "xdr-agent"],
  "agent_version": "0.1.0"
}
```

### Expected response

```json
{
  "enrollment_id": "server-generated-id",
  "message": "enrolled"
}
```

### OpenSearch Dashboards xdr-manager-plugin

1. Generate an enrollment token from the plugin UI (**Enroll XDR** flyout).
2. Set `control_plane_url` to OpenSearch Dashboards (default: `http://localhost:5601`).
3. Set `enrollment_path` to `/api/v1/agents/enroll`.
4. Set `enrollment_token` to the generated token.
5. Set `policy_id` to match the token's policy.
6. Set `heartbeat_path` to `/api/v1/agents/heartbeat`.

## Troubleshooting

| Problem | Solution |
|---|---|
| `go: command not found` | `sudo apt-get install -y golang-go` |
| Service not found after install | `sudo systemctl daemon-reload` |
| Enrollment rejected | Verify `enrollment_token` and `policy_id` match the control plane |
| Config file not found | Check path with `--config` flag; default is `/etc/xdr-agent/config.json` |

## License

Copyright (C) 2026  Diego A. Guillen-Rosaperez

This program is free software: you can redistribute it and/or modify it under
the terms of the **GNU Affero General Public License v3.0** as published by the
Free Software Foundation.

See [LICENSE](LICENSE) for the full text.
