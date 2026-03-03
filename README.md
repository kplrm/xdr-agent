# xdr-agent

Modular XDR endpoint security agent for Linux, written in Go.

Provides agent identity, control-plane enrollment, and **comprehensive endpoint
telemetry** (13 active collectors) with a capability-based architecture scaffolded
for detection, prevention, response, compliance, and cloud security.

## Current status — v0.3.1

| Domain | Status | Description |
|---|---|---|
| **Identity & Enrollment** | ✅ Working | Agent ID, machine fingerprint, control-plane enrollment, heartbeat |
| **Telemetry — Process** | ✅ Working | Process lifecycle (start/end), 30+ fields, ancestry tree, env vars, script content |
| **Telemetry — File** | ✅ Working | FIM (inotify + BoltDB baseline + SHA-256 + entropy), file access monitoring |
| **Telemetry — Network** | ✅ Working | TCP/UDP connections (Community ID, PID enrichment), DNS query/response |
| **Telemetry — Session** | ✅ Working | utmp logon/logoff, auth log (SSH, sudo, su) |
| **Telemetry — System** | ✅ Working | CPU, memory, disk I/O, network I/O combined metrics |
| **Telemetry — Library** | ✅ Working | Shared object loading, LD_PRELOAD detection |
| **Telemetry — Kernel** | ✅ Working | Kernel module load/unload (rootkit detection) |
| **Telemetry — TTY** | ✅ Working | Terminal session start/end detection |
| **Telemetry — Scheduled** | ✅ Working | Cron/systemd timer monitoring (persistence detection) |
| **Telemetry — Injection** | ✅ Working | ptrace attach, anonymous executable memory regions |
| **Telemetry — IPC** | ✅ Working | Unix domain sockets, named pipe creation |
| **Event Pipeline** | ✅ Working | ECS events → enrichment → batched gzip shipping to OpenSearch |
| **Detection** | 🔲 Scaffolded | YARA, hash matching, behavioral rules, memory, threat intel (Phase 3) |
| **Prevention** | 🔲 Scaffolded | fanotify blocking, ransomware shield, exploit mitigation (Phase 4) |
| **Response** | 🔲 Scaffolded | Network isolation, process kill, remote shell, playbooks (Phase 5) |
| **Cloud & Container** | 🔲 Scaffolded | Docker/containerd monitoring, K8s audit, drift detection (Phase 5) |
| **Compliance** | 🔲 Scaffolded | CIS benchmarks, SCA, hardening, software inventory (Phase 6) |
| **Vulnerability** | 🔲 Scaffolded | CVE matching, package scanning, open port audit (Phase 6) |

## Project layout

```
xdr-agent/
├── cmd/xdr-agent/              # CLI entrypoint (run, enroll, remove, version, completion)
├── internal/
│   ├── agent/                  # Orchestrator and lifecycle helpers
│   ├── buildinfo/              # Build version injection via -ldflags
│   ├── capability/             # Capability interface (Init/Start/Stop/Health)
│   ├── config/                 # JSON config loader with defaults
│   ├── controlplane/           # HTTP client wrapper + telemetry shipper
│   ├── enroll/                 # Enrollment + heartbeat HTTP client
│   ├── events/                 # Event pipeline, Event/Alert structs, enrichment
│   ├── identity/               # Agent identity and local state persistence
│   ├── service/                # Main runtime loop (wires all telemetry collectors)
│   ├── telemetry/              # 13 active telemetry collectors
│   │   ├── process/            #   Process lifecycle, tree, env vars, script capture
│   │   ├── file/               #   FIM (inotify + BoltDB) + file access monitoring
│   │   ├── network/            #   TCP/UDP connections + DNS (AF_PACKET)
│   │   ├── session/            #   utmp + auth log (SSH, sudo, su)
│   │   ├── system/             #   CPU, memory, disk I/O, network I/O
│   │   ├── library/            #   Shared object (SO) loading detection
│   │   ├── kernel/             #   Kernel module load/unload
│   │   ├── tty/                #   Terminal session monitoring
│   │   ├── scheduled/          #   Cron/systemd timer monitoring
│   │   ├── injection/          #   ptrace / process injection detection
│   │   ├── ipc/                #   Unix sockets + named pipe monitoring
│   │   └── script/             #   Script content capture utility
│   ├── detection/              # [Phase 3] Threat detection engines
│   │   ├── malware/            #   YARA, hash, static analysis
│   │   ├── behavioral/         #   SIGMA-like rule engine
│   │   ├── memory/             #   Injection, hollowing, fileless, exploits
│   │   └── threatintel/        #   IoC feeds, reputation matching
│   ├── prevention/             # [Phase 4] Real-time threat blocking
│   │   ├── malware/            #   fanotify exec blocker, quarantine
│   │   ├── ransomware/         #   Canary files, rollback, shield
│   │   ├── exploit/            #   ptrace restriction, ASLR/NX
│   │   └── allowlist/          #   Exclusion management
│   ├── response/               # [Phase 5] Active response actions
│   ├── cloud/                  # [Phase 5] Cloud & container security
│   │   ├── container/          #   Docker/containerd/CRI-O, drift, inventory
│   │   └── kubernetes/         #   K8s audit, pod security
│   ├── compliance/             # [Phase 6] CIS benchmarks, SCA, hardening
│   ├── vulnerability/          # [Phase 6] CVE matching, packages, ports
│   └── platform/               # OS abstraction layer
│       ├── linux/              #   eBPF, fanotify, seccomp, cgroups (scaffolded)
│       └── common/             #   File hashing (SHA-256, MD5)
├── pkg/
│   ├── eventschema/            # ECS-compatible event schema structs
│   └── ruleformat/             # Detection rule parsing (SIGMA-like)
├── rules/                      # Detection and compliance rule files
│   ├── behavioral/             #   SIGMA-like YAML rules
│   ├── malware/                #   Known hashes + YARA rules
│   ├── compliance/             #   Hardening check definitions
│   └── threatintel/            #   Threat intel feed config
├── config/config.json          # Default agent configuration
├── docs/                       # Project documentation
│   ├── architecture.md         #   Architecture overview and diagrams
│   ├── roadmap.md              #   Development roadmap
│   ├── event-pipeline.md       #   Event pipeline design
│   └── development/
│       └── adding-capability.md  # Guide: adding a new capability
├── test/                       # Test fixtures and integration tests
├── packaging/                  # deb, rpm, multi-arch build scripts
├── systemd/                    # systemd service unit
├── Makefile                    # Build, run, package targets
├── VERSION                     # Semantic version (0.3.1)
└── go.mod                      # Go module definition
```

## Prerequisites

- **Go 1.22+**
- **Linux** (agent uses Linux-specific APIs: procfs, inotify, AF_PACKET, syscall)
- `dpkg-deb` for Debian packaging
- `rpm` / `rpmbuild` for RPM packaging

## Build

```bash
cd xdr-agent
make build
```

Compiles to `dist/xdr-agent` with version from `VERSION` injected via `-ldflags`.

```bash
./dist/xdr-agent version
# 0.3.1
```

## Run

### One-shot enrollment

```bash
./dist/xdr-agent enroll <enrollment_token> --config ./config/config.json
```

### Long-running mode

```bash
./dist/xdr-agent run --config ./config/config.json
```

The agent will:
1. Load config and ensure agent identity.
2. Enroll with the control plane (retry until successful).
3. Start all 13 telemetry collectors.
4. Ship ECS-compatible events to OpenSearch via the control plane.
5. Send heartbeats every 30 seconds.
6. Shut down gracefully on `SIGTERM` or `SIGINT`.

### With make

```bash
make run                              # Build and run in foreground
make enroll ENROLLMENT_TOKEN=<token>  # Enroll and exit
```

## Configuration

Default path: `/etc/xdr-agent/config.json` — Sample: `config/config.json`

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
| `telemetry_url` | No | Telemetry shipping URL; defaults to `control_plane_url` |
| `telemetry_path` | No | Telemetry API path (default: `/api/v1/agents/telemetry`) |
| `telemetry_interval_seconds` | No | Telemetry collection interval in seconds (default: `60`) |
| `telemetry_ship_interval_seconds` | No | Max linger before shipping buffered events (default: `1`) |

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
make clean; make deb
sudo dpkg -i dist/xdr-agent_$(cat VERSION)_amd64.deb
```

### RPM

```bash
make rpm
```

### Multi-architecture (amd64 + arm64)

```bash
bash ./packaging/build_multi_arch.sh "$(cat VERSION)"
```

## Install & deploy

1. Install the package:
   ```bash
   sudo dpkg -i dist/xdr-agent_$(cat VERSION)_amd64.deb
   ```
2. Edit `/etc/xdr-agent/config.json` with your `control_plane_url`, `policy_id`, and `enrollment_token`.
3. Enroll (auto-enables and starts the systemd service):
   ```bash
   sudo xdr-agent enroll <token> --config /etc/xdr-agent/config.json
   ```
4. Verify:
   ```bash
   sudo systemctl status xdr-agent --no-pager -l
   sudo journalctl -u xdr-agent -f
   ```

## Update

```bash
sudo systemctl stop xdr-agent.service
make clean; make deb
sudo dpkg -i dist/xdr-agent_$(cat VERSION)_amd64.deb
sudo systemctl start xdr-agent.service
```

## Telemetry verification test

Verifies that all 13 telemetry collectors are actively collecting and shipping
events. The test works by:

1. Starting a local HTTP listener on a temporary port
2. Reconfiguring the agent to ship telemetry to the listener (instead of OpenSearch)
3. Generating real OS events that each collector should detect (files, processes, network connections, cron entries, pipes, etc.)
4. Analyzing the captured events for coverage across all 13 collectors
5. Restoring the original config and cleaning up all generated artifacts

**Requirements:** The agent must be enrolled and running. Requires `sudo`.

```bash
sudo bash test/telemetry_verify.sh
```

To keep the captured events for inspection after the test:

```bash
sudo KEEP_LOGS=1 bash test/telemetry_verify.sh
```

Expected output on success:

```
  ALL 13/13 COLLECTORS VERIFIED ✓
```

The test is safe — it does not push data to OpenSearch, and all files created
during the test are automatically deleted on exit (including on failure or Ctrl+C).

## Architecture

See [docs/architecture.md](docs/architecture.md) for diagrams, data flow, and design decisions.

See [docs/roadmap.md](docs/roadmap.md) for the full development roadmap.

See [docs/event-pipeline.md](docs/event-pipeline.md) for event pipeline design.

See [docs/development/adding-capability.md](docs/development/adding-capability.md) for adding new capabilities.

### Capability interface

```go
type Capability interface {
    Name() string                       // e.g. "telemetry.process"
    Init(deps Dependencies) error       // receive config, pipeline, logger
    Start(ctx context.Context) error    // begin monitoring
    Stop() error                        // graceful shutdown
    Health() HealthStatus               // running, degraded, failed, etc.
}
```

## Control-plane compatibility

### OpenSearch Dashboards xdr-manager-plugin

1. Generate an enrollment token from the plugin UI.
2. Set `control_plane_url` to OpenSearch Dashboards (default: `http://localhost:5601`).
3. Set `enrollment_token` to the generated token.
4. Set `policy_id` to match the token's policy.

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
  "agent_version": "0.3.1"
}
```

## Troubleshooting

| Problem | Solution |
|---|---|
| `go: command not found` | `sudo apt-get install -y golang-go` |
| Service not found after install | `sudo systemctl daemon-reload` |
| Enrollment rejected | Verify `enrollment_token` and `policy_id` match the control plane |
| Config file not found | Check path with `--config` flag; default is `/etc/xdr-agent/config.json` |
| DNS collector fails to start | Requires `CAP_NET_RAW` — run as root or grant the capability |

## License

Copyright (C) 2026  Diego A. Guillen-Rosaperez

This program is free software: you can redistribute it and/or modify it under
the terms of the **GNU Affero General Public License v3.0** as published by the
Free Software Foundation.

See [LICENSE](LICENSE) for the full text.
