# xdr-agent

`xdr-agent` is a Linux endpoint security agent written in Go.
It is the endpoint runtime for the XDR stack: it enrolls to the control plane, collects endpoint telemetry, applies policy, and ships ECS-compatible events.

## Current Status

- Version: `0.4.1`
- Platform: Linux (`x86_64`, `arm64`)
- Production focus today: telemetry, policy plumbing, signed artifact rollout plumbing
- In progress: detection + prevention hardening (Phase 3 + 4 together)

## What It Does Today

### 1. Agent identity and control plane lifecycle
- Agent identity persistence (`agent_id`, machine fingerprint, host metadata)
- Enrollment and heartbeat
- Command polling (for actions like upgrade and rollout commands)
- Batched, compressed event shipping to OpenSearch through the control plane

### 2. Endpoint telemetry collection (13 active collectors)
- `process`: process lifecycle, ancestry, command-line context
- `file.fim`: integrity changes and file metadata signals
- `file.access`: sensitive file access activity
- `network.connections`: socket and flow visibility
- `network.dns`: DNS query/response telemetry
- `session`: login/auth session signals
- `system`: host resource metrics
- `library`: shared library load signals
- `kernel`: kernel module activity
- `tty`: interactive terminal session signals
- `scheduled`: cron/timer persistence signals
- `injection`: ptrace and memory injection indicators
- `ipc`: local IPC visibility (sockets/pipes)

### 3. Policy and artifact consumption
- Consumes policy overlays from control plane paths
- Consumes signed rule/hash bundles produced by `xdr-defense`
- Maintains local state for rollout acknowledgment and reconciliation

## Design Choices

- Capability-based architecture:
  each telemetry/security module is isolated and lifecycle-managed by the service orchestrator.
- ECS-compatible event model:
  event fields are normalized early to simplify storage, dashboards, and downstream detections.
- Agent does local enforcement; control plane curates content:
  cloud-side plugins (`xdr-defense`) manage external feed sync and artifact curation; endpoint stays deterministic and lean.
- Fail-open on management-plane outages:
  enrollment/retry and buffered shipping are built to survive temporary control plane/network disruption.

## Deliberate Scope Boundaries

These are intentional and should remain so:

- No direct endpoint pull from remote threat intel feeds (STIX/TAXII/MISP) from each agent
- No heavy policy authoring logic embedded in the agent
- No dependency on always-on cloud connectivity for baseline telemetry collection

## Build and Run

```bash
cd /home/kplrm/github/xdr-agent
make build
go build ./...
go test ./...

./dist/xdr-agent run --config ./config/config.json
```

```bash
sudo xdr-agent remove
sudo systemctl stop xdr-agent.service
make clean; make deb
sudo dpkg -i dist/xdr-agent_$(cat VERSION)_amd64.deb
sudo systemctl start xdr-agent.service
sudo journalctl -u xdr-agent -f
```

## Roadmap (Pragmatic)

### Near term (active)
- Complete Phase 3 + 4 together:
  detection and prevention in one coherent runtime (YARA-X, hash detection, behavioral rules, memory-focused detections, prevention actions)
- Strengthen rollback and prevention posture controls
- Expand confidence tests for signed artifact rollout flows

### Mid term
- Response actions with strict safety controls and auditable execution
- Better operator diagnostics and health visibility per capability
- Performance tuning for high-event hosts and burst scenarios

### Long term
- Advanced kernel telemetry optimization
- Optional cloud/container posture modules where customer demand is proven

## Features De-prioritized or Removed From Active Plan

These are not current investment priorities because they increase complexity without clear product value now:

- Per-endpoint remote feed connectors (each agent pulling internet IoCs independently)
- Broad in-agent feature creep unrelated to endpoint enforcement
- Expanding partially implemented stubs without shipping measurable security outcomes

## Related Components

- `xdr-coordinator`: fleet management, enrollment, telemetry operations, dashboards
- `xdr-defense`: policy, rule/hash lifecycle, signed bundles, rollout status
- `xdr-security`: OpenSearch Dashboards wrapper/navigation grouping for XDR apps
