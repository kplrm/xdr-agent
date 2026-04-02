# xdr-agent Architecture

`xdr-agent` is a Linux endpoint runtime. Its responsibilities are narrow on purpose:

- collect endpoint telemetry
- apply policy overlays received from the control plane
- consume signed detection content produced by `xdr-defense`
- emit ECS-shaped telemetry, alerts, and prevention audit events

It is not intended to be a full control plane, a remote feed aggregator, or a rule authoring system.

## Runtime Structure

### Process flow
1. Load local config.
2. Load cached Defense Posture state if present.
3. Ensure persistent agent identity.
4. Enroll if needed.
5. Start telemetry collectors.
6. Start the event pipeline and shippers.
7. Start detection and prevention managers.
8. Poll for posture updates and signed artifact rollouts.

The main orchestration lives in `internal/service/run.go`.

## Core Components

### Identity and enrollment
- `internal/identity`: persistent agent identity and local state
- `internal/enroll`: enrollment and heartbeat HTTP client

### Eventing and shipping
- `internal/events`: in-memory event pipeline and base event model
- `internal/controlplane`: compressed batch shipping, Defense Posture sync, signed bundle sync

### Telemetry
The current runtime starts 13 active telemetry collectors:

- process
- file integrity monitoring
- file access monitoring
- network connections
- DNS
- session/auth
- system metrics
- library loading
- kernel modules
- TTY sessions
- scheduled tasks
- injection indicators
- IPC

### Detection
The detection engine consumes runtime events and emits alerts. Current engine structure includes:

- malware scanning and rule reload support
- behavioral rule engine
- local threat-intel matching
- memory-focused detection paths

This logic lives under `internal/detection`.

### Prevention
The prevention manager currently acts as an enforcement decision layer on top of detection output. It emits prevention audit/action events and chooses actions based on posture and alert severity.

This logic lives under `internal/prevention`.

## Policy and Bundle Model

### Defense Posture
`xdr-agent` polls `xdr-defense` for policy overlays and persists the last applied posture locally.

The posture controls:
- global mode: `detect` or `prevent`
- capability toggles such as malware hash detection, YARA detection, ransomware shield, memory detection, rollback, and prevention enablement

### Signed content
The agent consumes signed local artifacts instead of directly fetching internet feeds.

Current design intent:
- `xdr-defense` curates and signs content
- `xdr-agent` verifies, applies, and reports rollout state

This keeps endpoint behavior deterministic and reduces feed-management complexity on hosts.

## Design Choices

- Capability-oriented runtime:
  collectors and engines remain separable so policy can evolve without rewriting the service loop.
- In-memory event bus:
  the pipeline is intentionally simple, with bounded buffering and explicit drop logging under pressure.
- Control plane owns content curation:
  the agent should evaluate local artifacts, not become a distributed feed collector.
- Prevention follows posture:
  enforcement is policy-driven rather than hard-coded into each detector.

## Boundaries

The agent should not grow into these roles:

- remote threat feed aggregation per endpoint
- broad control-plane orchestration logic
- large amounts of duplicated policy-authoring behavior

Those concerns belong in the OpenSearch Dashboards plugins.
