# xdr-agent Roadmap

Last updated: 2026-04-02

## Direction

The near-term goal is not to expand the number of half-implemented domains.
The goal is to make the current endpoint runtime operationally credible by finishing the detection and prevention path already scaffolded into the agent.

## Current Phase Focus

### Active delivery: Phase 3 + 4 together

The project preference is to deliver detection and prevention together rather than as isolated milestones.

Priority areas:
- local hash and YARA detection
- behavioral rule execution
- memory-focused detections
- prevention mode and enforcement decisions
- ransomware rollback plumbing and confirmation flow
- signed bundle rollout reliability and status reporting

## Near-Term Work

### 1. Stabilize the detection runtime
- improve malware rule reload behavior
- tighten behavioral rule evaluation and hot reload
- keep local threat-intel matching strictly artifact-based
- expand memory detection coverage where the signal is reliable

### 2. Stabilize prevention behavior
- keep prevention policy-driven
- improve block/quarantine/kill decision auditability
- strengthen rollback confirmation and operator visibility

### 3. Improve control-plane compatibility
- maintain clean posture overlay handling
- keep rollout acknowledgments explicit
- preserve compatibility with signed artifact delivery from `xdr-defense`

## Mid-Term Work

- safer active response primitives
- stronger runtime health diagnostics per subsystem
- better performance under bursty host workloads
- better test coverage for rollout and recovery paths

## Long-Term Work

- selective kernel telemetry optimization where it clearly improves signal or cost
- limited cloud or container extensions only if customer demand proves they are core

## De-prioritized Work

These directions are intentionally not near-term priorities:

- per-agent internet threat-feed ingestion
- large new domains with only scaffold code and no shipping path
- documentation that treats every stub package as an active roadmap commitment
- broad platform expansion before Linux endpoint detection/prevention is solid

## Keep/Remove Rule

If a partially implemented feature does not improve the Phase 3 + 4 path, it should either:
- stay explicitly de-prioritized, or
- be removed from active documentation claims
