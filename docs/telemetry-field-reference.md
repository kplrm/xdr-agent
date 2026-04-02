# Telemetry Field Reference

This document is the stable reference for the event envelope and collector ownership.
It is not an exhaustive copy of every nested payload field in the codebase.

That is deliberate: large hand-maintained field inventories go stale faster than the implementation.

## Stable Event Envelope

All emitted events use the base model in `internal/events/event.go`.

Top-level fields:

| Field | Purpose |
|---|---|
| `id` | Event identifier |
| `@timestamp` | Event time in UTC |
| `event.type` | Event subtype |
| `event.category` | ECS-aligned category |
| `event.kind` | `event`, `alert`, `metric`, or `state` |
| `event.severity` | Severity enum |
| `event.module` | Emitting component |
| `agent.id` | Agent identifier |
| `host.hostname` | Hostname |
| `payload` | Component-specific body |
| `tags` | Routing/filter tags |
| `threat.*` | Threat mapping fields when populated |

## Collector Ownership

The following modules own their payload structure:

| Module | Responsibility |
|---|---|
| `telemetry.process` | process lifecycle and execution context |
| `telemetry.file` | integrity monitoring |
| `telemetry.file.access` | sensitive file access |
| `telemetry.network` | connection telemetry |
| `telemetry.dns` | DNS activity |
| `telemetry.session` | session and auth signals |
| `telemetry.system` | host metrics |
| `telemetry.library` | shared library loads |
| `telemetry.kernel` | kernel module activity |
| `telemetry.tty` | interactive terminal sessions |
| `telemetry.scheduled` | cron/timer persistence signals |
| `telemetry.injection` | injection-related indicators |
| `telemetry.ipc` | IPC visibility |

Detection and prevention emit additional modules such as:

- `detection.behavioral`
- `detection.malware`
- `detection.memory`
- `detection.threatintel`
- `prevention.manager`

## How To Treat Payload Fields

- The envelope is the stable contract.
- Payload details are owned by the producing package.
- When changing payload fields, update both the producer and the consuming dashboards or rules.
- Do not document speculative fields that are not emitted today.

## Source of Truth

When you need exact payload details, inspect the emitting package directly.
This document exists to prevent drift at the contract level, not to duplicate the entire codebase.
