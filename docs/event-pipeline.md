# Event Pipeline

## Overview

The event pipeline is the central nervous system of the XDR agent. All capabilities
emit structured events into the pipeline, which handles enrichment, filtering,
buffering, and shipping to the control plane.

## Event Flow

```
Capability → Emit() → Pipeline Channel → Enrichment → Filtering → Buffer → Ship to Control Plane
```

## Event Kinds

| Kind | Description | Example |
|---|---|---|
| `event` | Raw telemetry event | Process start, file write, network connection |
| `alert` | Detection alert | Malware detected, suspicious behavior, IoC match |
| `metric` | Performance metric | CPU usage, event rate, scan duration |
| `state` | State change | Capability started, agent enrolled, policy updated |

## Enrichment

Before shipping, events are enriched with:
- **Agent context**: agent_id, hostname, OS info
- **Cloud context**: cloud provider, instance ID, region (if applicable)
- **Container context**: container ID, image, K8s namespace (if applicable)
- **MITRE ATT&CK**: tactic and technique IDs (for alerts)
- **Threat intel**: reputation scores (for IoC matches)

## Buffering

When the control plane is unreachable, events are buffered to disk:
- Append-only log file in `/var/lib/xdr-agent/buffer/`
- Replayed in order when connectivity is restored  
- Maximum buffer size is configurable (default: 100MB)
- Oldest events are dropped when buffer is full

## Shipping

Events are shipped to the control plane via HTTP POST:
- Batched (default: up to 1000 events per request)
- Compressed (gzip)
- Retry with exponential backoff on failure
- Configurable endpoint and authentication
