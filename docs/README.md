# xdr-agent Documentation

This directory contains the internal documentation for the Linux endpoint agent.

## Read This First

- `architecture.md`: runtime structure, control-plane flow, and design boundaries
- `event-pipeline.md`: how events move from collectors to OpenSearch
- `roadmap.md`: delivery priorities and what is deliberately de-prioritized
- `telemetry-field-reference.md`: stable event envelope and collector-level field ownership
- `development/adding-capability.md`: how to add a new capability without breaking the current runtime model

## Documentation Principles

- Prefer current implementation over aspirational claims.
- Keep endpoint responsibilities separate from control-plane responsibilities.
- Treat policy overlays and signed bundle rollout as first-class runtime behavior.
- Remove stale detail instead of preserving it for completeness.
