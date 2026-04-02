# Threat Intel Rules Directory

This directory stores local threat-intel artifacts consumed by `xdr-agent`.

## Purpose

`xdr-agent` uses local, policy-assigned indicators during endpoint evaluation.
The control plane (`xdr-defense`) is responsible for collecting, curating, signing, and distributing those indicators.

## Design Choice

Threat intel ingestion is centralized in `xdr-defense`, not decentralized to each endpoint.

Why:
- Keeps endpoint behavior deterministic and auditable
- Reduces internet egress and feed parsing risk on endpoints
- Enables one curated source of truth for all agents
- Makes rollout/revoke workflows easier to verify

## What Belongs Here

- Indicator files deployed for local matching
- Signed or checksum-verifiable artifact payloads
- Minimal metadata needed for endpoint-side evaluation

## What Does Not Belong Here

- Endpoint-specific STIX/TAXII/MISP fetch logic
- Long-running remote feed clients
- Unverified direct internet feed payloads

## Future Work

- Standardize artifact schema and versioning metadata
- Improve rollback metadata for quick policy reversions
- Add integrity and freshness checks per artifact family
