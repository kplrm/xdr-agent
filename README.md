# XDR Agent

XDR Agent is the Linux endpoint component of [XDR Security](https://github.com/kplrm/xdr-security/blob/main/README.md). It collects endpoint activity, detects threats, and sends events to OpenSearch for investigation in the XDR plugins.

- **Telemetry:** process, file, network, DNS, and authentication activity.
- **Protection:** release-bundled YARA Forge Core rules. Detection is the default; prevention mode adds execution blocking and termination of matched processes.
- **Fleet management:** Coordinator handles enrollment, health, upgrades, and shared telemetry policies. Protection settings remain local.
- **Delivery:** telemetry, security alerts, and runtime logs go through Coordinator or directly to OpenSearch.

## Screenshot

TODO: Add an Agent overview showing fleet health, collected telemetry, and a protection alert in XDR Security.

<!-- ![XDR Agent overview](images/xdr-agent-overview.png) -->

## Local development

See [local development](docs/local-development.md) for source builds, a container workflow connected to the local XDR stack, and VM-based endpoint testing.

## Releases

Debian/Ubuntu packages support AMD64 and ARM64. `VERSION` controls independent Agent releases and their bundled rules. [GitHub Actions](.github/workflows/release.yml) builds and publishes packages on pushes to `main` or manual runs; existing release tags are skipped.

## Documentation

- [Telemetry](docs/telemetry.md): monitored paths, field meanings, emitted events, and collection limits.
- [Architecture](docs/architecture.md): runtime, protection, configuration, and delivery reliability.
- [HTTP contract](docs/api-endpoints.md): enrollment, health, ingestion, upgrades, and contract checks.
- [Roadmap](docs/roadmap.md): release gates and planned work.
- [Contributing](CONTRIBUTING.md): development and validation guidelines.

## License

Copyright (C) 2026 Diego A. Guillen-Rosaperez

Licensed under the [GNU Affero General Public License, version 3 only](LICENSE) (`AGPL-3.0`). Third-party components retain their own licenses and notices.
