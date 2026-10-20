# Contributing to xdr-agent

This repository owns Linux endpoint telemetry and release-bundled YARA protection. Start with the [README](README.md), [architecture](docs/architecture.md), [telemetry mappings](docs/telemetry.md), and [HTTP contract](docs/api-endpoints.md). Keep planned work in the [roadmap](docs/roadmap.md).

## Development and validation

Use Debian/Ubuntu Linux, a Go toolchain compatible with `go.mod`, Python 3, Make, and Docker. Install `yara` and `yarac` to exercise the native scanner tests. Keep the local YARA snapshot available for rule generation. Node.js and an adjacent Coordinator checkout enable the Coordinator handler checks.

```bash
make build
make test
```

`make test` runs Go, rule-bundling, HTTP-contract, enrollment, and bounded fanotify checks. Docker must be available for the disposable kernel-test container. Use focused tests while iterating; run the full checks before submitting runtime changes. For packaging changes, also validate `make deb` in a disposable Linux environment.

## Engineering expectations

- Follow the runtime architecture, shared event envelope, and lifecycle in `internal/service/run.go`; keep constructor dependencies explicit.
- Keep runtime work within the documented telemetry and YARA scope. Discuss additional protection domains before implementation.
- Keep protection configuration local and content tied to Agent releases; Coordinator manages only the settings allowed by the HTTP contract.
- For HTTP changes, update the authoritative contract, Agent contract tests, and [Coordinator handler tests](https://github.com/kplrm/xdr-coordinator/blob/main/scripts/test_api.cjs) together.
- Update telemetry source-to-field mappings when collection or emitted events change.
- Cover matching, nonmatching, and failure paths for protection changes. Validate kernel enforcement only in a disposable Linux test environment.
- Format Go with `gofmt`, follow existing package boundaries, use the project logging path, and prefer focused, table-driven tests where practical.
- Justify dependencies and preserve the licenses and notices of bundled YARA rules.

## Issues and pull requests

Use this repository's [issue tracker](https://github.com/kplrm/xdr-agent/issues) for general questions, reproducible bugs, and proposals. Discuss substantial changes before implementation.

1. Fork the repository and branch from `main`.
2. Keep the change focused and follow the existing code style.
3. Add regression coverage for changed behavior and update affected documentation.
4. In your PR, explain the problem, resulting behavior, validation performed, and compatibility impact. List any checks you could not run, including the reason.

Use sanitized logs and fixtures; remove secrets and identifying customer data before posting.

## License and attribution

By submitting a contribution, you agree to license your original changes under the [GNU Affero General Public License, version 3 only](LICENSE) (`AGPL-3.0`). You retain copyright in your contributions. Submit only work you have the right to contribute, and preserve existing copyright and third-party license notices.

## Security reports

Report vulnerabilities through this repository's [private vulnerability reporting](https://github.com/kplrm/xdr-agent/security/advisories/new) when enabled. Include affected versions, reproduction steps, impact, and sanitized supporting details. Keep vulnerability, bypass, and credential details out of public issues.

If private reporting is unavailable, open an issue asking the maintainer for a private reporting channel without describing the vulnerability.

## Conduct

Be respectful, direct, and technically concrete in issues, reviews, and discussions.
