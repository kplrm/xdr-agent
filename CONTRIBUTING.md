# Contributing to xdr-agent

Thank you for your interest in contributing to xdr-agent! This document
explains how to contribute and the terms under which contributions are accepted.

## License

xdr-agent is licensed under the **GNU Affero General Public License v3.0**
(AGPL-3.0). See [LICENSE](LICENSE) for the full text.

All contributions to this project are subject to the same license. By
submitting a pull request you agree that your work may be distributed under
the terms of the AGPL-3.0 (Inbound = Outbound).

## How to contribute

1. **Fork** the repository and create a feature branch from `main`.
2. Make your changes. Add or update tests where applicable.
3. Ensure the project builds cleanly: `make build`.
4. Commit with a clear message.
5. Open a **pull request** against `main`.

## Coding guidelines

- Go source files should be formatted with `gofmt`.
- Keep dependencies minimal — the project currently uses only the Go standard
  library, and that is intentional.
- Follow the existing package and file structure (see `docs/architecture.md`
  and `docs/development/adding-capability.md`).

## Reporting issues

Open a GitHub issue. Include steps to reproduce, expected behaviour, and actual
behaviour. For security vulnerabilities, **do not** open a public issue — email
the maintainer privately instead.

## Code of Conduct

Be respectful and constructive. Harassment or discriminatory behaviour of any
kind will not be tolerated.
