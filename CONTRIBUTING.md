# Contributing to xdr-agent

This document covers contribution expectations for the endpoint runtime.

## License

`xdr-agent` is licensed under the GNU Affero General Public License v3.0.
See `LICENSE` for the full terms.

By submitting a change, you agree that your contribution is distributed under the same license.

## Contribution Flow

1. Branch from `main`.
2. Make a focused change.
3. Add or update tests when behavior changes.
4. Build and test before opening a pull request.
5. Include a clear description of the runtime impact, and any compatibility implications.

## Build And Test

```bash
make build
make test
```

Run the smallest relevant test scope when iterating, but do not open a change without a clean build.

## Engineering Expectations

- Follow the current runtime architecture in `docs/architecture.md`.
- Keep capability boundaries clear instead of adding cross-cutting logic in ad hoc places.
- Prefer minimal, justified dependencies. External libraries are acceptable when they solve a real endpoint-security need better than custom code.
- Keep protection configuration local and content tied to agent releases; Coordinator policies are grouping labels.
- Update docs and contract tests when routes, field ownership, or scope change.
- Keep runtime changes within process/file/network collection and release-bundled YARA protection. Additional protection domains require a separate scope decision.
- Use the shared event envelope and lifecycle in `internal/service/run.go`; keep constructor dependencies explicit.
- For HTTP changes, update `docs/api-endpoints.md`, the Go contract test, and the Coordinator handler test together. Builds enforce route compatibility.
- Protection changes need matching/nonmatching and failure-path tests; kernel enforcement needs disposable privileged Linux validation.
- Update the source-to-field mappings in `docs/telemetry.md` when collection or emission changes; keep current behavior separate from planned work in `docs/roadmap.md`.

## Code Style

- Format Go code with `gofmt`.
- Match existing package structure and naming.
- Write table-driven tests for new logic where practical.
- Use the project logging path instead of ad hoc stdout logging.

## Security Issues

Do not open public issues for vulnerabilities, secrets exposure, or bypasses.
Report them privately to the maintainer through the established private contact path.

## General Issues And Pull Requests

For non-security issues, include:

- what you changed
- why the current behavior is wrong or incomplete
- how you validated the change
- whether agent, coordinator, or defense compatibility is affected

## Conduct

Be direct, respectful, and technically concrete.
