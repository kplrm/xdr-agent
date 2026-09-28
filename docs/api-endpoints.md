# XDR Agent HTTP contract

The Linux agent has **no inbound HTTP server**. This is the authoritative list of requests it sends to Coordinator, relative to `control_plane_url` (including any Dashboards base path).

| Method | Path | Purpose | Regression test |
| --- | --- | --- | --- |
| POST | /api/v1/agents/enroll | Register persistent identity using an enrollment token | `internal/enroll/api_contract_test.go` (`TestAgentAPI/enroll`) |
| POST | /api/v1/agents/heartbeat | Report health and installed release protections; receive upgrades | `internal/enroll/api_contract_test.go` (`TestAgentAPI/heartbeat`) |
| GET | /api/v1/agents/commands | Poll upgrades with agent_id and agent_version query parameters | `internal/enroll/api_contract_test.go` (`TestAgentAPI/commands`) |
| POST | /api/v1/agents/telemetry | Deliver process, file, connection, and DNS events | `internal/enroll/api_contract_test.go` (`TestAgentAPI/telemetry`) |
| POST | /api/v1/agents/security | Deliver YARA alerts and prevention outcomes | `internal/enroll/api_contract_test.go` (`TestAgentAPI/security`) |
| POST | /api/v1/agents/logs | Deliver runtime logs | `internal/enroll/api_contract_test.go` (`TestAgentAPI/logs`) |

Every request sends `Authorization: Bearer <enrollment_token>` and `osd-xsrf: true`. Coordinator binds a consumed token to one agent. Revocation or agent removal rejects subsequent traffic. Operator APIs use Dashboards authentication and are listed in Coordinator's API/data model.

Enrollment sends `agent_id`, `machine_id`, `hostname`, `architecture`, `os_type`, `ip_addresses`, `policy_id`, `tags`, and `agent_version`; the response contains `enrollment_id` and `message`.

Heartbeat sends identity, hostname, grouping metadata, and `agent_version`, plus `protection`: `rule_source`, `rule_version`, `rules_sha256`, `rule_count`, `platform`, `mode`, and `health` (component-to-status map). Heartbeat and command responses contain `message` and optional `pending_commands`, currently `upgrade:<version>`.

Batches contain `{ "agent_id": "...", "events": [...] }`, use gzip JSON with `Content-Encoding: gzip`, and receive an `indexed` count. Events follow `internal/events/event.go`. Stable IDs make retries idempotent within the daily destination index. Coordinator checks ownership and topic and returns an error for failed bulk indexing.

Defaults: health every 30 seconds, command polling every 5 seconds, enrollment retry every 30 seconds, process/network snapshots every 5 seconds, and telemetry/security/log batches every 30 seconds. Paths, base URLs, and intervals can be overridden locally. Delivery retains a bounded in-memory queue; crash replay is future work. TLS validation is enabled by default.

## External upgrade artifact

`GET https://github.com/kplrm/xdr-agent/releases/download/v{version}/{package}` downloads a distribution/architecture package. Tests in `internal/upgrade/upgrader_test.go` cover URL selection and HTTP errors without installing anything. Native package dependencies must already be available for self-upgrade.

## Required checks

`bash test/api_contract.sh` (`make api-test`) tests the real clients, headers, gzip payloads, and rejection handling for all six endpoints. Its route set must match this table and endpoint literals in agent source. Builds, packages, and release CI invoke these checks. `make test` also runs `test/post_enroll_smoke.py`, which starts an unprivileged Agent against a local Coordinator fixture with a CPU and time limit.

Coordinator's `node --test scripts/test_api.cjs` invokes every registered agent handler with real schemas and in-memory persistence/indexing fixtures. When the sibling checkout is available, it checks this document against the registered route set. The agent test script runs both sides when available; the plugin release workflow runs the handler tests after bootstrapping Dashboards.

For any endpoint addition/change/removal, update this table, its Go test case, and the Coordinator handler test together. An unexplained route-set difference fails the build.
