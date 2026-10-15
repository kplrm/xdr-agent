# XDR Agent HTTP contract

The Linux agent has **no inbound HTTP server**. This is the authoritative ingestion/control contract. Coordinator paths are relative to `control_plane_url` (including any Dashboards base path).

| Method | Path | Purpose | Regression test |
| --- | --- | --- | --- |
| POST | /api/v1/agents/enroll | Register persistent identity using an enrollment token | `internal/enroll/api_contract_test.go` (`TestAgentAPI/enroll`) |
| POST | /api/v1/agents/heartbeat | Report health and installed release protections; receive upgrades | `internal/enroll/api_contract_test.go` (`TestAgentAPI/heartbeat`) |
| GET | /api/v1/agents/commands | Poll upgrades with agent_id and agent_version query parameters | `internal/enroll/api_contract_test.go` (`TestAgentAPI/commands`) |
| POST | /api/v1/agents/telemetry | Deliver process, file, connection, and DNS events | `internal/enroll/api_contract_test.go` (`TestAgentAPI/telemetry`) |
| POST | /api/v1/agents/security | Deliver YARA alerts and prevention outcomes | `internal/enroll/api_contract_test.go` (`TestAgentAPI/security`) |
| POST | /api/v1/agents/logs | Deliver runtime logs | `internal/enroll/api_contract_test.go` (`TestAgentAPI/logs`) |

Every Coordinator request sends `Authorization: Bearer <enrollment_token>` and `osd-xsrf: true`. Coordinator binds a consumed token to one agent. Revocation or agent removal rejects subsequent Coordinator traffic. Operator APIs use Dashboards authentication and are listed in Coordinator's API/data model.

Enrollment sends `agent_id`, `machine_id`, `hostname`, `architecture`, `os_type`, `ip_addresses`, `policy_id`, `tags`, and `agent_version`; the response contains `enrollment_id` and `message`.

Heartbeat sends identity, hostname, grouping metadata, and `agent_version`, plus `protection`: `rule_source`, `rule_version`, `rules_sha256`, `rule_count`, `platform`, `mode`, and `health` (component-to-status map). Heartbeat and command responses contain `message` and optional `pending_commands`, currently `upgrade:<version>`.

Health is independent of version checks. Execution blocking is `not_applicable` in detection mode. YARA scan failures report degraded health and successful scans restore it when the scan queue is no longer full; execution-blocking failures remain separate.

Batches contain `{ "agent_id": "...", "events": [...] }`, use gzip JSON with `Content-Encoding: gzip`, and receive an `indexed` count. Events follow `internal/events/event.go`. Coordinator checks ownership and topic and returns an error for failed bulk indexing.

## Direct OpenSearch ingestion

Set `opensearch.url` to send **all telemetry, security events and runtime logs** directly to OpenSearch with gzip NDJSON `POST /_bulk`. Enrollment, heartbeats and commands still use Coordinator. An empty URL retains Coordinator event delivery; the per-topic URL overrides use the Coordinator JSON contract, not OpenSearch bulk.

Requires OpenSearch **3.7+** with Security username/password authentication enabled. Add this block to the installed `/etc/xdr-agent/config.json`; replace the API address and CA path:

```json
"opensearch": {
  "url": "https://OPENSEARCH_HOST:PORT",
  "username": "xdr-agent",
  "password_env": "XDR_OPENSEARCH_PASSWORD",
  "ca_file": "/etc/xdr-agent/opensearch-ca.pem"
}
```

First deploy Coordinator's data-stream support and create the restricted `xdr-agent` user using the [bundle installation steps](https://github.com/kplrm/xdr-security#4-send-agent-events-directly-to-opensearch). Install the updated Agent package. Copy the issuing CA certificate to `ca_file`; HTTPS verifies both the certificate chain and the API hostname/IP. Leave `ca_file` empty only when the system already trusts the certificate.

Using `sudoedit`, create `/etc/xdr-agent/opensearch.env` containing `XDR_OPENSEARCH_PASSWORD='YOUR_USER_PASSWORD'`, then run:

```bash
sudo chmod 600 /etc/xdr-agent/opensearch.env
sudo systemctl daemon-reload
sudo systemctl restart xdr-agent
sudo journalctl -u xdr-agent -f
```

The packaged systemd unit reads this file; foreground runs must export the same variable. Requests use **HTTP Basic authentication over verified HTTPS**. The username defaults to `xdr-agent`; change `opensearch.username` to use another account. Keep the password out of `config.json`.

The account can be shared across agents while their Agent IDs and hostnames stay separate. It can write all three streams without Coordinator's per-agent ownership enforcement. Revoking enrollment does **not** revoke direct writes. Changing the shared account's password affects every Agent using it: update each environment file and restart the service. When migrating, replace the old OpenSearch authentication fields in the installed config with the block above and replace the environment file's contents.

Bulk operations use `create` in `xdr-agent-telemetry`, `xdr-agent-security` and `xdr-agent-logs`, with `@timestamp` and `_id=agent_id:event_id`. Both delivery paths retain failed batches and accept duplicate-ID conflicts on retry. Deduplication applies within the current backing index; a retry after rollover can duplicate an event. Other bulk errors retain the batch. Credentials are sent only to the configured API, and redirects are rejected. Regression tests: `internal/controlplane/opensearch_test.go`.

The security stream contains detection alerts (currently YARA matches) and prevention actions, including action failures. It can remain empty when no such events occur. Ordinary process/file/network/DNS activity goes to telemetry; Agent diagnostic messages go to logs.

Defaults: health every 30 seconds, command polling every 5 seconds, enrollment retry every 30 seconds, process/network snapshots every 5 seconds, and telemetry/security/log batches every 30 seconds. Paths, base URLs, and intervals can be overridden locally. Delivery retains a bounded in-memory queue; crash replay is future work. TLS validation is enabled by default.

## External upgrade artifact

`GET https://github.com/kplrm/xdr-agent/releases/download/v{version}/{package}` downloads a distribution/architecture package. Tests in `internal/upgrade/upgrader_test.go` cover URL selection and HTTP errors without installing anything. Native package dependencies must already be available for self-upgrade.

## Required checks

`bash test/api_contract.sh` (`make api-test`) tests the real clients, headers, gzip payloads, and rejection handling for all six endpoints. Its route set must match this table and endpoint literals in agent source. Builds, packages, and release CI invoke these checks. `make test` also runs `test/post_enroll_smoke.py`, which starts an unprivileged Agent against a local Coordinator fixture with a CPU and time limit.

Coordinator's `node --test scripts/test_api.cjs` invokes every registered agent handler with real schemas and in-memory persistence/indexing fixtures. When the sibling checkout is available, it checks this document against the registered route set. The agent test script runs both sides when available; the plugin release workflow runs the handler tests after bootstrapping Dashboards.

For any endpoint addition/change/removal, update this table, its Go test case, and the Coordinator handler test together. An unexplained route-set difference fails the build.
