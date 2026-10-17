# XDR Agent HTTP contract

The Linux agent has **no inbound HTTP server**. This is the authoritative ingestion/control contract. Coordinator paths are relative to `control_plane_url` (including any Dashboards base path).

| Method | Path | Purpose |
| --- | --- | --- |
| POST | /api/v1/agents/enroll | Register persistent identity using an enrollment token |
| POST | /api/v1/agents/heartbeat | Report health, protections, and configuration status; receive upgrades and settings |
| GET | /api/v1/agents/commands | Poll upgrades and settings with `agent_id` and `agent_version` query parameters |
| POST | /api/v1/agents/telemetry | Deliver process, file, connection, and DNS events |
| POST | /api/v1/agents/security | Deliver YARA alerts and prevention outcomes |
| POST | /api/v1/agents/logs | Deliver runtime logs |

Every Coordinator request sends `Authorization: Bearer <enrollment_token>` and `osd-xsrf: true`. Coordinator binds a consumed token to one agent. Revocation or agent removal rejects subsequent Coordinator traffic. Operator APIs use Dashboards authentication and are listed in Coordinator's API/data model.

Enrollment sends `agent_id`, `machine_id`, `hostname`, `architecture`, `os_type`, `ip_addresses`, `policy_id`, `tags`, and `agent_version`; the response contains `enrollment_id` and `message`.

Heartbeat sends identity, hostname, grouping metadata, and `agent_version`, plus `protection`: `rule_source`, `rule_version`, `rules_sha256`, `rule_count`, `platform`, `mode`, and `health` (component-to-status map). Heartbeat and command responses contain `message`, optional `pending_commands` (`upgrade:<version>`), optional `upgrade_id` (unique attempt identity), and optional `managed_config` below. Heartbeats report optional `config_revision` / `config_error`, plus `upgrade_id`, `upgrade_error` (at most 1,024 bytes), `upgrade_retryable` (boolean), and `upgrade_retry_at` (earliest allowed retry, Unix seconds).

Health is independent of version checks. Execution blocking is `not_applicable` in detection mode. YARA scan failures report degraded health and successful scans restore it when the scan queue is no longer full; execution-blocking failures remain separate.

Batches contain `{ "agent_id": "...", "events": [...] }`, use gzip JSON with `Content-Encoding: gzip`, and receive an `indexed` count. [Telemetry](telemetry.md) defines the event envelope and payload fields. Coordinator checks ownership and topic and returns an error for failed bulk indexing.

## Managed configuration

Edit **Coordinator → Policies → Edit** to manage settings for every enrolled agent assigned to that policy, including `default-endpoint`. Coordinator returns the assigned policy through authenticated heartbeats and command polls; the agent normally receives changes within the 5-second command-poll interval. No inbound endpoint is needed.

```json
"managed_config": {
  "schema_version": 1,
  "revision": "opaque-policy-revision",
  "settings": {
    "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"],
    "process_scan_interval_seconds": 1,
    "network_scan_interval_seconds": 1,
    "telemetry_ship_interval_seconds": 5
  }
}
```

These four settings are the managed allowlist. Intervals are whole seconds from 1 to 86,400; the CIDR list permits at most 256 entries, including an explicit empty list. Settings are a complete snapshot of policy overrides. Omitting a never-managed field preserves its local value; removing a previously managed field resets it to the packaged default. An empty `settings` object clears previous overrides. An absent `managed_config` leaves local configuration unchanged. Only configuration edits change the policy revision; renaming a policy does not.

The agent validates the complete update before atomically merging it into its active config file (normally `/etc/xdr-agent/config.json`, mode `0600`). Identity, enrollment token, destinations, OpenSearch credentials, and unrelated local keys are preserved. It updates collection/shipping timers and perimeter classification in place, retaining queues and collection baselines. Repeated revisions do not rewrite the file. Invalid or unwritable updates keep the last good configuration and report an error; Coordinator displays Pending, Applied, or Error using the next heartbeat's acknowledgment.

Deploy Coordinator support, then upgrade agents to **0.4.6 or later**. Older agents ignore the additive response; editing a package template does not modify installed files. New managed fields require matching server/agent validation and schema compatibility, plus explicit reset/migration handling for removed fields. Protection settings and credentials remain local. Existing groups are unmanaged until settings are saved; moving a previously managed agent to an unmanaged group clears its prior overrides.

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

Deploy Coordinator's data-stream support and create the restricted user using the [bundle installation steps](https://github.com/kplrm/xdr-security#4-send-agent-events-directly-to-opensearch). Copy the issuing CA certificate to `ca_file`; leave it empty only when the system already trusts the certificate. HTTPS verifies the chain and hostname/IP.

Installation creates root-owned `/etc/xdr-agent/opensearch.env` with mode `600` and an empty `XDR_OPENSEARCH_PASSWORD`. Upgrades preserve its contents. Using `sudoedit`, set `XDR_OPENSEARCH_PASSWORD='YOUR_USER_PASSWORD'` there, then run:

```bash
sudo chmod 600 /etc/xdr-agent/opensearch.env
sudo systemctl daemon-reload
sudo systemctl restart xdr-agent
sudo journalctl -u xdr-agent -f
```

The systemd unit reads this file; foreground runs must export the variable. Requests use **HTTP Basic authentication over verified HTTPS**. `opensearch.username` defaults to `xdr-agent`. Keep the password out of `config.json`.

A shared account writes all three streams without Coordinator's per-agent ownership enforcement; Agent IDs and hostnames stay separate. Revoking enrollment does **not** revoke direct writes. Password rotation requires updating every affected environment file and restarting services. When migrating, replace old OpenSearch authentication fields with the block above and update the environment file.

Bulk operations use `create` in `xdr-agent-telemetry`, `xdr-agent-security` and `xdr-agent-logs`, with `@timestamp` and `_id=agent_id:event_id`. Both delivery paths retain failed batches and accept duplicate-ID conflicts on retry. Deduplication is limited to the current backing index; retries after rollover can duplicate events. Other bulk errors retain the batch. Direct credentials go only to the configured API; redirects are rejected.

The security stream can remain empty when no YARA alerts or prevention outcomes occur. [Telemetry](telemetry.md) lists each producer's fields.

Paths, base URLs, and intervals can be overridden locally. [Architecture](architecture.md) defines timing defaults, queue limits, retries, and shutdown. TLS validation is enabled by default.

## Agent upgrades

Coordinator offers only a published stable GitHub release with uploaded, nonempty AMD64 and ARM64 Debian assets. Shared release lookups cache successes, failures, and in-flight requests for five minutes; GitHub rate-limit headers can extend this cooldown. Repository `VERSION` selects build output, not upgrade availability. Newer installed versions are never downgraded.

Each operator request has a persistent job ID and at most **three command deliveries**, spaced by one minute then five minutes, plus up to 15 seconds of jitter. Frequent heartbeats/command polls do not consume extra attempts or cause extra downloads. After the limit, an unconfirmed upgrade becomes Failed; **Retry upgrade** creates a new job and resets the counter while preserving any outstanding cooldown. Unavailable or superseded targets are stopped. Older agents also receive this server-side limit.

Agents persist each attempt ID before downloading and ignore duplicate deliveries across restarts. Download/launch failures are reported through heartbeat; HTTP 4xx errors other than 408 stop automatic retries immediately, including missing packages, authorization failures, and rate limiting. GitHub `Retry-After` and `X-RateLimit-Reset` headers delay even operator retries. Network/5xx failures may use the remaining attempts. Coordinator displays Queued, Upgrading, Retrying, or Failed with the last error and next permitted attempt time. Success requires the reported installed version, rather than the installer merely being launched. Deploy Coordinator support before Agent **0.4.9+**; existing queued unavailable targets are stopped during polling.

`GET https://github.com/kplrm/xdr-agent/releases/download/v{version}/{package}` downloads a distribution/architecture package. Native package dependencies must already be available for self-upgrade.

## Required checks

`make api-test` runs `test/api_contract.sh`: `internal/enroll/api_contract_test.go` (`TestAgentAPI`) checks all six routes against this table, headers, and gzip/rejection behavior. It also runs shipping and upgrade-client tests, plus Coordinator's `scripts/test_api.cjs` handler tests when the sibling checkout exists. Builds, packages, and release CI invoke these checks. Direct-ingestion tests are in `internal/controlplane/opensearch_test.go`.

For endpoint changes, update this table, its Go case, and the Coordinator handler test together; route differences fail the build. [Contributing](../CONTRIBUTING.md) covers broader runtime and enforcement validation.
