# xdr-agent

Lightweight XDR agent focused on the first capability: **identity and enrollment**.

This repo is intentionally independent from the OpenSearch Dashboards plugin repo.

## Current MVP scope

- Generates and persists a stable `agent_id`.
- Collects host identity: machine ID, hostname, OS, architecture, IPv4 addresses.
- Performs secure enrollment to a control plane over HTTP(S).
- Stores enrollment status in local state.
- Runs as a low-overhead systemd service with periodic re-enrollment attempts.

## Project layout

- `cmd/xdr-agent` - CLI entrypoint (`run`, `enroll`, `version`)
- `internal/config` - JSON config loader
- `internal/identity` - local identity/state management
- `internal/enroll` - control-plane enrollment client
- `internal/service` - runtime loop and retry scheduling
- `systemd/xdr-agent.service` - service unit
- `packaging/deb` - Debian package build and maintainer scripts
- `packaging/rpm` - RPM package spec template and build script
- `packaging/build_multi_arch.sh` - multi-arch packaging orchestrator

## Configuration

Default config path: `/etc/xdr-agent/config.json`

Sample file: `config/config.json`

Required values for real enrollment:

- `control_plane_url` (for example `https://xdr-manager.example.com`)
- `enrollment_path` (for example `/api/v1/agents/enroll`)
- `policy_id`
- `enroll_interval_seconds` (> 0)
- `request_timeout_seconds` (> 0)
- `state_path`

Optional:

- `enrollment_token` for bearer auth
- `tags`
- `insecure_skip_tls_verify` (keep `false` in production)

`config/config.json` is the single source for default values used by this project.

## Local build and test

Default version source: `VERSION` (for example `0.1.0`).

You can bump once for all build/package commands:

```bash
echo "0.1.1" > VERSION
```

```bash
cd /home/kplrm/github/xdr-agent
make build
./dist/xdr-agent version
./dist/xdr-agent enroll --config ./config/config.json
```

## Build Debian package

```bash
cd /home/kplrm/github/xdr-agent
chmod +x packaging/deb/build.sh packaging/deb/postinst packaging/deb/prerm
make deb
```

Optional override (without editing `VERSION`):

```bash
make deb VERSION=0.1.0
```

Package output:

- `dist/xdr-agent_0.1.0_amd64.deb`

## Build RPM package

Prerequisite on Debian/Ubuntu build hosts:

```bash
sudo apt install rpm
```

Then build:

```bash
cd /home/kplrm/github/xdr-agent
chmod +x packaging/rpm/build.sh
bash ./packaging/rpm/build.sh "$(cat VERSION)" amd64
```

## Build multi-architecture packages

Build both `amd64` and `arm64` for both `deb` and `rpm`:

```bash
cd /home/kplrm/github/xdr-agent
chmod +x packaging/build_multi_arch.sh packaging/deb/build.sh packaging/rpm/build.sh
bash ./packaging/build_multi_arch.sh
```

You can customize with env vars:

```bash
ARCHES="amd64 arm64" FORMATS="deb rpm" bash ./packaging/build_multi_arch.sh "$(cat VERSION)"
```

## Install on Debian/Ubuntu

```bash
sudo dpkg -i dist/xdr-agent_0.1.0_amd64.deb
sudo systemctl status xdr-agent
sudo journalctl -u xdr-agent -f
```

## Notes on control-plane compatibility

Current enrollment request schema sent by agent:

```json
{
  "agent_id": "...",
  "machine_id": "...",
  "hostname": "...",
  "architecture": "amd64",
  "os_type": "linux",
  "ip_addresses": ["10.0.0.12"],
  "policy_id": "default-endpoint",
  "tags": ["linux", "xdr-agent"],
  "agent_version": "<VERSION>"
}
```

Expected response body (minimal):

```json
{
  "enrollment_id": "server-generated-id",
  "message": "enrolled"
}
```
