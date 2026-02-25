# xdr-agent

Lightweight XDR agent focused on the first capability: **identity and enrollment**.

This repo is intentionally independent from the OpenSearch Dashboards plugin repo.

## Current MVP scope

- Generates and persists a stable `agent_id`.
- Collects host identity: machine ID, hostname, OS, architecture, IPv4 addresses.
- Performs secure enrollment to a control plane over HTTP(S).
- Sends heartbeat every 30 seconds after successful enrollment.
- Stores enrollment status in local state.
- Runs as a low-overhead systemd service.

## Project layout

- `cmd/xdr-agent` - CLI entrypoint (`run`, `enroll`, `remove`, `version`)
- `internal/config` - JSON config loader
- `internal/identity` - local identity/state management
- `internal/enroll` - control-plane enrollment client
- `internal/service` - runtime loop, enrollment retry, and heartbeat scheduling
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
- `heartbeat_path` (for example `/api/v1/agents/heartbeat`)
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

Prerequisite (Debian/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y golang-go
go version
```

Default version source: `VERSION` (for example `0.1.0`).

You can bump once for all build/package commands:

```bash
echo "0.1.1" > VERSION
```

```bash
cd xdr-agent
make build
./dist/xdr-agent version
./dist/xdr-agent run --config ./config/config.json
./dist/xdr-agent enroll <enrollment_token> --config ./config/config.json
./dist/xdr-agent completion bash
```

## Bash completion

Generate completion script from a local build:

```bash
source <(./dist/xdr-agent completion bash)
```

After `.deb` installation, completion is installed automatically at:

- `/etc/bash_completion.d/xdr-agent`

Open a new shell session (or run `source /etc/bash_completion.d/xdr-agent`) and tab-complete:

- `xdr-agent <TAB>` → `run`, `enroll`, `remove`, `version`, `completion`, `help`
- `sudo xdr-agent <TAB>` → same command suggestions

## Build Debian package

Prerequisites:

- Go toolchain available in `PATH` (`go version` must work)
- `dpkg-deb` installed (part of `dpkg` on Debian/Ubuntu)

```bash
cd xdr-agent
chmod +x packaging/deb/build.sh packaging/deb/postinst packaging/deb/prerm
make deb
ls -lh dist/*.deb
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
cd xdr-agent
chmod +x packaging/rpm/build.sh
bash ./packaging/rpm/build.sh "$(cat VERSION)" amd64
```

## Build multi-architecture packages

Build both `amd64` and `arm64` for both `deb` and `rpm`:

```bash
cd xdr-agent
chmod +x packaging/build_multi_arch.sh packaging/deb/build.sh packaging/rpm/build.sh
bash ./packaging/build_multi_arch.sh
```

You can customize with env vars:

```bash
ARCHES="amd64 arm64" FORMATS="deb rpm" bash ./packaging/build_multi_arch.sh "$(cat VERSION)"
```

## Install on Debian/Ubuntu

```bash
cd xdr-agent
sudo dpkg -i dist/xdr-agent_$(cat VERSION)_amd64.deb
sudo systemctl daemon-reload
sudo xdr-agent enroll <enrollment_token> --config config/config.json
sudo systemctl enable xdr-agent
sudo systemctl start xdr-agent
sudo systemctl status xdr-agent
sudo journalctl -u xdr-agent -f
```

Installation does **not** auto-start the service by default.
This prevents restart loops while you are still editing `/etc/xdr-agent/config.json`.

Recommended flow:

1. Install package.
2. Update `/etc/xdr-agent/config.json` with `control_plane_url`, `policy_id`, `enrollment_token`.
3. Start service with `sudo systemctl start xdr-agent`.

Expected process command line after installation:

- `/usr/bin/xdr-agent run --config /etc/xdr-agent/config.json`

## Troubleshooting build/install

`make deb` fails with `go: command not found`:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
go version
```

Service not found after install:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now xdr-agent
systemctl status xdr-agent --no-pager -l
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

## OpenSearch Dashboards xdr-manager-plugin compatibility

For the plugin at `OpenSearch-Dashboards/plugins/xdr-manager-plugin`:

1. Generate an enrollment token from the plugin UI (**Enroll XDR** flyout).
2. Use `control_plane_url` pointing to OpenSearch Dashboards (default local: `http://localhost:5601`).
3. Keep `enrollment_path` as `/api/v1/agents/enroll`.
4. Set `enrollment_token` to the generated token.
5. Set `policy_id` to the same policy used when generating the token.
6. Keep `heartbeat_path` as `/api/v1/agents/heartbeat`.

The plugin validates the bearer token and rejects enrollment when the token is invalid or policy mismatched.
