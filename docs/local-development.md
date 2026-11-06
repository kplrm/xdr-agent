# Local development

Use a rootless Podman container for detection and event-delivery development. Its process and filesystem visibility is limited to the container. For complete endpoint telemetry, prevention, and systemd testing, use a disposable Debian/Ubuntu VM: [containers share the host kernel](https://ubuntu.com/containers/what-are-containers).

Run commands from `xdr-agent/`. Requires Linux, Go 1.22+, Make, Python 3, and Podman. Start the [local XDR stack](https://github.com/kplrm/xdr-security/blob/main/docs/local-development.md) with `xdr-agent/` beside `xdr-security/`. If Coordinator is also cloned, its build-time contract checks use the Node.js and Dashboards dependencies from that setup.

## 1. Build

Navigate to the `xdr-agent/` directory and fetch the rule snapshot once, then reuse it while iterating:

```bash
python3 tools/refresh_yara.py --output yara-forge-core/yara-rules-core.yar
export OSD_ROOT="$PWD/../.build/OpenSearch-Dashboards"
CGO_ENABLED=0 make build
```

This creates `dist/xdr-agent`; disabling CGO lets it run in the container without host C-library dependencies. After code changes, repeat only the build command.

## 2. Prepare the development container

Build the runtime image with only YARA, trusted CA certificates, and rsyslog plus their dependencies. It creates `/var/log/auth.log`, routes local authentication messages there, and starts rsyslog before the Agent. The Agent binary is mounted separately so code changes do not require rebuilding the image.

```bash
podman build -t localhost/xdr-agent-dev - <<'EOF'
FROM docker.io/library/debian:stable
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    yara ca-certificates rsyslog \
    && rm -rf /var/lib/apt/lists/* \
    && printf '%s\n' 'module(load="imuxsock")' 'auth,authpriv.* /var/log/auth.log' > /etc/rsyslog.conf \
    && install -m 640 /dev/null /var/log/auth.log
ENTRYPOINT ["/bin/sh", "-ec", "rsyslogd; exec /usr/local/bin/xdr-agent run --config /etc/xdr-agent/config.json"]
EOF
```

Create the development `config.json`.

```bash
mkdir -p ../.build/agent-dev
cp config/config.default.json ../.build/agent-dev/config.json
```

In this config copy, set:

- `control_plane_url`: `http://opensearch-dashboards:5601`.
- `enrollment_token`: a token from **Coordinator → Enroll new XDR Agent**, using the policy matching `policy_id`.

Keep `detection_prevention.mode` as `detect` and `opensearch.url` empty. Start from the token-free defaults above rather than an existing machine's config.

## 3. Run and send events

Use the same Podman user as the local XDR stack. This joins its default Compose network; if you changed the Compose project name, adjust the network name accordingly.

```bash
podman run --rm -it --name xdr-agent-dev --hostname xdr-agent-dev \
  --network xdr-security_opensearch-net \
  --cap-add NET_RAW \
  --cpus 1 --memory 512m --pids-limit 128 \
  -v "$PWD/dist/xdr-agent:/usr/local/bin/xdr-agent:ro,Z" \
  -v "$PWD/../.build/agent-dev:/etc/xdr-agent:Z" \
  -v xdr-agent-dev-state:/var/lib/xdr-agent \
  localhost/xdr-agent-dev
```

The foreground `run` command enrolls automatically and ships events after enrollment. It does not need systemd. Keep the config and named state volume across restarts to retain the Agent identity; stop with Ctrl+C, rebuild, and rerun the command after changes.

Delivery is **Agent → Coordinator → OpenSearch**. Coordinator writes runtime logs to `xdr-agent-logs`, activity to `xdr-agent-telemetry`, and alerts to `xdr-agent-security`. Check the Agent in Coordinator and the streams in Discover. The Agent needs no OpenSearch password for this route. Container-local `localhost` refers to the Agent container, so use the Dashboards service name above.

## 4. Inspect logs and health

The Agent writes runtime logs to the container's stderr, shown in the foreground terminal; it does not create an internal log file. From a second **host terminal**, follow the same output with [Podman logs](https://docs.podman.io/en/latest/markdown/podman-logs.1.html):

```bash
podman logs --tail 100 -f xdr-agent-dev
```

In this container:

- DNS requires `NET_RAW`. If you started without it, stop with Ctrl+C and rerun the updated command in step 3, keeping the config and state volume.
- Authentication tails `/var/log/auth.log`, supplied by the image above. To generate real PAM session messages from the host:

```bash
podman exec xdr-agent-dev su nobody -s /bin/sh -c true
podman exec xdr-agent-dev tail -n 10 /var/log/auth.log
```

These events exercise container authentication only; use a VM for full host coverage. Coordinator reflects collector health on the next heartbeat. Logs already shipped remain available in Discover under `xdr-agent-logs`; `--rm` removes the container's local logs when it exits.

## Full endpoint and package testing

In a disposable Debian/Ubuntu VM, install the build prerequisites, native YARA, and Docker. Run `make test` for the full regression suite; its fanotify test currently requires Docker and `CAP_SYS_ADMIN` and does not run as a normal rootless container test. See [validation guidelines](../CONTRIBUTING.md#development-and-validation).

For package/systemd testing on an AMD64 VM, replace `<TOKEN>` and `DEV_HOST_IP` with a fresh Coordinator token and the reachable development host address:

```bash
make deb
sudo apt install "./dist/xdr-agent_$(cat VERSION)_amd64.deb"
sudo /usr/bin/xdr-agent enroll '<TOKEN>' --config ./config/config.default.json \
  --control-plane-url 'http://DEV_HOST_IP:5601'
```

`make deb` also runs the regression suite. Enrollment copies the supplied config into `/etc/xdr-agent/config.json` and starts the service. The DEB installs YARA automatically; upgrades preserve the active config. Manage shared telemetry settings through **Coordinator → Policies → Edit**; edit local protection settings in the installed config and restart:

```bash
sudo systemctl restart xdr-agent.service
sudo journalctl -u xdr-agent.service -f
```

Remove with `sudo apt remove xdr-agent`; `sudo apt purge xdr-agent` also deletes configuration, enrollment identity, and local state.
