# xdr-agent

Linux endpoint for process, file, and network telemetry with release-bundled YARA Forge Core rules. Detection is the default: matches generate alerts without stopping execution. Check the mode in the config passed to `enroll`; enrollment copies that file into the installed service config, including an existing `prevent` setting. Set `detection_prevention.mode` to `prevent` to enable execution denial and termination of matched processes. The installed rules change with agent releases.

## Build, test, and install locally (Debian/Ubuntu, amd64)

Set `control_plane_url` in `./config/config.json` to your Coordinator URL (`http://localhost:5601` if local). Leave `enrollment_token` empty. Packages use `config/config.default.json` as their token-free template; the installed service reads `/etc/xdr-agent/config.json`. If that installed file already exists, edit it directly; reinstalling preserves it. Set `max_cpu_cores` to the maximum logical CPUs the Agent and YARA may use (default `1`; `0` uses all available CPUs). The systemd unit also limits the service to 75% of one CPU and gives it lower CPU priority. Restart the service after editing the installed config. In prevention mode, execution blocking checks the complete `execution_watch_paths` tree before installing watches. If it exceeds 2,048 directories, blocking stays off and the Agent reports degraded health while YARA detection and verified process termination continue. Slow execution scans fail open after 500 ms. `make test` checks fanotify decisions and these failure paths inside a disposable Docker container.

```bash
make build
make test
make deb
sudo apt install "./dist/xdr-agent_$(cat VERSION)_amd64.deb"
sudo /usr/bin/xdr-agent enroll '<TOKEN>' --config ./config/config.json
```

Replace `<TOKEN>` with the token from **Coordinator → Enroll new XDR**. Enrollment reads `--config`, saves the enrolled config to `/etc/xdr-agent/config.json` without changing the source file, and starts the service. `make build` creates a binary; `make deb` packages it with the systemd unit. The agent uses the external `yara` and `yarac` programs; installing the DEB pulls in the `yara` package automatically. `make test` runs a non-root, CPU-limited post-enrollment smoke test and a bounded Docker prevention test before packaging. Without it, `make test` skips the native YARA scanner test.

## Operate and remove

```bash
sudo systemctl status xdr-agent.service
sudo journalctl -u xdr-agent.service -f
sudo systemctl stop xdr-agent.service
sudo systemctl start xdr-agent.service
sudo systemctl restart xdr-agent.service
sudo apt purge xdr-agent
```

`apt purge` also deletes `/etc/xdr-agent` and `/var/lib/xdr-agent`, including enrollment identity and local state. `apt remove` keeps them for reinstall. The `_apt` "unsandboxed" notice during local installation only means `_apt` could not read the `.deb` inside your home directory; installation still succeeds.

[Architecture](docs/architecture.md) · [API endpoints](docs/api-endpoints.md) · [Roadmap](docs/roadmap.md)
