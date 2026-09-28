# Agent architecture

The supported runtime collects process, file, and network telemetry and protects Linux hosts using release-bundled YARA Forge Core rules. Coordinator policies group agents.

## Runtime

`internal/service/run.go` owns startup and shutdown:

1. Load local configuration and persistent identity.
2. Start event dispatch and runtime log capture.
3. Initialize the embedded YARA release and, in prevention mode, local execution protection.
4. Start process, file integrity, file access, network connection, and DNS collectors.
5. Enroll or retry enrollment without stopping local protection.
6. Send immediate and periodic health reports, poll upgrade commands, and ship gzip batches.
7. Stop collectors, drain event/log queues, and attempt a bounded final shipment.

`internal/enroll` implements Coordinator requests; `internal/controlplane` batches and delivers events. The complete agent HTTP surface is documented and checked in [api-endpoints.md](api-endpoints.md). The endpoint agent has no inbound HTTP listener.

## Protection and content

The release build selects explicitly Linux-targeted YARA Forge Core rules and their compatible dependencies, excluding Windows and other incompatible rules. Generated source is embedded into the binary so protection does not depend on a rule download at enrollment. The source release and filtered digest identify the installed inventory.

YARA compilation and scanning use the native `yarac` and `yara` executables. Initialization fails visibly if the installed scanner or rules cannot be loaded. Process/file telemetry drives scanning; fanotify execution permission events allow decisions before executable launch under explicitly configured directories. The event reader starts before any directory marks are installed and stays active during watch refresh. A YARA match can deny execution or terminate a matching running process after verifying its identity. Detection is the local default; prevention must be selected explicitly. Two execution scan workers share a bounded queue. Each permission request has a 500 ms deadline from kernel delivery; overload, timeout, or response failure allows execution, disables fanotify blocking until restart, and reports degraded health. Directory roots are counted before any blocking mark is installed; an oversized tree disables pre-execution blocking while detection and verified process termination continue.

Heartbeat metadata reports installed source/version/digest, rule count, mode, and runtime health. Availability of scanning and execution blocking must be reported separately. No remote rule editing, rule feed ingestion, or bundle rollout runs on the endpoint.

## Telemetry

- `telemetry.process`: procfs snapshots, process lifecycle, executable and parent context.
- `telemetry.file`: inotify plus periodic integrity rescans of selected critical configuration paths; broad binary and package directories are excluded from the startup baseline, and scans pause briefly between 16-file batches.
- `telemetry.file.access`: access events for sensitive paths.
- `telemetry.network`: procfs connection snapshots and process attribution.
- `telemetry.dns`: DNS traffic capture; requires packet capture privileges.

Process and network snapshots run no faster than every five seconds, even with an older config requesting a shorter interval, and gzip batches ship every 30 seconds. The systemd service uses a 75% CPU quota, lower CPU priority, and memory limits. Polling can miss short-lived processes and connections. File monitoring covers watched paths. The default execution watch roots are `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/tmp`, `/var/tmp`, and `/home`. Existing subdirectories are marked recursively only when the complete configured tree fits within 2,048 directory watches. Oversized trees do not install blocking watches and health reports degraded; process/file YARA scanning remains available. Watches refresh every 30 seconds while below the cap; new directories have a coverage gap until refresh. The file-integrity baseline is separate from these execution watches. Interpreted scripts and execution outside these paths are not universally intercepted. Fanotify coverage depends on kernel, privileges, and filesystem support; a degraded health report does not mean execution is blocked everywhere.

## Removed and deferred scope

Unused orchestrators, remote response shell/playbooks, vulnerability/compliance/cloud modules, extra telemetry domains, hash feed synchronization, behavioral engines, ransomware rollback, and memory detection are removed from the active runtime. Process environment, script-content capture, and executable hashing are excluded to keep collection bounded. XDR Defense and XDR Sentry are outside the current work scope.
