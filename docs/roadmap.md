# Agent roadmap

Updated: 2026-09-28

## Current scope

- Linux `amd64`/`arm64` process, file, and network telemetry.
- Release-bundled Linux-relevant YARA Forge Core content.
- Detection by default; optional execution denial on configured fanotify directories and verified process termination.
- Coordinator enrollment, periodic health, grouped fleet policies, and agent upgrades.
- Health every 30 seconds; compressed telemetry, security, and log batches every 30 seconds.
- A central HTTP contract with build-time endpoint regression checks.

## Release gates

- Refresh the upstream Core snapshot for a new release and record its version/digest.
- Validate filtering and compile the complete selected ruleset with the packaged scanner.
- Run agent tests, API contract checks, a non-root post-enrollment CPU smoke test, a disposable-container fanotify allow/deny test, and package checks for all supported architectures.
- Verify real fanotify denial and process termination on disposable privileged Linux VMs; unprivileged tests alone do not establish kernel enforcement coverage.

## Next reliability work

- Durable disk buffering and replay across service crashes and long Coordinator outages.
- Measure rule compilation/scanning latency, missed decisions at the 500 ms deadline, and memory use on realistic hosts. Add cached or in-process scanning before enabling broad pre-execution watch trees.
- Expand kernel/filesystem execution-blocking coverage tests, including directory/mount changes and interpreted scripts.
- Improve short-lived process/network visibility where polling loses events.

## Deferred scope

XDR Defense and XDR Sentry need separate redesigns. Ransomware, memory, and behavioral protection, Windows support, remote shell/playbooks, compliance scanning, and cloud posture have no work scheduled in this Agent roadmap.
