// Package telemetry provides endpoint visibility by collecting system events
// from the host. This is the foundation of the XDR agent — all detection,
// prevention, and compliance capabilities consume telemetry data.
//
// Sub-packages:
//   - process/   — Process creation, termination, and tree tracking
//   - file/      — File system events and integrity monitoring
//   - network/   — Network connection and DNS monitoring
//   - session/   — User session and privilege monitoring
//   - kernel/    — Kernel module and eBPF telemetry
//   - audit/     — auditd and syslog collection
//   - scheduled/ — Cron, at, systemd timer monitoring
package telemetry

// Manager orchestrates all telemetry collectors.
// It implements the capability.Capability interface to be managed by the agent.

// TODO: Implement telemetry manager
// - Register sub-collectors (process, file, network, etc.)
// - Start/stop collectors based on policy
// - Route collected events to the event pipeline
