package controlplane

// Heartbeat sends periodic heartbeat signals to the control plane.
// This is the migration target for the current internal/enroll/heartbeat.go logic.

// TODO: Migrate heartbeat logic from internal/enroll/heartbeat.go
// - HeartbeatRequest type
// - Heartbeat(ctx, state, version) method on Client
