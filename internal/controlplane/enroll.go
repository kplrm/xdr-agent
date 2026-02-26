package controlplane

// Enroll performs agent enrollment with the control plane.
// This is the migration target for the current internal/enroll/client.go logic.

// TODO: Migrate enrollment logic from internal/enroll/client.go
// - EnrollRequest / EnrollResponse types
// - Enroll(ctx, state, version) method on Client
