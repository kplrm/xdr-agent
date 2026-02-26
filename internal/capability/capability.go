// Package capability defines the interface that all XDR security capabilities must implement.
// Each capability (telemetry, detection, prevention, response, compliance, etc.) registers
// itself with the agent and is managed through this common lifecycle interface.
package capability

import "context"

// HealthStatus represents the operational state of a capability.
type HealthStatus int

const (
	HealthUnknown  HealthStatus = iota
	HealthStarting              // Capability is initializing
	HealthRunning               // Capability is operating normally
	HealthDegraded              // Capability is running with reduced functionality
	HealthStopped               // Capability has been stopped
	HealthFailed                // Capability encountered an unrecoverable error
)

func (h HealthStatus) String() string {
	switch h {
	case HealthStarting:
		return "starting"
	case HealthRunning:
		return "running"
	case HealthDegraded:
		return "degraded"
	case HealthStopped:
		return "stopped"
	case HealthFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Capability is the interface every security module must satisfy to be managed by the agent.
//
// Lifecycle:
//  1. The agent calls Init() once during startup to pass configuration and dependencies.
//  2. The agent calls Start() to begin the capability's work (monitoring, scanning, etc.).
//  3. The agent calls Stop() during graceful shutdown or when the capability is disabled via policy.
//  4. Health() may be called at any time to check operational status.
type Capability interface {
	// Name returns a dot-separated identifier, e.g. "telemetry.process" or "detection.malware".
	Name() string

	// Init prepares the capability with its dependencies. Called once before Start.
	Init(deps Dependencies) error

	// Start begins the capability's main work. ctx is canceled on agent shutdown.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the capability and releases resources.
	Stop() error

	// Health returns the current operational status of the capability.
	Health() HealthStatus
}

// Dependencies bundles the common services that capabilities may need.
// This avoids each capability needing to wire up its own infrastructure.
type Dependencies struct {
	// EventPipeline is the central event bus for emitting telemetry and alerts.
	// All capabilities should emit structured events here.
	EventPipeline interface{} // will be *events.Pipeline once that package is built

	// Config provides access to the agent's configuration, including
	// per-capability settings.
	Config interface{} // will be config.Config once expanded

	// Logger provides structured logging.
	Logger interface{} // will be *slog.Logger or similar
}
