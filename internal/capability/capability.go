// Package capability defines the interface that all XDR security capabilities must implement.
// Retained telemetry collectors share this lifecycle and health interface.
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

// Dependencies is reserved for collector initialization; collectors receive typed
// dependencies through their constructors.
type Dependencies struct{}
