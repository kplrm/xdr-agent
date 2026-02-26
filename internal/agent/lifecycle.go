package agent

import (
	"log"

	"xdr-agent/internal/capability"
)

// HealthReport contains the health status of all registered capabilities.
type HealthReport struct {
	Capabilities map[string]capability.HealthStatus
}

// Lifecycle provides startup, shutdown, and health-check helpers for the agent.

// HealthCheck returns the health status of all registered capabilities.
func (a *Agent) HealthCheck() HealthReport {
	a.mu.Lock()
	defer a.mu.Unlock()

	report := HealthReport{
		Capabilities: make(map[string]capability.HealthStatus, len(a.capabilities)),
	}
	for _, cap := range a.capabilities {
		report.Capabilities[cap.Name()] = cap.Health()
	}
	return report
}

// LogHealth prints the health status of every capability.
func (a *Agent) LogHealth() {
	report := a.HealthCheck()
	for name, status := range report.Capabilities {
		log.Printf("capability health: %s = %s", name, status)
	}
}
