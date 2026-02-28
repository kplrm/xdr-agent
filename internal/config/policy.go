package config

// Policy represents the security policy received from the control plane.
// Policies control which capabilities are enabled and their runtime configuration.
type Policy struct {
	// Version is the policy version for change detection.
	Version string `json:"version"`

	// Capabilities maps capability names (e.g., "telemetry.process") to their policy settings.
	Capabilities map[string]CapabilityPolicy `json:"capabilities"`
}

// CapabilityPolicy defines the per-capability policy settings.
type CapabilityPolicy struct {
	// Enabled controls whether the capability should be running.
	Enabled bool `json:"enabled"`

	// Settings holds capability-specific key-value configuration.
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// IsEnabled checks if a named capability is enabled in the policy.
// If the capability is not listed or the policy is nil, it defaults to false.
func (p *Policy) IsEnabled(name string) bool {
	if p == nil || p.Capabilities == nil {
		return false
	}
	cp, ok := p.Capabilities[name]
	if !ok {
		return false
	}
	return cp.Enabled
}

// GetSettings returns the settings map for a named capability, or nil if not found.
func (p *Policy) GetSettings(name string) map[string]interface{} {
	if p == nil || p.Capabilities == nil {
		return nil
	}
	cp, ok := p.Capabilities[name]
	if !ok {
		return nil
	}
	return cp.Settings
}
