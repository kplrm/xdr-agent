package agent

import "xdr-agent/internal/capability"

// CapabilityFactory is a constructor function that creates a new capability instance.
type CapabilityFactory func() capability.Capability

// DefaultCapabilities returns the full set of capability factories that should
// be registered with the agent. Each capability is enabled/disabled via policy.
//
// The order matters: telemetry capabilities start first (they feed data to detections),
// then detection, then prevention, then response.
func DefaultCapabilities() []CapabilityFactory {
	return []CapabilityFactory{
		// ── Telemetry (endpoint visibility) ──
		// TODO: telemetry.NewProcessMonitor,
		// TODO: telemetry.NewFileMonitor,
		// TODO: telemetry.NewNetworkMonitor,
		// TODO: telemetry.NewSessionMonitor,
		// TODO: telemetry.NewKernelMonitor,
		// TODO: telemetry.NewAuditCollector,
		// TODO: telemetry.NewScheduledTaskMonitor,

		// ── Detection engines ──
		// TODO: detection.NewMalwareScanner,
		// TODO: detection.NewBehavioralEngine,
		// TODO: detection.NewMemoryScanner,
		// TODO: detection.NewThreatIntelMatcher,

		// ── Prevention (blocking) ──
		// TODO: prevention.NewMalwareBlocker,
		// TODO: prevention.NewRansomwareShield,
		// TODO: prevention.NewExploitGuard,

		// ── Active response ──
		// TODO: response.NewManager,

		// ── Cloud & container ──
		// TODO: cloud.NewMetadataCollector,
		// TODO: cloud.NewContainerMonitor,

		// ── Periodic checks ──
		// TODO: compliance.NewManager,
		// TODO: vulnerability.NewScanner,
	}
}
