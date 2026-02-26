package controlplane

// Policy handles pulling security policy from the control plane and applying
// it to enable/disable capabilities and configure their parameters.

// TODO: Implement policy sync
// - PolicyResponse type (per-capability enable/disable + settings)
// - PullPolicy(ctx) method on Client
// - Policy change notification to agent orchestrator
