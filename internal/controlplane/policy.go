package controlplane

// Policy sync is a placeholder for Phase 1. The control plane does not yet
// expose a policy endpoint. When it does, PullPolicy will fetch the latest
// policy document and the agent orchestrator will apply capability changes.

// TODO: Implement when the control-plane plugin adds a policy endpoint:
// - PullPolicy(ctx, agentID) (*config.Policy, error)
// - Compare policy.Version to detect changes
// - Notify agent orchestrator to start/stop capabilities accordingly
