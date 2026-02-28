package controlplane

import (
	"context"
	"fmt"
	"strings"

	"xdr-agent/internal/identity"
)

// HeartbeatRequest is the payload sent to the control plane on each heartbeat.
type HeartbeatRequest struct {
	AgentID      string   `json:"agent_id"`
	MachineID    string   `json:"machine_id"`
	Hostname     string   `json:"hostname"`
	PolicyID     string   `json:"policy_id"`
	Tags         []string `json:"tags"`
	AgentVersion string   `json:"agent_version"`
}

// Heartbeat sends a periodic heartbeat signal to the control plane.
// The heartbeat confirms the agent is alive and transmits basic identity metadata
// so the control plane can track connected agents.
func (c *Client) Heartbeat(ctx context.Context, state identity.State, policyID string, tags []string, version string) error {
	payload := HeartbeatRequest{
		AgentID:      state.AgentID,
		MachineID:    state.MachineID,
		Hostname:     state.Hostname,
		PolicyID:     policyID,
		Tags:         tags,
		AgentVersion: version,
	}

	respBody, status, err := c.doJSON(ctx, c.heartbeatPath, payload)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}

	if status < 200 || status >= 300 {
		return fmt.Errorf("heartbeat rejected: status=%d body=%s", status, strings.TrimSpace(string(respBody)))
	}

	return nil
}
