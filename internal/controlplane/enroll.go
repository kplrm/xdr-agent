package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xdr-agent/internal/identity"
)

// EnrollRequest is the payload sent to the control plane during enrollment.
type EnrollRequest struct {
	AgentID      string   `json:"agent_id"`
	MachineID    string   `json:"machine_id"`
	Hostname     string   `json:"hostname"`
	Architecture string   `json:"architecture"`
	OSType       string   `json:"os_type"`
	IPAddresses  []string `json:"ip_addresses"`
	PolicyID     string   `json:"policy_id"`
	Tags         []string `json:"tags"`
	AgentVersion string   `json:"agent_version"`
}

// EnrollResponse is the control plane's response to an enrollment request.
type EnrollResponse struct {
	EnrollmentID string `json:"enrollment_id"`
	Message      string `json:"message"`
}

// Enroll registers the agent with the control plane.
// On success it returns the enrollment ID and a human-readable message.
func (c *Client) Enroll(ctx context.Context, state identity.State, policyID string, tags []string, version string) (EnrollResponse, error) {
	payload := EnrollRequest{
		AgentID:      state.AgentID,
		MachineID:    state.MachineID,
		Hostname:     state.Hostname,
		Architecture: state.Architecture,
		OSType:       state.OSType,
		IPAddresses:  state.IPAddresses,
		PolicyID:     policyID,
		Tags:         tags,
		AgentVersion: version,
	}

	start := time.Now()
	respBody, status, err := c.doJSON(ctx, c.enrollPath, payload)
	if err != nil {
		return EnrollResponse{}, fmt.Errorf("enroll: %w", err)
	}

	if status < 200 || status >= 300 {
		return EnrollResponse{}, fmt.Errorf("enrollment rejected: status=%d body=%s", status, strings.TrimSpace(string(respBody)))
	}

	// Parse the enrollment response, allowing for an empty body which indicates
	// success with default values.
	var parsed EnrollResponse
	trimmed := strings.TrimSpace(string(respBody))
	if len(trimmed) == 0 {
		parsed.EnrollmentID = state.AgentID
		parsed.Message = "enrolled"
		return parsed, nil
	}

	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return EnrollResponse{}, fmt.Errorf("parse enrollment response: %w", err)
	}

	if parsed.EnrollmentID == "" {
		parsed.EnrollmentID = state.AgentID
	}
	if parsed.Message == "" {
		parsed.Message = fmt.Sprintf("enrolled in %s", time.Since(start).Round(time.Millisecond))
	}

	return parsed, nil
}
