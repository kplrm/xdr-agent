package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"xdr-agent/internal/config"
	"xdr-agent/internal/identity"
)

type HeartbeatRequest struct {
	AgentID      string   `json:"agent_id"`
	MachineID    string   `json:"machine_id"`
	Hostname     string   `json:"hostname"`
	PolicyID     string   `json:"policy_id"`
	Tags         []string `json:"tags"`
	AgentVersion string   `json:"agent_version"`
}

// HeartbeatResponse holds the fields returned by the control plane on a
// successful heartbeat. PendingCommands lists any operations the agent must
// perform (e.g. "upgrade:0.3.2").
type HeartbeatResponse struct {
	Message         string   `json:"message"`
	PendingCommands []string `json:"pending_commands"`
}

// Heartbeat sends a heartbeat to the control plane and returns the server's
// response (including any pending commands) and an error.
func Heartbeat(ctx context.Context, cfg config.Config, state identity.State, version string) (HeartbeatResponse, error) {
	payload := HeartbeatRequest{
		AgentID:      state.AgentID,
		MachineID:    state.MachineID,
		Hostname:     state.Hostname,
		PolicyID:     cfg.PolicyID,
		Tags:         cfg.Tags,
		AgentVersion: version,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return HeartbeatResponse{}, fmt.Errorf("marshal heartbeat payload: %w", err)
	}

	endpoint, err := joinURL(cfg.ControlPlaneURL, cfg.HeartbeatPath)
	if err != nil {
		return HeartbeatResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return HeartbeatResponse{}, fmt.Errorf("build heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xdr-agent")
	req.Header.Set("osd-xsrf", "true")

	client := &http.Client{
		Timeout: cfg.RequestTimeout(),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipTLSVerify},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return HeartbeatResponse{}, fmt.Errorf("send heartbeat request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return HeartbeatResponse{}, fmt.Errorf("read heartbeat response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return HeartbeatResponse{}, fmt.Errorf("heartbeat rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var hbResp HeartbeatResponse
	if err := json.Unmarshal(respBody, &hbResp); err != nil {
		// Non-fatal: log a warning but don't fail the heartbeat
		return HeartbeatResponse{Message: string(respBody)}, nil
	}

	return hbResp, nil
}
