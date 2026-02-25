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
	AgentID     string   `json:"agent_id"`
	MachineID   string   `json:"machine_id"`
	Hostname    string   `json:"hostname"`
	PolicyID    string   `json:"policy_id"`
	Tags        []string `json:"tags"`
	AgentVersion string  `json:"agent_version"`
}

func Heartbeat(ctx context.Context, cfg config.Config, state identity.State, version string) error {
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
		return fmt.Errorf("marshal heartbeat payload: %w", err)
	}

	endpoint, err := joinURL(cfg.ControlPlaneURL, cfg.HeartbeatPath)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("build heartbeat request: %w", err)
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
		return fmt.Errorf("send heartbeat request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return fmt.Errorf("read heartbeat response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return nil
}
