package enroll

import (
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

// PollCommands queries the lightweight /commands endpoint for any pending
// actions (e.g. "upgrade:0.3.3"). Unlike Heartbeat it does not send a full
// status payload and does not update the agent's lastSeen timestamp on the
// server, making it safe to poll frequently (default every 5 s).
func PollCommands(ctx context.Context, cfg config.Config, state identity.State, version string) (HeartbeatResponse, error) {
	endpoint, err := joinURL(cfg.ControlPlaneURL, cfg.CommandsPath)
	if err != nil {
		return HeartbeatResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return HeartbeatResponse{}, fmt.Errorf("build commands request: %w", err)
	}

	q := req.URL.Query()
	q.Set("agent_id", state.AgentID)
	q.Set("agent_version", version)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("User-Agent", "xdr-agent")
	req.Header.Set("osd-xsrf", "true")

	client := &http.Client{
		Timeout: cfg.RequestTimeout(),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipTLSVerify}, //nolint:gosec
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return HeartbeatResponse{}, fmt.Errorf("send commands request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return HeartbeatResponse{}, fmt.Errorf("read commands response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return HeartbeatResponse{}, fmt.Errorf("commands rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var cmdResp HeartbeatResponse
	if err := json.Unmarshal(respBody, &cmdResp); err != nil {
		return HeartbeatResponse{}, nil
	}

	return cmdResp, nil
}
