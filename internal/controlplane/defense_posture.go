package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xdr-agent/internal/config"
)

// DefensePosture is the local/stateful view of posture used by the agent.
type DefensePosture struct {
	PolicyID     string          `json:"policy_id"`
	Mode         string          `json:"mode"`
	Capabilities map[string]bool `json:"capabilities"`
	Version      int64           `json:"version"`
	UpdatedAt    string          `json:"updatedAt"`
	ReceivedAt   string          `json:"receivedAt"`
}

type defensePostureOverlayResponse struct {
	ManagerPolicyID string          `json:"manager_policy_id"`
	Mode            string          `json:"mode"`
	Capabilities    map[string]bool `json:"capabilities"`
	UpdatedAt       string          `json:"updatedAt"`
	Version         int64           `json:"version"`
}

// DefensePostureFetchError is returned when the posture endpoint responds with
// a non-2xx status code.
type DefensePostureFetchError struct {
	StatusCode int
	Body       string
}

func (e *DefensePostureFetchError) Error() string {
	return fmt.Sprintf("Defense Posture fetch rejected: status=%d body=%s", e.StatusCode, strings.TrimSpace(e.Body))
}

// DefensePostureAckRequest confirms that a posture version has been delivered.
type DefensePostureAckRequest struct {
	AgentID        string `json:"agent_id"`
	PolicyID       string `json:"policy_id"`
	PostureVersion int64  `json:"posture_version"`
	Hostname       string `json:"hostname"`
}

func LoadDefensePosture(path string) (DefensePosture, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return DefensePosture{}, err
	}

	var posture DefensePosture
	if err := json.Unmarshal(content, &posture); err != nil {
		return DefensePosture{}, fmt.Errorf("parse Defense Posture state %s: %w", path, err)
	}
	if posture.Capabilities == nil {
		posture.Capabilities = map[string]bool{}
	}
	return posture, nil
}

func SaveDefensePosture(path string, posture DefensePosture) error {
	if posture.ReceivedAt == "" {
		posture.ReceivedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if posture.Capabilities == nil {
		posture.Capabilities = map[string]bool{}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create Defense Posture state dir: %w", err)
	}

	content, err := json.MarshalIndent(posture, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Defense Posture state: %w", err)
	}
	content = append(content, '\n')

	if err := os.WriteFile(path, content, 0o640); err != nil {
		return fmt.Errorf("write Defense Posture state %s: %w", path, err)
	}
	return nil
}

func ShouldApplyDefensePosture(cached DefensePosture, fetched DefensePosture) bool {
	return fetched.Version > cached.Version
}

// ApplyDefensePosture applies posture mode/capability toggles onto runtime config.
// Unknown capability keys are ignored to keep compatibility with new server-side keys.
func ApplyDefensePosture(cfg *config.Config, posture DefensePosture) {
	if cfg == nil {
		return
	}

	switch strings.ToLower(strings.TrimSpace(posture.Mode)) {
	case string(config.ModeDetect):
		cfg.DetectionPrevention.Mode = config.ModeDetect
	case string(config.ModePrevent):
		cfg.DetectionPrevention.Mode = config.ModePrevent
	}

	for key, enabled := range posture.Capabilities {
		switch key {
		case "malware.hash_detection":
			cfg.DetectionPrevention.Capabilities.Malware.HashDetection = enabled
		case "malware.yara_detection":
			cfg.DetectionPrevention.Capabilities.Malware.YaraDetection = enabled
		case "malware.static_detection":
			cfg.DetectionPrevention.Capabilities.Malware.StaticDetection = enabled
		case "malware.execution_blocking":
			cfg.DetectionPrevention.Capabilities.Malware.ExecutionBlocking = enabled
		case "ransomware.behavior_detection":
			cfg.DetectionPrevention.Capabilities.Ransomware.BehaviorDetection = enabled
		case "ransomware.shield":
			cfg.DetectionPrevention.Capabilities.Ransomware.Shield = enabled
		case "behavioral.rules":
			cfg.DetectionPrevention.Capabilities.Behavioral.Rules = enabled
		case "threatintel.local_ioc_match":
			cfg.DetectionPrevention.Capabilities.ThreatIntel.LocalIOCMatch = enabled
		case "memory.injection":
			cfg.DetectionPrevention.Capabilities.Memory.Injection = enabled
		case "memory.hollowing":
			cfg.DetectionPrevention.Capabilities.Memory.Hollowing = enabled
		case "memory.fileless":
			cfg.DetectionPrevention.Capabilities.Memory.Fileless = enabled
		case "rollback.enabled":
			cfg.DetectionPrevention.Capabilities.Rollback.Enabled = enabled
		case "prevention.enabled":
			cfg.DetectionPrevention.Capabilities.Prevention.Enabled = enabled
		case "correlation.opensearch_time_window":
			cfg.DetectionPrevention.Capabilities.Correlation.OpenSearchTimeWindow = enabled
		case "local_updates.enable_hot_reload":
			cfg.DetectionPrevention.Capabilities.LocalUpdates.EnableHotReload = enabled
		}
	}
}

func (c *Client) FetchDefensePosture(ctx context.Context, policyID string) (DefensePosture, error) {
	path := "/api/xdr-defense/policy-overlays/" + url.PathEscape(policyID)
	endpoint, err := c.buildURL(path)
	if err != nil {
		return DefensePosture{}, fmt.Errorf("build Defense Posture endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return DefensePosture{}, fmt.Errorf("build Defense Posture request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "xdr-agent")
	req.Header.Set("osd-xsrf", "true")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return DefensePosture{}, fmt.Errorf("fetch Defense Posture: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return DefensePosture{}, fmt.Errorf("read Defense Posture response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return DefensePosture{}, &DefensePostureFetchError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	var overlay defensePostureOverlayResponse
	if err := json.Unmarshal(respBody, &overlay); err != nil {
		return DefensePosture{}, fmt.Errorf("parse Defense Posture response: %w", err)
	}

	if overlay.Capabilities == nil {
		overlay.Capabilities = map[string]bool{}
	}

	return DefensePosture{
		PolicyID:     overlay.ManagerPolicyID,
		Mode:         overlay.Mode,
		Capabilities: overlay.Capabilities,
		Version:      overlay.Version,
		UpdatedAt:    overlay.UpdatedAt,
		ReceivedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (c *Client) AckDefensePosture(ctx context.Context, ackPath string, request DefensePostureAckRequest) error {
	if !strings.HasPrefix(ackPath, "/") {
		ackPath = "/" + ackPath
	}
	endpoint, err := c.buildURL(ackPath)
	if err != nil {
		return fmt.Errorf("build Defense Posture ACK endpoint: %w", err)
	}

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal Defense Posture ACK payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("build Defense Posture ACK request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "xdr-agent")
	httpReq.Header.Set("osd-xsrf", "true")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send Defense Posture ACK: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return fmt.Errorf("read Defense Posture ACK response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Defense Posture ACK rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return nil
}
