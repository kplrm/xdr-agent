package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"xdr-agent/internal/config"
	"xdr-agent/internal/identity"
)

type Request struct {
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

type Response struct {
	EnrollmentID string `json:"enrollment_id"`
	Message      string `json:"message"`
}

func Enroll(ctx context.Context, cfg config.Config, state identity.State, version string) (Response, error) {
	payload := Request{
		AgentID:      state.AgentID,
		MachineID:    state.MachineID,
		Hostname:     state.Hostname,
		Architecture: state.Architecture,
		OSType:       state.OSType,
		IPAddresses:  state.IPAddresses,
		PolicyID:     cfg.PolicyID,
		Tags:         cfg.Tags,
		AgentVersion: version,
	}

	// Marshal the enrollment payload to JSON
	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, fmt.Errorf("marshal enrollment payload: %w", err)
	}

	// Build the enrollment request
	endpoint, err := joinURL(cfg.ControlPlaneURL, cfg.EnrollmentPath)
	if err != nil {
		return Response{}, err
	}

	// Create an HTTP request with the enrollment payload
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return Response{}, fmt.Errorf("build enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xdr-agent")
	if cfg.EnrollmentToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.EnrollmentToken)
	}

	client := &http.Client{
		Timeout: cfg.RequestTimeout(),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipTLSVerify},
		},
	}

	// Send the enrollment request and measure the time taken for the request
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("send enrollment request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body (limit to 32KB to prevent potential memory issues)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return Response{}, fmt.Errorf("read enrollment response: %w", err)
	}

	// Check for non-successful HTTP status codes and return an error with the response body for debugging
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("enrollment rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	// Parse the enrollment response, allowing for an empty body which indicates success with default values
	var parsed Response
	if len(strings.TrimSpace(string(respBody))) == 0 {
		parsed.EnrollmentID = state.AgentID
		parsed.Message = "enrolled"
		return parsed, nil
	}

	// Unmarshal the response body into the Response struct ("parsed" variable)
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return Response{}, fmt.Errorf("parse enrollment response: %w", err)
	}

	if parsed.EnrollmentID == "" {
		parsed.EnrollmentID = state.AgentID
	}
	if parsed.Message == "" {
		parsed.Message = fmt.Sprintf("enrolled in %s", time.Since(start).Round(time.Millisecond))
	}

	return parsed, nil
}

func joinURL(base, path string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return "", fmt.Errorf("invalid control_plane_url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid control_plane_url: expected absolute URL")
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	return u.String(), nil
}
