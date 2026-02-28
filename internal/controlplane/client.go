package controlplane

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
)

// ClientConfig holds the parameters needed to create a control-plane Client.
type ClientConfig struct {
	BaseURL         string
	Token           string
	EnrollPath      string
	HeartbeatPath   string
	EventsPath      string
	Timeout         time.Duration
	InsecureSkipTLS bool
}

// Client handles all HTTP communication with the XDR control plane.
// It is the single shared HTTP client used by enrollment, heartbeat,
// event shipping, and policy sync.
type Client struct {
	baseURL       string
	token         string
	enrollPath    string
	heartbeatPath string
	eventsPath    string
	httpClient    *http.Client
}

// NewClient creates a new control-plane client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL:       strings.TrimSuffix(cfg.BaseURL, "/"),
		token:         cfg.Token,
		enrollPath:    cfg.EnrollPath,
		heartbeatPath: cfg.HeartbeatPath,
		eventsPath:    cfg.EventsPath,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipTLS},
			},
		},
	}
}

// SetToken updates the bearer token (e.g., after enrollment).
func (c *Client) SetToken(token string) {
	c.token = token
}

// buildURL joins the base URL with a path segment.
func (c *Client) buildURL(path string) (string, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid base URL: expected absolute URL")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	return u.String(), nil
}

// doJSON sends a JSON-encoded POST request to the given path and returns the
// response body, HTTP status code, and any transport-level error.
func (c *Client) doJSON(ctx context.Context, path string, payload interface{}) ([]byte, int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal payload: %w", err)
	}

	endpoint, err := c.buildURL(path)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xdr-agent")
	req.Header.Set("osd-xsrf", "true")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("send request to %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}
