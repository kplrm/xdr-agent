package controlplane

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client handles all HTTP communication with the XDR control plane.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new control-plane client.
func NewClient(baseURL, token string, timeout time.Duration, insecureSkipTLS bool) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipTLS},
			},
		},
	}
}

// SetToken updates the bearer token.
func (c *Client) SetToken(token string) {
	c.token = token
}

// buildURL joins the base URL with a path.
func (c *Client) buildURL(path string) (string, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	return u.String(), nil
}
