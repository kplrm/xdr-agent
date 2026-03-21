package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const DefaultConfigPath = "/etc/xdr-agent/config.json"

type Config struct {
	ControlPlaneURL       string   `json:"control_plane_url"`
	EnrollmentPath        string   `json:"enrollment_path"`
	HeartbeatPath         string   `json:"heartbeat_path"`
	EnrollmentToken       string   `json:"enrollment_token"`
	PolicyID              string   `json:"policy_id"`
	Tags                  []string `json:"tags"`
	EnrollIntervalSeconds int      `json:"enroll_interval_seconds"`
	RequestTimeoutSeconds int      `json:"request_timeout_seconds"`
	StatePath             string   `json:"state_path"`
	InsecureSkipTLSVerify bool     `json:"insecure_skip_tls_verify"`

	// Telemetry shipping — optional fields.
	// When TelemetryURL is empty the agent ships telemetry to ControlPlaneURL.
	// Setting a different URL allows routing through Kafka, Logstash, etc.
	TelemetryURL                 string `json:"telemetry_url,omitempty"`
	TelemetryPath                string `json:"telemetry_path,omitempty"`
	TelemetryIntervalSeconds     int    `json:"telemetry_interval_seconds,omitempty"`
	TelemetryShipIntervalSeconds int    `json:"telemetry_ship_interval_seconds,omitempty"`

	// Command polling — lightweight endpoint polled frequently to deliver
	// upgrade and other commands without waiting for the full heartbeat cycle.
	CommandsPath               string `json:"commands_path,omitempty"`
	CommandPollIntervalSeconds int    `json:"command_poll_interval_seconds,omitempty"`
}

// LoadRaw reads a config file and unmarshals it without validation.
// Useful for applying CLI overrides before saving back.
func LoadRaw(path string) (Config, error) {
	var cfg Config
	content, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

func Load(path string) (Config, error) {
	var cfg Config
	// Read the config file
	content, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}

	// Parse the JSON content into the Config struct
	if err := json.Unmarshal(content, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Validate required fields and set defaults
	if cfg.ControlPlaneURL == "" {
		return cfg, fmt.Errorf("control_plane_url is required")
	}
	if cfg.EnrollmentPath == "" {
		return cfg, fmt.Errorf("enrollment_path is required")
	}
	if cfg.HeartbeatPath == "" {
		cfg.HeartbeatPath = "/api/v1/agents/heartbeat"
	}
	if cfg.CommandsPath == "" {
		cfg.CommandsPath = "/api/v1/agents/commands"
	}
	if cfg.PolicyID == "" {
		return cfg, fmt.Errorf("policy_id is required")
	}
	if cfg.EnrollIntervalSeconds <= 0 {
		return cfg, fmt.Errorf("enroll_interval_seconds must be > 0")
	}
	if cfg.RequestTimeoutSeconds <= 0 {
		return cfg, fmt.Errorf("request_timeout_seconds must be > 0")
	}
	if cfg.StatePath == "" {
		return cfg, fmt.Errorf("state_path is required")
	}
	if cfg.Tags == nil {
		cfg.Tags = []string{}
	}

	// Ensure the "state_path" directory exists and create state directory if missing
	dir := filepath.Dir(cfg.StatePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return cfg, fmt.Errorf("create state dir %s: %w", dir, err)
	}

	return cfg, nil
}

// Save writes the config back to the given path as indented JSON.
func Save(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}

func (c Config) EnrollInterval() time.Duration {
	return time.Duration(c.EnrollIntervalSeconds) * time.Second
}

func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutSeconds) * time.Second
}

func (c Config) HeartbeatInterval() time.Duration {
	return 30 * time.Second
}

// CommandPollInterval returns how often the agent polls the lightweight
// /commands endpoint for urgent tasks such as upgrades.
// Default: 5 seconds.
func (c Config) CommandPollInterval() time.Duration {
	if c.CommandPollIntervalSeconds > 0 {
		return time.Duration(c.CommandPollIntervalSeconds) * time.Second
	}
	return 5 * time.Second
}

// TelemetryBaseURL returns the base URL for shipping telemetry data.
// Falls back to ControlPlaneURL when TelemetryURL is not set.
func (c Config) TelemetryBaseURL() string {
	if c.TelemetryURL != "" {
		return c.TelemetryURL
	}
	return c.ControlPlaneURL
}

// TelemetryEndpointPath returns the HTTP path for the telemetry endpoint.
func (c Config) TelemetryEndpointPath() string {
	if c.TelemetryPath != "" {
		return c.TelemetryPath
	}
	return "/api/v1/agents/telemetry"
}

// TelemetryInterval returns the collection interval for telemetry metrics.
func (c Config) TelemetryInterval() time.Duration {
	if c.TelemetryIntervalSeconds > 0 {
		return time.Duration(c.TelemetryIntervalSeconds) * time.Second
	}
	return 60 * time.Second
}

// TelemetryShipInterval returns the maximum linger time before the shipper
// flushes buffered events. Events are also shipped immediately when the
// buffer receives new data, so this is effectively a ceiling.
func (c Config) TelemetryShipInterval() time.Duration {
	if c.TelemetryShipIntervalSeconds > 0 {
		return time.Duration(c.TelemetryShipIntervalSeconds) * time.Second
	}
	return 1 * time.Second
}
