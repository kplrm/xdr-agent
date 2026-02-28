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
	EventsPath            string   `json:"events_path"`
	PolicyID              string   `json:"policy_id"`
	Tags                  []string `json:"tags"`
	EnrollIntervalSeconds int      `json:"enroll_interval_seconds"`
	HeartbeatIntervalSeconds int   `json:"heartbeat_interval_seconds"`
	RequestTimeoutSeconds int      `json:"request_timeout_seconds"`
	EventBufferSize       int      `json:"event_buffer_size"`
	ShipIntervalSeconds   int      `json:"ship_interval_seconds"`
	StatePath             string   `json:"state_path"`
	InsecureSkipTLSVerify bool     `json:"insecure_skip_tls_verify"`
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
	if cfg.EventsPath == "" {
		cfg.EventsPath = "/api/v1/agents/events"
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
	if cfg.HeartbeatIntervalSeconds <= 0 {
		cfg.HeartbeatIntervalSeconds = 30
	}
	if cfg.EventBufferSize <= 0 {
		cfg.EventBufferSize = 4096
	}
	if cfg.ShipIntervalSeconds <= 0 {
		cfg.ShipIntervalSeconds = 10
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

func (c Config) EnrollInterval() time.Duration {
	return time.Duration(c.EnrollIntervalSeconds) * time.Second
}

func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutSeconds) * time.Second
}

func (c Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatIntervalSeconds) * time.Second
}

func (c Config) ShipInterval() time.Duration {
	return time.Duration(c.ShipIntervalSeconds) * time.Second
}
