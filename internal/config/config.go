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
	// MaxCPUCores limits logical CPUs for the agent and its child processes; 0 removes the limit.
	MaxCPUCores int `json:"max_cpu_cores"`
	// ExecutionWatchPaths bounds the directories covered by execution prevention.
	ExecutionWatchPaths      []string `json:"execution_watch_paths,omitempty"`
	ControlPlaneURL          string   `json:"control_plane_url"`
	EnrollmentPath           string   `json:"enrollment_path"`
	HeartbeatPath            string   `json:"heartbeat_path"`
	EnrollmentToken          string   `json:"enrollment_token"`
	PolicyID                 string   `json:"policy_id"`
	Tags                     []string `json:"tags"`
	EnrollIntervalSeconds    int      `json:"enroll_interval_seconds"`
	HeartbeatIntervalSeconds int      `json:"heartbeat_interval_seconds,omitempty"`
	RequestTimeoutSeconds    int      `json:"request_timeout_seconds"`
	StatePath                string   `json:"state_path"`
	InsecureSkipTLSVerify    bool     `json:"insecure_skip_tls_verify"`

	// Telemetry shipping — optional fields.
	// When TelemetryURL is empty the agent ships telemetry to ControlPlaneURL.
	// Setting a different URL allows routing through Kafka, Logstash, etc.
	TelemetryURL                 string `json:"telemetry_url,omitempty"`
	TelemetryPath                string `json:"telemetry_path,omitempty"`
	TelemetryIntervalSeconds     int    `json:"telemetry_interval_seconds,omitempty"`
	TelemetryShipIntervalSeconds int    `json:"telemetry_ship_interval_seconds,omitempty"`
	SecurityURL                  string `json:"security_url,omitempty"`
	SecurityPath                 string `json:"security_path,omitempty"`
	SecurityShipIntervalSeconds  int    `json:"security_ship_interval_seconds,omitempty"`

	// Command polling — lightweight endpoint polled frequently to deliver
	// upgrade and other commands without waiting for the full heartbeat cycle.
	CommandsPath               string `json:"commands_path,omitempty"`
	CommandPollIntervalSeconds int    `json:"command_poll_interval_seconds,omitempty"`

	DetectionPrevention DetectionPreventionConfig `json:"detection_prevention,omitempty"`
	Logging             LoggingConfig             `json:"logging,omitempty"`
}

type DetectionPreventionMode string

const (
	ModeDetect  DetectionPreventionMode = "detect"
	ModePrevent DetectionPreventionMode = "prevent"
)

type DetectionPreventionConfig struct {
	Mode DetectionPreventionMode `json:"mode,omitempty"`
}

type LoggingConfig struct {
	Level string            `json:"level,omitempty"`
	Ship  LoggingShipConfig `json:"ship,omitempty"`
}

type LoggingShipConfig struct {
	Enabled             bool   `json:"enabled,omitempty"`
	URL                 string `json:"url,omitempty"`
	Path                string `json:"path,omitempty"`
	Index               string `json:"index,omitempty"`
	ShipIntervalSeconds int    `json:"ship_interval_seconds,omitempty"`
}

// Detection is the safe default. Prevention requires an explicit mode change.
func defaults() Config {
	return Config{
		MaxCPUCores:              1,
		ExecutionWatchPaths:      []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt", "/tmp", "/var/tmp", "/home"},
		EnrollmentPath:           "/api/v1/agents/enroll",
		HeartbeatPath:            "/api/v1/agents/heartbeat",
		CommandsPath:             "/api/v1/agents/commands",
		PolicyID:                 "default-endpoint",
		StatePath:                "/var/lib/xdr-agent/state.json",
		EnrollIntervalSeconds:    30,
		HeartbeatIntervalSeconds: 30,
		RequestTimeoutSeconds:    10,
		DetectionPrevention:      DetectionPreventionConfig{Mode: ModeDetect},
		Logging:                  LoggingConfig{Level: "INFO", Ship: LoggingShipConfig{Enabled: true}},
	}
}

// LoadRaw reads a config file and unmarshals it without validation.
// Useful for applying CLI overrides before saving back.
func LoadRaw(path string) (Config, error) {
	cfg := defaults()
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
	cfg := defaults()
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
	if cfg.MaxCPUCores < 0 {
		return cfg, fmt.Errorf("max_cpu_cores must be >= 0")
	}
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

	if cfg.DetectionPrevention.Mode == "" {
		cfg.DetectionPrevention.Mode = ModeDetect
	}
	if cfg.DetectionPrevention.Mode != ModeDetect && cfg.DetectionPrevention.Mode != ModePrevent {
		return cfg, fmt.Errorf("detection_prevention.mode must be detect or prevent")
	}

	setLoggingDefaults(&cfg)

	// Ensure the "state_path" directory exists and create state directory if missing
	dir := filepath.Dir(cfg.StatePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return cfg, fmt.Errorf("create state dir %s: %w", dir, err)
	}

	return cfg, nil
}

func setLoggingDefaults(cfg *Config) {
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "INFO"
	}
	if cfg.Logging.Ship.Path == "" {
		cfg.Logging.Ship.Path = "/api/v1/agents/logs"
	}
	if cfg.Logging.Ship.Index == "" {
		cfg.Logging.Ship.Index = "xdr-agent-logs"
	}
}

// Save writes the config back to the given path as indented JSON.
func Save(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')
	// Enrollment tokens must never inherit the sample config's read permissions.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xdr-agent-config-*")
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write config %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace config %s: %w", path, err)
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
	if c.HeartbeatIntervalSeconds > 0 {
		return time.Duration(c.HeartbeatIntervalSeconds) * time.Second
	}
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

// TelemetryInterval bounds /proc polling even when an older config requests faster scans.
func (c Config) TelemetryInterval() time.Duration {
	if c.TelemetryIntervalSeconds >= 5 {
		return time.Duration(c.TelemetryIntervalSeconds) * time.Second
	}
	return 5 * time.Second
}

// TelemetryShipInterval controls periodic batch delivery.
func (c Config) TelemetryShipInterval() time.Duration {
	if c.TelemetryShipIntervalSeconds > 0 {
		return time.Duration(c.TelemetryShipIntervalSeconds) * time.Second
	}
	return 30 * time.Second
}

// SecurityBaseURL returns the base URL for shipping security-classified events.
// Falls back to TelemetryURL when set, otherwise ControlPlaneURL.
func (c Config) SecurityBaseURL() string {
	if c.SecurityURL != "" {
		return c.SecurityURL
	}
	if c.TelemetryURL != "" {
		return c.TelemetryURL
	}
	return c.ControlPlaneURL
}

// SecurityEndpointPath returns the HTTP path for security-classified events.
func (c Config) SecurityEndpointPath() string {
	if c.SecurityPath != "" {
		return c.SecurityPath
	}
	return "/api/v1/agents/security"
}

// SecurityShipInterval returns the max linger before the security shipper flushes.
func (c Config) SecurityShipInterval() time.Duration {
	if c.SecurityShipIntervalSeconds > 0 {
		return time.Duration(c.SecurityShipIntervalSeconds) * time.Second
	}
	return c.TelemetryShipInterval()
}

func (c Config) IsPreventionMode() bool {
	return c.DetectionPrevention.Mode == ModePrevent
}

func (c Config) LogsBaseURL() string {
	if c.Logging.Ship.URL != "" {
		return c.Logging.Ship.URL
	}
	return c.ControlPlaneURL
}

func (c Config) LogsEndpointPath() string {
	if c.Logging.Ship.Path != "" {
		return c.Logging.Ship.Path
	}
	return "/api/v1/agents/logs"
}

func (c Config) LogsShipInterval() time.Duration {
	if c.Logging.Ship.ShipIntervalSeconds > 0 {
		return time.Duration(c.Logging.Ship.ShipIntervalSeconds) * time.Second
	}
	return 30 * time.Second
}
