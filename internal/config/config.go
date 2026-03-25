package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const DefaultConfigPath = "/etc/xdr-agent/config.json"

const (
	DefaultDefensePosturePath            = "/var/lib/xdr-agent/defense_posture.json"
	DefaultDefensePostureAckPath         = "/api/xdr-defense/policy-rollouts/ack"
	DefaultYaraRolloutAckPath            = "/api/xdr-defense/yara/rollouts/ack"
	DefaultYaraRuleStatusPath            = "/api/xdr-defense/yara/rollouts/status"
	DefaultDefensePosturePollIntervalSec = 30
)

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
	SecurityURL                  string `json:"security_url,omitempty"`
	SecurityPath                 string `json:"security_path,omitempty"`
	SecurityShipIntervalSeconds  int    `json:"security_ship_interval_seconds,omitempty"`

	// Command polling — lightweight endpoint polled frequently to deliver
	// upgrade and other commands without waiting for the full heartbeat cycle.
	CommandsPath               string `json:"commands_path,omitempty"`
	CommandPollIntervalSeconds int    `json:"command_poll_interval_seconds,omitempty"`

	DefensePosturePath                string `json:"defense_posture_path,omitempty"`
	DefensePosturePollIntervalSeconds int    `json:"defense_posture_poll_interval_seconds,omitempty"`
	DefensePostureAckPath             string `json:"defense_posture_ack_path,omitempty"`
	YaraRolloutAckPath                string `json:"yara_rollout_ack_path,omitempty"`
	YaraRuleStatusPath                string `json:"yara_rule_status_path,omitempty"`
	YaraRuleInventoryPath             string `json:"yara_rule_inventory_path,omitempty"`
	YaraBundleSyncIntervalSeconds     int    `json:"yara_bundle_sync_interval_seconds,omitempty"`
	YaraInventoryCheckIntervalSeconds int    `json:"yara_inventory_check_interval_seconds,omitempty"`

	DetectionPrevention DetectionPreventionConfig `json:"detection_prevention,omitempty"`
	Logging             LoggingConfig             `json:"logging,omitempty"`
	Rules               RulesConfig               `json:"rules,omitempty"`
}

type DetectionPreventionMode string

const (
	ModeDetect  DetectionPreventionMode = "detect"
	ModePrevent DetectionPreventionMode = "prevent"
)

type DetectionPreventionConfig struct {
	Mode         DetectionPreventionMode `json:"mode,omitempty"`
	Capabilities CapabilityOptions       `json:"capabilities,omitempty"`
}

type CapabilityOptions struct {
	Malware      MalwareCapabilityOptions     `json:"malware,omitempty"`
	Ransomware   RansomwareCapabilityOptions  `json:"ransomware,omitempty"`
	Behavioral   BehavioralCapabilityOptions  `json:"behavioral,omitempty"`
	ThreatIntel  ThreatIntelCapabilityOptions `json:"threatintel,omitempty"`
	Memory       MemoryCapabilityOptions      `json:"memory,omitempty"`
	Rollback     RollbackCapabilityOptions    `json:"rollback,omitempty"`
	Prevention   PreventionCapabilityOptions  `json:"prevention,omitempty"`
	Correlation  CorrelationCapabilityOptions `json:"correlation,omitempty"`
	LocalUpdates LocalUpdateCapabilityOptions `json:"local_updates,omitempty"`
}

type MalwareCapabilityOptions struct {
	HashDetection     bool `json:"hash_detection,omitempty"`
	YaraDetection     bool `json:"yara_detection,omitempty"`
	StaticDetection   bool `json:"static_detection,omitempty"`
	ExecutionBlocking bool `json:"execution_blocking,omitempty"`
}

type RansomwareCapabilityOptions struct {
	BehaviorDetection bool `json:"behavior_detection,omitempty"`
	Shield            bool `json:"shield,omitempty"`
}

type BehavioralCapabilityOptions struct {
	Rules bool `json:"rules,omitempty"`
}

type ThreatIntelCapabilityOptions struct {
	LocalIOCMatch bool `json:"local_ioc_match,omitempty"`
}

type MemoryCapabilityOptions struct {
	Injection bool `json:"injection,omitempty"`
	Hollowing bool `json:"hollowing,omitempty"`
	Fileless  bool `json:"fileless,omitempty"`
}

type RollbackCapabilityOptions struct {
	Enabled bool `json:"enabled,omitempty"`
}

type PreventionCapabilityOptions struct {
	Enabled bool `json:"enabled,omitempty"`
}

type CorrelationCapabilityOptions struct {
	OpenSearchTimeWindow bool `json:"opensearch_time_window,omitempty"`
}

type LocalUpdateCapabilityOptions struct {
	EnableHotReload bool `json:"enable_hot_reload,omitempty"`
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

type RulesConfig struct {
	BehavioralDir  string `json:"behavioral_dir,omitempty"`
	YaraDir        string `json:"yara_dir,omitempty"`
	HashesFile     string `json:"hashes_file,omitempty"`
	ThreatIntelDir string `json:"threatintel_dir,omitempty"`
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

	if cfg.DetectionPrevention.Mode == "" {
		cfg.DetectionPrevention.Mode = ModeDetect
	}
	if cfg.DetectionPrevention.Mode != ModeDetect && cfg.DetectionPrevention.Mode != ModePrevent {
		return cfg, fmt.Errorf("detection_prevention.mode must be detect or prevent")
	}

	setLoggingDefaults(&cfg)
	setRulePathDefaults(&cfg)
	setDefensePostureDefaults(&cfg)

	// Ensure the "state_path" directory exists and create state directory if missing
	dir := filepath.Dir(cfg.StatePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return cfg, fmt.Errorf("create state dir %s: %w", dir, err)
	}

	postureDir := filepath.Dir(cfg.DefensePosturePath)
	if err := os.MkdirAll(postureDir, 0o750); err != nil {
		return cfg, fmt.Errorf("create Defense Posture state dir %s: %w", postureDir, err)
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

func setRulePathDefaults(cfg *Config) {
	if cfg.Rules.BehavioralDir == "" {
		cfg.Rules.BehavioralDir = "/etc/xdr-agent/rules/behavioral"
	}
	if cfg.Rules.YaraDir == "" {
		cfg.Rules.YaraDir = "/etc/xdr-agent/rules/malware/yara"
	}
	if cfg.Rules.HashesFile == "" {
		cfg.Rules.HashesFile = "/etc/xdr-agent/rules/malware/hashes"
	}
	if cfg.Rules.ThreatIntelDir == "" {
		cfg.Rules.ThreatIntelDir = "/etc/xdr-agent/rules/threatintel"
	}
}

func setDefensePostureDefaults(cfg *Config) {
	if cfg.DefensePosturePath == "" {
		cfg.DefensePosturePath = DefaultDefensePosturePath
	}
	if cfg.DefensePostureAckPath == "" {
		cfg.DefensePostureAckPath = DefaultDefensePostureAckPath
	}
	if cfg.YaraRolloutAckPath == "" {
		cfg.YaraRolloutAckPath = DefaultYaraRolloutAckPath
	}
	if cfg.DefensePosturePollIntervalSeconds <= 0 {
		cfg.DefensePosturePollIntervalSeconds = DefaultDefensePosturePollIntervalSec
	}
	if cfg.YaraRuleStatusPath == "" {
		cfg.YaraRuleStatusPath = DefaultYaraRuleStatusPath
	}
	if cfg.YaraRuleInventoryPath == "" {
		cfg.YaraRuleInventoryPath = "/api/xdr-defense/yara-rules/inventory"
	}
	if cfg.YaraBundleSyncIntervalSeconds <= 0 {
		cfg.YaraBundleSyncIntervalSeconds = 5
	}
	if cfg.YaraInventoryCheckIntervalSeconds <= 0 {
		cfg.YaraInventoryCheckIntervalSeconds = 300 // 5 minutes
	}
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

func (c Config) DefensePosturePollInterval() time.Duration {
	if c.DefensePosturePollIntervalSeconds > 0 {
		return time.Duration(c.DefensePosturePollIntervalSeconds) * time.Second
	}
	return DefaultDefensePosturePollIntervalSec * time.Second
}

// YaraBundleSyncInterval returns how often the agent polls for signed YARA bundles.
// This decouples YARA rollout reaction time from the slower defense posture poll loop.
func (c Config) YaraBundleSyncInterval() time.Duration {
	if c.YaraBundleSyncIntervalSeconds > 0 {
		return time.Duration(c.YaraBundleSyncIntervalSeconds) * time.Second
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

// YaraInventoryCheckInterval returns the interval for periodic YARA rule inventory reporting.
func (c Config) YaraInventoryCheckInterval() time.Duration {
	if c.YaraInventoryCheckIntervalSeconds > 0 {
		return time.Duration(c.YaraInventoryCheckIntervalSeconds) * time.Second
	}
	return 5 * time.Minute
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
	return 2 * time.Second
}
