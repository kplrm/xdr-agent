// Package ruleformat defines the format for detection rules used by the XDR agent.
package ruleformat

// Rule represents a behavioral detection rule.
type Rule struct {
	ID          string   `yaml:"id"          json:"id"`
	Name        string   `yaml:"name"        json:"name"`
	Description string   `yaml:"description" json:"description"`
	Severity    string   `yaml:"severity"    json:"severity"` // info, low, medium, high, critical
	Enabled     bool     `yaml:"enabled"     json:"enabled"`
	Tags        []string `yaml:"tags"        json:"tags"`

	// MITRE ATT&CK mapping
	MitreTactic    string `yaml:"mitre_tactic"    json:"mitre_tactic"`
	MitreTechnique string `yaml:"mitre_technique" json:"mitre_technique"`

	// Condition for matching (simplified for initial implementation)
	Condition RuleCondition `yaml:"condition" json:"condition"`

	// Action to take on match
	Action string `yaml:"action" json:"action"` // alert, block, kill, quarantine
}

// RuleCondition defines matching criteria for a rule.
type RuleCondition struct {
	// Process matching
	ProcessName   string `yaml:"process_name,omitempty"   json:"process_name,omitempty"`
	ParentProcess string `yaml:"parent_process,omitempty" json:"parent_process,omitempty"`
	CommandLine   string `yaml:"command_line,omitempty"    json:"command_line,omitempty"` // regex

	// File matching
	FilePath string `yaml:"file_path,omitempty" json:"file_path,omitempty"` // regex

	// Network matching
	DestinationIP   string `yaml:"destination_ip,omitempty"   json:"destination_ip,omitempty"`
	DestinationPort int    `yaml:"destination_port,omitempty" json:"destination_port,omitempty"`

	// Event type
	EventType string `yaml:"event_type,omitempty" json:"event_type,omitempty"`
}
