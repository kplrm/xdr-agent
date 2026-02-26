package events

import "time"

// Severity represents the severity level of an event or alert.
type Severity int

const (
	SeverityInfo     Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "info"
	}
}

// Event is the base event schema for all XDR agent events.
// Designed to be compatible with the Elastic Common Schema (ECS).
type Event struct {
	// Core fields
	ID        string    `json:"id"`
	Timestamp time.Time `json:"@timestamp"`
	Type      string    `json:"event.type"`     // e.g. "process_start", "file_write", "alert"
	Category  string    `json:"event.category"` // e.g. "process", "file", "network", "malware"
	Kind      string    `json:"event.kind"`     // "event", "alert", "metric", "state"
	Severity  Severity  `json:"event.severity"`
	Module    string    `json:"event.module"` // capability that generated the event

	// Agent identity
	AgentID  string `json:"agent.id"`
	Hostname string `json:"host.hostname"`

	// Payload holds capability-specific data (process info, file info, alert details, etc.)
	Payload map[string]interface{} `json:"payload,omitempty"`

	// MITRE ATT&CK mapping (for detection/alert events)
	MitreTactic   string `json:"threat.tactic.name,omitempty"`
	MitreTechique string `json:"threat.technique.id,omitempty"`
	MitreSubtech  string `json:"threat.technique.subtechnique.id,omitempty"`

	// Tags for filtering and routing
	Tags []string `json:"tags,omitempty"`
}
