package events

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

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

func (s Severity) Pointer() *Severity { return &s }

// Event is the base event schema for all XDR agent events.
// Designed to be compatible with the Elastic Common Schema (ECS).
type Event struct {
	// Core fields
	ID        string    `json:"id"`
	Timestamp time.Time `json:"@timestamp"`
	Type      string    `json:"event.type"`     // e.g. "process_start", "file_write", "alert"
	Category  string    `json:"event.category"` // e.g. "process", "file", "network", "malware"
	Kind      string    `json:"event.kind"`     // "event", "alert", "metric", "state"
	Severity  *Severity `json:"event.severity,omitempty"`
	Module    string    `json:"event.module"` // capability that generated the event

	// Agent identity
	AgentID  string `json:"agent.id"`
	Hostname string `json:"host.hostname"`

	// Payload holds detail fields serialized alongside the event envelope.
	Payload map[string]interface{} `json:"-"`

	// MITRE ATT&CK mapping (for detection/alert events)
	MitreTactic   string `json:"threat.tactic.name,omitempty"`
	MitreTechique string `json:"threat.technique.id,omitempty"`
	MitreSubtech  string `json:"threat.technique.subtechnique.id,omitempty"`

	// Tags for filtering and routing
	Tags []string `json:"tags,omitempty"`
}

type eventEnvelope Event

var envelopeFields = [...]string{
	"id", "@timestamp", "event.type", "event.category", "event.kind", "event.severity", "event.module",
	"agent.id", "host.hostname", "threat.tactic.name", "threat.technique.id", "threat.technique.subtechnique.id", "tags",
}

// MarshalJSON emits detail fields at the root without allowing envelope overrides.
func (e Event) MarshalJSON() ([]byte, error) {
	header, err := json.Marshal(eventEnvelope(e))
	if err != nil || len(e.Payload) == 0 {
		return header, err
	}
	for _, key := range envelopeFields {
		if _, exists := e.Payload[key]; exists {
			return nil, fmt.Errorf("event detail field %q conflicts with the envelope", key)
		}
	}
	fields, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, err
	}
	return append(append(header[:len(header)-1], ','), fields[1:]...), nil
}

// UnmarshalJSON separates the envelope from root-level detail fields.
func (e *Event) UnmarshalJSON(data []byte) error {
	var header eventEnvelope
	if err := json.Unmarshal(data, &header); err != nil {
		return err
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, key := range envelopeFields {
		delete(fields, key)
	}
	*e = Event(header)
	e.Payload = fields
	return nil
}

// NewID is assigned before queueing so retries preserve document identity.
func NewID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("event identity entropy unavailable: " + err.Error())
	}
	return hex.EncodeToString(id[:])
}
