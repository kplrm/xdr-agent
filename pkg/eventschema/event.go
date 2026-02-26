// Package eventschema defines the public event schema for XDR agent events.
//
// This package can be imported by external tools, the control plane, and
// OpenSearch ingestion pipelines to parse agent events.
// The schema is designed to be compatible with the Elastic Common Schema (ECS).
package eventschema

import "time"

// Event is the base event structure for all XDR agent events.
type Event struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"@timestamp"`
	Type      string                 `json:"event.type"`
	Category  string                 `json:"event.category"`
	Kind      string                 `json:"event.kind"`
	Severity  int                    `json:"event.severity"`
	Module    string                 `json:"event.module"`
	AgentID   string                 `json:"agent.id"`
	Hostname  string                 `json:"host.hostname"`
	Payload   map[string]interface{} `json:"payload,omitempty"`
	Tags      []string               `json:"tags,omitempty"`
}
