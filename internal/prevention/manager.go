// Package prevention provides active threat blocking capabilities.
// Unlike detection (which only alerts), prevention actively blocks malicious
// activity in real-time — stopping malware execution, ransomware encryption,
// and exploit techniques before damage occurs.
//
// Sub-packages:
//   - malware/     — Block malware execution and quarantine malicious files
//   - ransomware/  — Ransomware-specific prevention (canaries, rollback)
//   - exploit/     — Memory and exploit protection enforcement
//   - allowlist/   — Allow/block list management for exception handling
package prevention

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/config"
	"xdr-agent/internal/events"
)

type Manager struct {
	cfg      config.Config
	pipeline *events.Pipeline
	mu       sync.RWMutex
	posture  config.DetectionPreventionConfig
}

func NewManager(cfg config.Config, pipeline *events.Pipeline) *Manager {
	return &Manager{cfg: cfg, pipeline: pipeline, posture: cfg.DetectionPrevention}
}

func (m *Manager) UpdateDefensePosture(posture config.DetectionPreventionConfig) {
	m.mu.Lock()
	m.posture = posture
	m.mu.Unlock()
}

func (m *Manager) currentPosture() config.DetectionPreventionConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.posture
}

func (m *Manager) Handle(event events.Event) {
	posture := m.currentPosture()

	if event.Kind != "alert" {
		return
	}
	if !strings.HasPrefix(event.Module, "detection.") {
		return
	}

	action := "alert_only"
	if posture.Mode == config.ModePrevent && posture.Capabilities.Prevention.Enabled {
		action = m.recommendedAction(event, posture)
	}

	m.pipeline.Emit(events.Event{
		Timestamp: time.Now().UTC(),
		Type:      "prevention.action",
		Category:  "prevention",
		Kind:      "event",
		Severity:  event.Severity,
		Module:    "prevention.manager",
		AgentID:   event.AgentID,
		Hostname:  event.Hostname,
		Payload: map[string]interface{}{
			"action":           action,
			"source_alert":     event.Type,
			"source_module":    event.Module,
			"source_rule_id":   payloadString(event.Payload, "rule.id"),
			"source_rule_name": payloadString(event.Payload, "rule.name"),
			"justification":    fmt.Sprintf("mode=%s severity=%s", posture.Mode, event.Severity.String()),
		},
		Tags: []string{"prevention", action, "audit"},
	})
}

func (m *Manager) recommendedAction(event events.Event, posture config.DetectionPreventionConfig) string {
	if strings.Contains(event.Module, "malware") && posture.Capabilities.Malware.ExecutionBlocking {
		return "block"
	}
	if strings.Contains(event.Module, "ransomware") && posture.Capabilities.Ransomware.Shield {
		return "kill_process"
	}
	if event.Severity >= events.SeverityHigh {
		return "quarantine"
	}
	return "alert_only"
}

func payloadString(payload map[string]interface{}, key string) string {
	if payload == nil {
		return ""
	}
	v, _ := payload[key].(string)
	return v
}
