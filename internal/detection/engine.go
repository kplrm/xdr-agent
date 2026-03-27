// Package detection provides the detection engine layer for the XDR agent.
// Detection engines consume telemetry events and produce security alerts when
// threats or suspicious activity are identified.
//
// Sub-packages:
//   - malware/     — Static malware detection (hashes, YARA, file analysis)
//   - behavioral/  — Behavioral rule-based detection (process chains, scripts, LOLBins)
//   - memory/      — Memory and exploit detection (injection, hollowing, fileless)
//   - threatintel/ — Threat intelligence IoC matching
package detection

import (
	"context"
	"log"
	"sync"
	"time"

	"xdr-agent/internal/config"
	"xdr-agent/internal/detection/behavioral"
	"xdr-agent/internal/detection/malware"
	"xdr-agent/internal/detection/memory"
	"xdr-agent/internal/detection/threatintel"
	"xdr-agent/internal/events"
)

type Engine struct {
	cfg      config.Config
	pipeline *events.Pipeline
	mu       sync.RWMutex
	posture  config.DetectionPreventionConfig

	behavioral  *behavioral.Engine
	malware     *malware.Scanner
	threatintel *threatintel.Matcher
	memory      *memory.Scanner
}

func NewEngine(cfg config.Config, pipeline *events.Pipeline) (*Engine, error) {
	b, err := behavioral.NewEngine(cfg.Rules.BehavioralDir)
	if err != nil {
		return nil, err
	}
	mw, err := malware.NewScanner(cfg.Rules.HashesFile, cfg.Rules.YaraDir)
	if err != nil {
		return nil, err
	}
	ti, err := threatintel.NewMatcher(cfg.Rules.ThreatIntelDir)
	if err != nil {
		return nil, err
	}

	return &Engine{
		cfg:         cfg,
		pipeline:    pipeline,
		posture:     cfg.DetectionPrevention,
		behavioral:  b,
		malware:     mw,
		threatintel: ti,
		memory:      memory.NewScanner(),
	}, nil
}

func (e *Engine) Start(ctx context.Context) {
	posture := e.currentPosture()
	if posture.Capabilities.LocalUpdates.EnableHotReload {
		go e.behavioral.StartAutoReload(ctx)
	}
	e.pipeline.Subscribe(e.handle)
	log.Printf("detection engine started (mode=%s)", posture.Mode)
}

func (e *Engine) UpdateDefensePosture(posture config.DetectionPreventionConfig) {
	e.mu.Lock()
	e.posture = posture
	e.mu.Unlock()
	log.Printf("Defense Posture applied to detection engine (mode=%s)", posture.Mode)
}

func (e *Engine) ReloadMalwareRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.malware != nil {
		if err := e.malware.Reload(e.cfg.Rules.HashesFile, e.cfg.Rules.YaraDir); err != nil {
			log.Printf("warning: failed to reload malware rules: %v", err)
		}
	}
}

func (e *Engine) ReloadBehavioralRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.behavioral != nil {
		if err := e.behavioral.Reload(); err != nil {
			log.Printf("warning: failed to reload behavioral rules: %v", err)
		}
	}
}

func (e *Engine) currentPosture() config.DetectionPreventionConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.posture
}

func (e *Engine) handle(event events.Event) {
	posture := e.currentPosture()

	if event.Kind != "event" && event.Kind != "metric" {
		return
	}
	if event.Module == "detection.engine" || event.Module == "prevention.manager" || event.Module == "agent.logger" {
		return
	}

	if posture.Capabilities.Behavioral.Rules {
		e.evalBehavioral(event)
	}
	if posture.Capabilities.ThreatIntel.LocalIOCMatch {
		e.evalThreatIntel(event)
	}
	if posture.Capabilities.Memory.Injection || posture.Capabilities.Memory.Hollowing || posture.Capabilities.Memory.Fileless {
		e.evalMemory(event, posture)
	}
	e.evalMalware(event, posture)
}

func (e *Engine) evalBehavioral(event events.Event) {
	for _, rule := range e.behavioral.Match(event) {
		e.emitAlert(event, "detection.behavioral", rule.ID, rule.Name, rule.Description, rule.SeverityValue(), string(rule.Action), map[string]interface{}{
			"rule.tags":          rule.Tags,
			"mitre.tactic":       rule.MitreTactic,
			"mitre.technique":    rule.MitreTechnique,
			"trigger_event_type": event.Type,
		})
	}
}

func (e *Engine) evalThreatIntel(event events.Event) {
	itype, ivalue, source, ok := e.threatintel.Match(event)
	if !ok {
		return
	}
	e.emitAlert(event, "detection.threatintel", "threatintel.local.match", "Threat intel indicator match", "event matched a local indicator", events.SeverityHigh, "alert", map[string]interface{}{
		"indicator.type":   itype,
		"indicator.value":  ivalue,
		"indicator.source": source,
	})
}

func (e *Engine) evalMemory(event events.Event, posture config.DetectionPreventionConfig) {
	for _, finding := range e.memory.Evaluate(
		event,
		posture.Capabilities.Memory.Injection,
		posture.Capabilities.Memory.Hollowing,
		posture.Capabilities.Memory.Fileless,
	) {
		e.emitAlert(event, "detection.memory", finding.RuleID, finding.Name, finding.Description, finding.Severity, "alert", nil)
	}
}

func (e *Engine) evalMalware(event events.Event, posture config.DetectionPreventionConfig) {
	// Only fire on event categories that carry executable or file paths.
	if event.Category != "process" && event.Category != "file" {
		return
	}

	cap := posture.Capabilities.Malware
	if !cap.HashDetection && !cap.YaraDetection && !cap.StaticDetection {
		return
	}

	path := pathFromEvent(event)
	knownSHA := sha256FromEvent(event)

	// Need at least a path or a pre-computed hash to do anything.
	if path == "" && knownSHA == "" {
		return
	}

	action := "alert"
	if posture.Mode == config.ModePrevent && cap.ExecutionBlocking {
		action = "block"
	}

	// ── Hash fast path: use pre-computed SHA256 from the event ─────────────────
	// Avoids reading the file from disk; works even if the file was deleted.
	if cap.HashDetection {
		sha := knownSHA
		if sha == "" && path != "" {
			// Fall back to computing the hash if the event didn't carry one.
			if computed, err := malware.SHA256File(path); err == nil {
				sha = computed
			}
		}
		if sha != "" {
			if result, ok := e.malware.LookupHash(sha); ok {
				e.emitAlert(event, "detection.malware", "malware.hash.match", result.Name, result.Description, result.Severity, action, map[string]interface{}{
					"file.path":        path,
					"file.hash.sha256": result.HashSHA256,
					"method":           result.Method,
				})
				return
			}
		}
	}

	// ── YARA / static scan: requires the file to be on disk ───────────────────
	if (cap.YaraDetection || cap.StaticDetection) && path != "" {
		result, err := e.malware.ScanFile(path, false, cap.YaraDetection, cap.StaticDetection)
		if err != nil || !result.Matched {
			return
		}
		sha := result.HashSHA256
		if sha == "" {
			sha = knownSHA
		}
		e.emitAlert(event, "detection.malware", "malware.local.scan", result.Name, result.Description, result.Severity, action, map[string]interface{}{
			"file.path":        path,
			"file.hash.sha256": sha,
			"method":           result.Method,
		})
	}
}

func (e *Engine) emitAlert(src events.Event, module, ruleID, ruleName, description string, severity events.Severity, action string, extra map[string]interface{}) {
	payload := map[string]interface{}{
		"rule.id":          ruleID,
		"rule.name":        ruleName,
		"rule.description": description,
		"event.action":     action,
		"source.module":    src.Module,
		"source.type":      src.Type,
	}
	for k, v := range extra {
		payload[k] = v
	}

	e.pipeline.Emit(events.Event{
		Timestamp: time.Now().UTC(),
		Type:      "alert",
		Category:  "threat",
		Kind:      "alert",
		Severity:  severity,
		Module:    module,
		AgentID:   src.AgentID,
		Hostname:  src.Hostname,
		Payload:   payload,
		Tags:      []string{"detection", action},
	})
}

// pathFromEvent extracts the relevant file path from an event payload.
// Handles both flat legacy keys and the ECS-nested structures used by
// the process and file telemetry collectors.
func pathFromEvent(event events.Event) string {
	if event.Payload == nil {
		return ""
	}
	// ECS process events: payload["process"]["executable"]
	if proc, ok := event.Payload["process"]; ok {
		if procMap, ok := proc.(map[string]interface{}); ok {
			if v, ok := procMap["executable"]; ok {
				if s, _ := v.(string); s != "" {
					return s
				}
			}
		}
	}
	// ECS file events: payload["file"]["path"]
	if file, ok := event.Payload["file"]; ok {
		if fileMap, ok := file.(map[string]interface{}); ok {
			if v, ok := fileMap["path"]; ok {
				if s, _ := v.(string); s != "" {
					return s
				}
			}
		}
	}
	// Legacy flat keys (kept for backward compatibility).
	for _, key := range []string{"file_path", "file.path", "process.executable"} {
		if v, ok := event.Payload[key]; ok {
			if s, _ := v.(string); s != "" {
				return s
			}
		}
	}
	return ""
}

// sha256FromEvent extracts a pre-computed SHA-256 digest from the event payload.
// Returns empty string if no hash is present.
func sha256FromEvent(event events.Event) string {
	if event.Payload == nil {
		return ""
	}
	// ECS process events: payload["process"]["hash"]["sha256"]
	if proc, ok := event.Payload["process"]; ok {
		if procMap, ok := proc.(map[string]interface{}); ok {
			if h, ok := procMap["hash"]; ok {
				if hMap, ok := h.(map[string]interface{}); ok {
					if v, ok := hMap["sha256"]; ok {
						if s, _ := v.(string); s != "" {
							return s
						}
					}
				}
			}
		}
	}
	// ECS file events: payload["file"]["hash"]["sha256"]
	if file, ok := event.Payload["file"]; ok {
		if fileMap, ok := file.(map[string]interface{}); ok {
			if h, ok := fileMap["hash"]; ok {
				if hMap, ok := h.(map[string]interface{}); ok {
					if v, ok := hMap["sha256"]; ok {
						if s, _ := v.(string); s != "" {
							return s
						}
					}
				}
			}
		}
	}
	return ""
}
