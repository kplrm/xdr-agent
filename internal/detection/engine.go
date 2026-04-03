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
	"strconv"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/config"
	"xdr-agent/internal/detection/behavioral"
	"xdr-agent/internal/detection/customrules"
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
	memoryRules *customrules.Engine
	ransomRules *customrules.Engine
	malware     *malware.Scanner
	threatintel *threatintel.Matcher
	memory      *memory.Scanner
}

func NewEngine(cfg config.Config, pipeline *events.Pipeline) (*Engine, error) {
	b, err := behavioral.NewEngine(cfg.Rules.BehavioralDir)
	if err != nil {
		return nil, err
	}
	memoryRules, err := customrules.NewEngine(cfg.Rules.MemoryDir)
	if err != nil {
		return nil, err
	}
	ransomRules, err := customrules.NewEngine(cfg.Rules.RansomwareDir)
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
		memoryRules: memoryRules,
		ransomRules: ransomRules,
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

func (e *Engine) ReloadMemoryRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.memoryRules != nil {
		if err := e.memoryRules.Reload(); err != nil {
			log.Printf("warning: failed to reload memory rules: %v", err)
		}
	}
}

func (e *Engine) ReloadRansomwareRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ransomRules != nil {
		if err := e.ransomRules.Reload(); err != nil {
			log.Printf("warning: failed to reload ransomware rules: %v", err)
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
		e.evalMemoryCustomRules(event)
	}
	if posture.Capabilities.Ransomware.BehaviorDetection {
		e.evalRansomwareRules(event)
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

func (e *Engine) evalMemoryCustomRules(event events.Event) {
	for _, rule := range e.memoryRules.Match(event) {
		e.emitAlert(event, "detection.memory.rules", rule.ID, rule.Name, rule.Description, rule.SeverityValue(), string(rule.Action), map[string]interface{}{
			"rule.tags":          rule.Tags,
			"trigger_event_type": event.Type,
		})
	}
}

func (e *Engine) evalRansomwareRules(event events.Event) {
	for _, rule := range e.ransomRules.Match(event) {
		e.emitAlert(event, "detection.ransomware", rule.ID, rule.Name, rule.Description, rule.SeverityValue(), string(rule.Action), map[string]interface{}{
			"rule.tags":          rule.Tags,
			"trigger_event_type": event.Type,
		})
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
				extra := map[string]interface{}{
					"file.path":        path,
					"file.hash.sha256": result.HashSHA256,
					"method":           result.Method,
				}
				for k, v := range hashEntryPayload(result.HashEntry) {
					extra[k] = v
				}
				e.emitAlert(event, "detection.malware", "malware.hash.match", result.Name, result.Description, result.Severity, action, extra)
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
		"source.event.id":  src.ID,
	}
	for k, v := range extra {
		payload[k] = v
	}
	enrichPayloadWithSourceProcess(payload, src)

	e.pipeline.Emit(events.Event{
		ID:        buildAlertID(module, ruleID, src.ID),
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

func buildAlertID(module, ruleID, sourceEventID string) string {
	// Keep IDs stable enough for dedup and always non-empty for index _id.
	ts := time.Now().UnixNano()
	if sourceEventID != "" {
		return "alert-" + module + "-" + ruleID + "-" + sourceEventID + "-" + strconv.FormatInt(ts, 10)
	}
	return "alert-" + module + "-" + ruleID + "-" + strconv.FormatInt(ts, 10)
}

func hashEntryPayload(entry malware.HashEntry) map[string]interface{} {
	payload := map[string]interface{}{}
	if s := strings.TrimSpace(entry.Severity); s != "" {
		payload["threat.indicator.severity"] = s
	}
	if s := strings.TrimSpace(entry.Source); s != "" {
		payload["threat.indicator.provider"] = s
	}
	if s := strings.TrimSpace(entry.Family); s != "" {
		payload["threat.software.family"] = s
	}
	if s := strings.TrimSpace(entry.MimeType); s != "" {
		payload["threat.indicator.file.mime_type"] = s
	}
	if s := strings.TrimSpace(entry.FirstSeenUTC); s != "" {
		payload["threat.indicator.first_seen"] = s
	}
	return payload
}

func enrichPayloadWithSourceProcess(payload map[string]interface{}, src events.Event) {
	if src.Payload == nil {
		return
	}
	processRaw, ok := src.Payload["process"]
	if !ok {
		return
	}
	processMap, ok := processRaw.(map[string]interface{})
	if !ok {
		return
	}

	copyString(payload, "process.entity_id", processMap, "entity_id")
	copyString(payload, "process.name", processMap, "name")
	copyString(payload, "process.executable", processMap, "executable")
	copyString(payload, "process.command_line", processMap, "command_line")
	copyNumber(payload, "process.pid", processMap, "pid")
	copyNumber(payload, "process.ppid", processMap, "ppid")

	parentRaw, ok := processMap["parent"]
	if !ok {
		return
	}
	parentMap, ok := parentRaw.(map[string]interface{})
	if !ok {
		return
	}
	copyString(payload, "process.parent.entity_id", parentMap, "entity_id")
	copyString(payload, "process.parent.name", parentMap, "name")
	copyString(payload, "process.parent.executable", parentMap, "executable")
	copyString(payload, "process.parent.command_line", parentMap, "command_line")
	copyNumber(payload, "process.parent.pid", parentMap, "pid")
	copyNumber(payload, "process.parent.ppid", parentMap, "ppid")
}

func copyString(dst map[string]interface{}, dstKey string, src map[string]interface{}, srcKey string) {
	v, ok := src[srcKey]
	if !ok {
		return
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return
	}
	dst[dstKey] = s
}

func copyNumber(dst map[string]interface{}, dstKey string, src map[string]interface{}, srcKey string) {
	v, ok := src[srcKey]
	if !ok {
		return
	}
	switch n := v.(type) {
	case int:
		dst[dstKey] = n
	case int32:
		dst[dstKey] = n
	case int64:
		dst[dstKey] = n
	case float64:
		dst[dstKey] = n
	}
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
