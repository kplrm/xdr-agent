package system

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

// SystemCollector combines memory and CPU collection into a single collector
// that emits one "system.metrics" event per interval containing both
// system.memory and system.cpu in the payload.  Per-process CPU events
// are still emitted as separate "process.cpu" documents.
//
// This replaces running MemoryCollector and CpuCollector independently,
// giving a correlated view of host resources in a single indexed document.
type SystemCollector struct {
	pipeline *events.Pipeline
	agentID  string
	hostname string
	interval time.Duration
	procRoot string // root for CPU procfs (/proc)
	memPath  string // path to meminfo file (/proc/meminfo)
	topN     int

	mu       sync.Mutex
	health   capability.HealthStatus
	cancel   context.CancelFunc
	prevSys  *CpuStats
	prevProc map[int]ProcessCpuSnapshot
}

// NewSystemCollector creates a combined memory + CPU telemetry collector.
func NewSystemCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *SystemCollector {
	if interval <= 0 {
		interval = defaultInterval
	}
	return &SystemCollector{
		pipeline: pipeline,
		agentID:  agentID,
		hostname: hostname,
		interval: interval,
		procRoot: "/proc",
		memPath:  defaultProcMeminfo,
		topN:     defaultTopN,
		health:   capability.HealthStopped,
	}
}

// SetProcRoot overrides the /proc path (useful for testing).
func (s *SystemCollector) SetProcRoot(path string) {
	s.procRoot = path
}

// SetMemPath overrides the /proc/meminfo path (useful for testing).
func (s *SystemCollector) SetMemPath(path string) {
	s.memPath = path
}

// ── capability.Capability interface ──────────────────────────────────────────

func (s *SystemCollector) Name() string { return "telemetry.system" }

func (s *SystemCollector) Init(_ capability.Dependencies) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health = capability.HealthStarting
	return nil
}

func (s *SystemCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.health = capability.HealthRunning
	s.mu.Unlock()

	go s.loop(childCtx)
	return nil
}

func (s *SystemCollector) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	s.health = capability.HealthStopped
	return nil
}

func (s *SystemCollector) Health() capability.HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.health
}

// ── internal ─────────────────────────────────────────────────────────────────

func (s *SystemCollector) loop(ctx context.Context) {
	// First tick: capture CPU baseline (no delta available yet), but still
	// emit a memory-only system.metrics event.
	s.collectBaseline()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.collectAndEmit()
		}
	}
}

// collectBaseline reads the initial CPU state without emitting CPU events.
// It does emit a system.metrics event with memory data only.
func (s *SystemCollector) collectBaseline() {
	sys, err := ReadSystemCpu(s.procRoot)
	if err != nil {
		log.Printf("system collector: baseline CPU read failed: %v", err)
		s.mu.Lock()
		s.health = capability.HealthDegraded
		s.mu.Unlock()
		return
	}

	proc, err := ReadProcessCpuTimes(s.procRoot)
	if err != nil {
		log.Printf("system collector: baseline process read failed: %v", err)
	}

	s.mu.Lock()
	s.prevSys = &sys
	s.prevProc = proc
	s.mu.Unlock()
	log.Printf("system collector: CPU baseline captured (%d cores, %d processes)", sys.Cores, len(proc))

	// Emit memory-only event on baseline
	memInfo, memErr := ReadMemoryInfo(s.memPath)
	if memErr != nil {
		log.Printf("system collector: baseline memory read failed: %v", memErr)
		return
	}

	event := events.Event{
		ID:        fmt.Sprintf("sys-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "system.metrics",
		Category:  "host",
		Kind:      "metric",
		Severity:  events.SeverityInfo,
		Module:    "telemetry.system",
		AgentID:   s.agentID,
		Hostname:  s.hostname,
		Payload: map[string]interface{}{
			"system": map[string]interface{}{
				"memory": map[string]interface{}{
					"total":  memInfo.TotalBytes,
					"free":   memInfo.FreeBytes,
					"cached": memInfo.CachedBytes,
					"buffer": memInfo.BuffersBytes,
					"used": map[string]interface{}{
						"bytes": memInfo.UsedBytes,
						"pct":   memInfo.UsedPercent,
					},
					"actual": map[string]interface{}{
						"free": memInfo.AvailableBytes,
					},
					"swap": map[string]interface{}{
						"total": memInfo.SwapTotalBytes,
						"free":  memInfo.SwapFreeBytes,
						"used": map[string]interface{}{
							"bytes": memInfo.SwapUsedBytes,
						},
					},
				},
			},
		},
		Tags: []string{"memory", "system", "metric"},
	}

	s.pipeline.Emit(event)
	log.Printf("system collector: emitted baseline memory metric")
}

// collectAndEmit reads memory + CPU state, computes CPU deltas, and emits
// a combined system.metrics event plus per-process CPU events.
func (s *SystemCollector) collectAndEmit() {
	// ── Memory ──────────────────────────────────────────────────────────
	memInfo, memErr := ReadMemoryInfo(s.memPath)
	if memErr != nil {
		log.Printf("system collector: memory read failed: %v", memErr)
		s.mu.Lock()
		s.health = capability.HealthDegraded
		s.mu.Unlock()
	}

	// ── CPU ─────────────────────────────────────────────────────────────
	sys, cpuErr := ReadSystemCpu(s.procRoot)
	if cpuErr != nil {
		log.Printf("system collector: CPU read failed: %v", cpuErr)
		s.mu.Lock()
		s.health = capability.HealthDegraded
		s.mu.Unlock()
	}

	proc, procErr := ReadProcessCpuTimes(s.procRoot)
	if procErr != nil {
		log.Printf("system collector: process CPU read failed: %v", procErr)
	}

	if memErr != nil && cpuErr != nil {
		return // nothing useful to emit
	}

	s.mu.Lock()
	prevSys := s.prevSys
	prevProc := s.prevProc
	if cpuErr == nil {
		s.prevSys = &sys
		s.prevProc = proc
	}
	s.health = capability.HealthRunning
	s.mu.Unlock()

	// ── Build combined payload ──────────────────────────────────────────
	systemPayload := make(map[string]interface{})

	if memErr == nil {
		systemPayload["memory"] = map[string]interface{}{
			"total":  memInfo.TotalBytes,
			"free":   memInfo.FreeBytes,
			"cached": memInfo.CachedBytes,
			"buffer": memInfo.BuffersBytes,
			"used": map[string]interface{}{
				"bytes": memInfo.UsedBytes,
				"pct":   memInfo.UsedPercent,
			},
			"actual": map[string]interface{}{
				"free": memInfo.AvailableBytes,
			},
			"swap": map[string]interface{}{
				"total": memInfo.SwapTotalBytes,
				"free":  memInfo.SwapFreeBytes,
				"used": map[string]interface{}{
					"bytes": memInfo.SwapUsedBytes,
				},
			},
		}
	}

	var totalPct, userPct, systemPct, idlePct, iowaitPct, stealPct float64
	var totalDelta uint64
	hasCpuDelta := false

	if cpuErr == nil && prevSys != nil {
		totalDelta = sys.Total - prevSys.Total
		if totalDelta > 0 {
			hasCpuDelta = true
			fd := float64(totalDelta)
			userPct = round2(float64(sys.User-prevSys.User) / fd * 100)
			systemPct = round2(float64(sys.System-prevSys.System) / fd * 100)
			idlePct = round2(float64(sys.Idle-prevSys.Idle) / fd * 100)
			iowaitPct = round2(float64(sys.IOWait-prevSys.IOWait) / fd * 100)
			stealPct = round2(float64(sys.Steal-prevSys.Steal) / fd * 100)
			totalPct = round2(100.0 - idlePct - iowaitPct)

			systemPayload["cpu"] = map[string]interface{}{
				"total":  map[string]interface{}{"pct": totalPct},
				"user":   map[string]interface{}{"pct": userPct},
				"system": map[string]interface{}{"pct": systemPct},
				"idle":   map[string]interface{}{"pct": idlePct},
				"iowait": map[string]interface{}{"pct": iowaitPct},
				"steal":  map[string]interface{}{"pct": stealPct},
				"cores":  sys.Cores,
			}
		}
	}

	tags := []string{"system", "metric"}
	if memErr == nil {
		tags = append(tags, "memory")
	}
	if hasCpuDelta {
		tags = append(tags, "cpu")
	}

	event := events.Event{
		ID:        fmt.Sprintf("sys-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "system.metrics",
		Category:  "host",
		Kind:      "metric",
		Severity:  events.SeverityInfo,
		Module:    "telemetry.system",
		AgentID:   s.agentID,
		Hostname:  s.hostname,
		Payload: map[string]interface{}{
			"system": systemPayload,
		},
		Tags: tags,
	}

	s.pipeline.Emit(event)
	if hasCpuDelta {
		log.Printf("system collector: emitted system.metrics (mem used_pct=%.1f%% cpu=%.1f%% cores=%d)",
			memInfo.UsedPercent, totalPct, sys.Cores)
	} else {
		log.Printf("system collector: emitted system.metrics (memory only, used_pct=%.1f%%)",
			memInfo.UsedPercent)
	}

	// ── Per-process CPU events (unchanged behavior) ─────────────────────
	if !hasCpuDelta || proc == nil || prevProc == nil {
		return
	}

	type procCpu struct {
		info   ProcessCpuSnapshot
		cpuPct float64
	}

	var ranked []procCpu
	fd := float64(totalDelta)
	for pid, curr := range proc {
		prev, ok := prevProc[pid]
		if !ok {
			continue
		}
		utimeDelta := curr.UTime - prev.UTime
		stimeDelta := curr.STime - prev.STime
		pct := round2(float64(utimeDelta+stimeDelta) / fd * 100)
		if pct < 0.01 {
			continue
		}
		ranked = append(ranked, procCpu{info: curr, cpuPct: pct})
	}

	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].cpuPct > ranked[j].cpuPct
	})

	limit := s.topN
	if limit > len(ranked) {
		limit = len(ranked)
	}

	for _, entry := range ranked[:limit] {
		procEvent := events.Event{
			ID:        fmt.Sprintf("cpu-proc-%d-%d", entry.info.PID, time.Now().UnixNano()),
			Timestamp: time.Now().UTC(),
			Type:      "process.cpu",
			Category:  "process",
			Kind:      "metric",
			Severity:  events.SeverityInfo,
			Module:    "telemetry.system",
			AgentID:   s.agentID,
			Hostname:  s.hostname,
			Payload: map[string]interface{}{
				"process": map[string]interface{}{
					"pid":          entry.info.PID,
					"name":         entry.info.Name,
					"executable":   entry.info.Executable,
					"command_line": entry.info.CommandLine,
					"cpu": map[string]interface{}{
						"pct": entry.cpuPct,
					},
				},
			},
			Tags: []string{"cpu", "process", "metric"},
		}
		s.pipeline.Emit(procEvent)
	}

	if limit > 0 {
		log.Printf("system collector: emitted %d process.cpu events (top by CPU%%)", limit)
	}
}
