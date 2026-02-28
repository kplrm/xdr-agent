// Package system provides system-level telemetry collectors for the XDR agent.
// These collectors gather host metrics (memory, CPU, disk, etc.) and emit them
// as structured events into the event pipeline.
package system

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

const (
	defaultProcMeminfo = "/proc/meminfo"
	defaultInterval    = 60 * time.Second
)

// MemoryInfo holds parsed memory statistics from /proc/meminfo.
type MemoryInfo struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	FreeBytes      uint64  `json:"free_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	BuffersBytes   uint64  `json:"buffers_bytes"`
	CachedBytes    uint64  `json:"cached_bytes"`
	SwapTotalBytes uint64  `json:"swap_total_bytes"`
	SwapFreeBytes  uint64  `json:"swap_free_bytes"`
	SwapUsedBytes  uint64  `json:"swap_used_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

// MemoryCollector reads /proc/meminfo periodically and emits memory metric
// events into the event pipeline. It implements capability.Capability.
type MemoryCollector struct {
	pipeline *events.Pipeline
	agentID  string
	hostname string
	interval time.Duration
	procPath string // path to meminfo file; defaults to /proc/meminfo

	mu     sync.Mutex
	health capability.HealthStatus
	cancel context.CancelFunc
}

// NewMemoryCollector creates a new memory telemetry collector.
//
// Parameters:
//   - pipeline: the central event bus to emit events into
//   - agentID:  the enrolled agent identifier
//   - hostname: the host's name (for event enrichment)
//   - interval: how often to collect memory metrics (0 → 60 s default)
func NewMemoryCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *MemoryCollector {
	if interval <= 0 {
		interval = defaultInterval
	}
	return &MemoryCollector{
		pipeline: pipeline,
		agentID:  agentID,
		hostname: hostname,
		interval: interval,
		procPath: defaultProcMeminfo,
		health:   capability.HealthStopped,
	}
}

// SetProcPath overrides the default /proc/meminfo path (useful for testing).
func (m *MemoryCollector) SetProcPath(path string) {
	m.procPath = path
}

// ── capability.Capability interface ──────────────────────────────────────────

func (m *MemoryCollector) Name() string { return "telemetry.system.memory" }

func (m *MemoryCollector) Init(_ capability.Dependencies) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.health = capability.HealthStarting
	return nil
}

func (m *MemoryCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.cancel = cancel
	m.health = capability.HealthRunning
	m.mu.Unlock()

	go m.loop(childCtx)
	return nil
}

func (m *MemoryCollector) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
	m.health = capability.HealthStopped
	return nil
}

func (m *MemoryCollector) Health() capability.HealthStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.health
}

// ── internal ─────────────────────────────────────────────────────────────────

// loop runs the periodic collection cycle.
func (m *MemoryCollector) loop(ctx context.Context) {
	// Collect immediately on start, then on each tick.
	m.collectAndEmit()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.collectAndEmit()
		}
	}
}

// collectAndEmit reads memory info and emits an event.
func (m *MemoryCollector) collectAndEmit() {
	info, err := ReadMemoryInfo(m.procPath)
	if err != nil {
		log.Printf("memory collector: %v", err)
		m.mu.Lock()
		m.health = capability.HealthDegraded
		m.mu.Unlock()
		return
	}

	m.mu.Lock()
	m.health = capability.HealthRunning
	m.mu.Unlock()

	event := events.Event{
		ID:        fmt.Sprintf("mem-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "system.memory",
		Category:  "host",
		Kind:      "metric",
		Severity:  events.SeverityInfo,
		Module:    "telemetry.system.memory",
		AgentID:   m.agentID,
		Hostname:  m.hostname,
		Payload: map[string]interface{}{
			"system": map[string]interface{}{
				"memory": map[string]interface{}{
					"total_bytes":     info.TotalBytes,
					"used_bytes":      info.UsedBytes,
					"free_bytes":      info.FreeBytes,
					"available_bytes": info.AvailableBytes,
					"buffers_bytes":   info.BuffersBytes,
					"cached_bytes":    info.CachedBytes,
					"swap_total_bytes": info.SwapTotalBytes,
					"swap_free_bytes": info.SwapFreeBytes,
					"swap_used_bytes": info.SwapUsedBytes,
					"used_percent":    info.UsedPercent,
				},
			},
		},
		Tags: []string{"memory", "system", "metric"},
	}

	m.pipeline.Emit(event)
	log.Printf("memory collector: emitted metric total=%d used=%d free=%d available=%d used_pct=%.1f%%",
		info.TotalBytes, info.UsedBytes, info.FreeBytes, info.AvailableBytes, info.UsedPercent)
}

// ReadMemoryInfo parses the given /proc/meminfo-format file and returns
// structured memory statistics.
func ReadMemoryInfo(path string) (MemoryInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return MemoryInfo{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	return ParseMeminfo(f)
}

// ParseMeminfo parses a /proc/meminfo formatted reader into MemoryInfo.
func ParseMeminfo(r *os.File) (MemoryInfo, error) {
	fields := make(map[string]uint64)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.TrimSuffix(parts[0], ":")
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}

		// /proc/meminfo values are in kB; convert to bytes.
		if len(parts) >= 3 && strings.ToLower(parts[2]) == "kb" {
			value *= 1024
		}

		fields[key] = value
	}

	if err := scanner.Err(); err != nil {
		return MemoryInfo{}, fmt.Errorf("scan meminfo: %w", err)
	}

	total := fields["MemTotal"]
	free := fields["MemFree"]
	available := fields["MemAvailable"]
	buffers := fields["Buffers"]
	cached := fields["Cached"]
	swapTotal := fields["SwapTotal"]
	swapFree := fields["SwapFree"]

	// Used = Total - Free - Buffers - Cached (standard calculation)
	used := uint64(0)
	if total > free+buffers+cached {
		used = total - free - buffers - cached
	}

	swapUsed := uint64(0)
	if swapTotal > swapFree {
		swapUsed = swapTotal - swapFree
	}

	usedPercent := 0.0
	if total > 0 {
		usedPercent = float64(used) / float64(total) * 100.0
	}

	return MemoryInfo{
		TotalBytes:     total,
		UsedBytes:      used,
		FreeBytes:      free,
		AvailableBytes: available,
		BuffersBytes:   buffers,
		CachedBytes:    cached,
		SwapTotalBytes: swapTotal,
		SwapFreeBytes:  swapFree,
		SwapUsedBytes:  swapUsed,
		UsedPercent:    usedPercent,
	}, nil
}
