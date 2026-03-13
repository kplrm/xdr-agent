//go:build linux

// Package kernel monitors kernel-level events: module loading/unloading and eBPF telemetry.
//
// ModuleCollector polls /proc/modules every 10 seconds, diffs the known-module set,
// and emits events for newly loaded or unloaded kernel modules.
//
// MITRE ATT&CK: T1547.006 (Boot or Logon Autostart: Kernel Modules and Extensions),
//
//	T1014    (Rootkit)
package kernel

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

const (
	defaultKernelModuleInterval = 10 * time.Second
	procModulesPath             = "/proc/modules"
)

// ModuleInfo holds metadata for one kernel module as reported by /proc/modules.
//
// /proc/modules format (space-separated):
//
//	name size refcount deps state address
type ModuleInfo struct {
	Name     string
	Size     int64
	RefCount int
	Deps     []string
	State    string // Live, Loading, Unloading
	Address  string // kernel load address (hex)
}

// ModuleCollector monitors /proc/modules for kernel module load/unload events.
// It implements capability.Capability.
type ModuleCollector struct {
	pipeline *events.Pipeline
	agentID  string
	hostname string
	interval time.Duration

	mu     sync.Mutex
	known  map[string]ModuleInfo // name → info; nil until first scan
	health capability.HealthStatus
	cancel context.CancelFunc
}

// NewModuleCollector creates a new kernel module telemetry collector.
// Pass 0 for interval to use the 10 s default.
func NewModuleCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *ModuleCollector {
	if interval <= 0 {
		interval = defaultKernelModuleInterval
	}
	return &ModuleCollector{
		pipeline: pipeline,
		agentID:  agentID,
		hostname: hostname,
		interval: interval,
		health:   capability.HealthStopped,
	}
}

// ── capability.Capability ────────────────────────────────────────────────────

func (m *ModuleCollector) Name() string { return "telemetry.kernel.modules" }

func (m *ModuleCollector) Init(_ capability.Dependencies) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.health = capability.HealthStarting
	return nil
}

func (m *ModuleCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.cancel = cancel
	m.health = capability.HealthRunning
	m.mu.Unlock()

	go m.loop(childCtx)
	return nil
}

func (m *ModuleCollector) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
	m.health = capability.HealthStopped
	return nil
}

func (m *ModuleCollector) Health() capability.HealthStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.health
}

// ── internal ─────────────────────────────────────────────────────────────────

func (m *ModuleCollector) loop(ctx context.Context) {
	// First scan establishes a baseline without emitting events.
	m.scan(ctx, true)

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scan(ctx, false)
		}
	}
}

func (m *ModuleCollector) scan(ctx context.Context, baseline bool) {
	snapshot, err := readProcModules()
	if err != nil {
		log.Printf("kernel.modules: read %s: %v", procModulesPath, err)
		m.mu.Lock()
		m.health = capability.HealthDegraded
		m.mu.Unlock()
		return
	}

	m.mu.Lock()
	previous := m.known
	m.known = snapshot
	m.health = capability.HealthRunning
	m.mu.Unlock()

	if baseline {
		log.Printf("kernel.modules: baseline established with %d modules", len(snapshot))
		return
	}

	if ctx.Err() != nil {
		return
	}

	// Newly loaded modules (in snapshot but not in previous).
	for name, info := range snapshot {
		if _, existed := previous[name]; !existed {
			m.emitEvent("kernel.module_load", events.SeverityHigh, info)
		}
	}

	// Unloaded modules (in previous but not in snapshot).
	for name, info := range previous {
		if _, exists := snapshot[name]; !exists {
			m.emitEvent("kernel.module_unload", events.SeverityMedium, info)
		}
	}
}

func (m *ModuleCollector) emitEvent(eventType string, severity events.Severity, mod ModuleInfo) {
	payload := map[string]interface{}{
		"xdr": map[string]interface{}{
			"kernel_module": map[string]interface{}{
				"name":      mod.Name,
				"size":      mod.Size,
				"ref_count": mod.RefCount,
				"deps":      mod.Deps,
				"state":     mod.State,
				"address":   mod.Address,
			},
		},
		// ECS driver fields (closest ECS mapping for kernel modules)
		"driver": map[string]interface{}{
			"name": mod.Name,
		},
	}

	ev := events.Event{
		ID:            fmt.Sprintf("kmod-%s-%s-%d", eventType, mod.Name, time.Now().UnixNano()),
		Timestamp:     time.Now().UTC(),
		Type:          eventType,
		Category:      "driver",
		Kind:          "event",
		Severity:      severity,
		Module:        "telemetry.kernel.modules",
		AgentID:       m.agentID,
		Hostname:      m.hostname,
		MitreTactic:   "Persistence",
		MitreTechique: "T1547.006",
		Tags:          []string{"kernel", "module", "telemetry"},
		Payload:       payload,
	}
	m.pipeline.Emit(ev)
}

// ── /proc/modules parser ──────────────────────────────────────────────────────

// readProcModules parses /proc/modules and returns a map of name → ModuleInfo.
//
// /proc/modules line format:
//
//	<name> <size> <refcount> <deps> <state> <address>
//
// Example:
//
//	binfmt_misc 24576 1 - Live 0xffffffffc08b4000
func readProcModules() (map[string]ModuleInfo, error) {
	f, err := os.Open(procModulesPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	mods := make(map[string]ModuleInfo)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		name := fields[0]
		var size int64
		fmt.Sscanf(fields[1], "%d", &size)
		var refCount int
		fmt.Sscanf(fields[2], "%d", &refCount)

		deps := []string{}
		if fields[3] != "-" {
			for _, d := range strings.Split(strings.TrimSuffix(fields[3], ","), ",") {
				if d != "" {
					deps = append(deps, d)
				}
			}
		}

		state := fields[4]
		address := fields[5]

		mods[name] = ModuleInfo{
			Name:     name,
			Size:     size,
			RefCount: refCount,
			Deps:     deps,
			State:    state,
			Address:  address,
		}
	}

	return mods, scanner.Err()
}
