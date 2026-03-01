package system

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

// CpuStats holds parsed aggregate CPU times from the "cpu" line in /proc/stat.
type CpuStats struct {
	User    uint64
	Nice    uint64
	System  uint64
	Idle    uint64
	IOWait  uint64
	IRQ     uint64
	SoftIRQ uint64
	Steal   uint64
	Total   uint64 // sum of all fields above
	Cores   int    // count of cpuN lines
}

// ProcessCpuSnapshot holds cumulative CPU times for a single process,
// read from /proc/[pid]/stat.
type ProcessCpuSnapshot struct {
	PID         int
	Name        string
	Executable  string
	CommandLine string // full command line including arguments
	UTime       uint64 // cumulative user-mode clock ticks
	STime       uint64 // cumulative kernel-mode clock ticks
}

const defaultTopN = 20

// CpuCollector reads /proc/stat and per-process CPU times periodically,
// computes deltas between readings, and emits system.cpu and process.cpu
// metric events into the event pipeline.
//
// ECS field mapping (within payload):
//
//	system.cpu.total.pct    → total CPU usage (0–100)
//	system.cpu.user.pct     → user-mode CPU (0–100)
//	system.cpu.system.pct   → kernel-mode CPU (0–100)
//	system.cpu.idle.pct     → idle (0–100)
//	system.cpu.iowait.pct   → I/O wait (0–100)
//	system.cpu.steal.pct    → steal (0–100)
//	system.cpu.cores        → online core count
//	process.pid             → process ID
//	process.name            → process name (comm)
//	process.executable      → executable path
//	process.cpu.pct         → per-process CPU usage (0–100)
type CpuCollector struct {
	pipeline *events.Pipeline
	agentID  string
	hostname string
	interval time.Duration
	procRoot string
	topN     int

	mu       sync.Mutex
	health   capability.HealthStatus
	cancel   context.CancelFunc
	prevSys  *CpuStats
	prevProc map[int]ProcessCpuSnapshot
}

// NewCpuCollector creates a new CPU telemetry collector.
//
// Parameters:
//   - pipeline: the central event bus to emit events into
//   - agentID:  the enrolled agent identifier
//   - hostname: the host's name (for event enrichment)
//   - interval: how often to collect CPU metrics (0 → 60 s default)
func NewCpuCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *CpuCollector {
	if interval <= 0 {
		interval = defaultInterval
	}
	return &CpuCollector{
		pipeline: pipeline,
		agentID:  agentID,
		hostname: hostname,
		interval: interval,
		procRoot: "/proc",
		topN:     defaultTopN,
		health:   capability.HealthStopped,
	}
}

// SetProcRoot overrides the default /proc path (useful for testing).
func (c *CpuCollector) SetProcRoot(path string) {
	c.procRoot = path
}

// ── capability.Capability interface ──────────────────────────────────────────

func (c *CpuCollector) Name() string { return "telemetry.system.cpu" }

func (c *CpuCollector) Init(_ capability.Dependencies) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health = capability.HealthStarting
	return nil
}

func (c *CpuCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	c.health = capability.HealthRunning
	c.mu.Unlock()

	go c.loop(childCtx)
	return nil
}

func (c *CpuCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	c.health = capability.HealthStopped
	return nil
}

func (c *CpuCollector) Health() capability.HealthStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

// ── internal ─────────────────────────────────────────────────────────────────

// loop runs the periodic collection cycle. The first tick captures a baseline
// (no deltas available yet). Subsequent ticks compute and emit deltas.
func (c *CpuCollector) loop(ctx context.Context) {
	// First collection: store baseline, don't emit (no delta yet).
	c.collectBaseline()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collectAndEmit()
		}
	}
}

// collectBaseline reads the initial CPU state without emitting events.
func (c *CpuCollector) collectBaseline() {
	sys, err := ReadSystemCpu(c.procRoot)
	if err != nil {
		log.Printf("cpu collector: baseline read failed: %v", err)
		c.mu.Lock()
		c.health = capability.HealthDegraded
		c.mu.Unlock()
		return
	}

	proc, err := ReadProcessCpuTimes(c.procRoot)
	if err != nil {
		log.Printf("cpu collector: baseline process read failed: %v", err)
	}

	c.mu.Lock()
	c.prevSys = &sys
	c.prevProc = proc
	c.mu.Unlock()
	log.Printf("cpu collector: baseline captured (%d cores, %d processes)", sys.Cores, len(proc))
}

// collectAndEmit reads current CPU state, computes deltas versus the previous
// reading, and emits system.cpu + process.cpu events.
func (c *CpuCollector) collectAndEmit() {
	sys, err := ReadSystemCpu(c.procRoot)
	if err != nil {
		log.Printf("cpu collector: system CPU read failed: %v", err)
		c.mu.Lock()
		c.health = capability.HealthDegraded
		c.mu.Unlock()
		return
	}

	proc, err := ReadProcessCpuTimes(c.procRoot)
	if err != nil {
		log.Printf("cpu collector: process CPU read failed: %v", err)
	}

	c.mu.Lock()
	prevSys := c.prevSys
	prevProc := c.prevProc
	c.prevSys = &sys
	c.prevProc = proc
	c.health = capability.HealthRunning
	c.mu.Unlock()

	if prevSys == nil {
		return // no previous reading
	}

	totalDelta := sys.Total - prevSys.Total
	if totalDelta == 0 {
		return // avoid division by zero
	}

	fd := float64(totalDelta)
	userPct := round2(float64(sys.User-prevSys.User) / fd * 100)
	systemPct := round2(float64(sys.System-prevSys.System) / fd * 100)
	idlePct := round2(float64(sys.Idle-prevSys.Idle) / fd * 100)
	iowaitPct := round2(float64(sys.IOWait-prevSys.IOWait) / fd * 100)
	stealPct := round2(float64(sys.Steal-prevSys.Steal) / fd * 100)
	totalPct := round2(100.0 - idlePct - iowaitPct)

	// ── Emit system.cpu event ────────────────────────────────────────
	sysEvent := events.Event{
		ID:        fmt.Sprintf("cpu-sys-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "system.cpu",
		Category:  "host",
		Kind:      "metric",
		Severity:  events.SeverityInfo,
		Module:    "telemetry.system.cpu",
		AgentID:   c.agentID,
		Hostname:  c.hostname,
		Payload: map[string]interface{}{
			"system": map[string]interface{}{
				"cpu": map[string]interface{}{
					"total":  map[string]interface{}{"pct": totalPct},
					"user":   map[string]interface{}{"pct": userPct},
					"system": map[string]interface{}{"pct": systemPct},
					"idle":   map[string]interface{}{"pct": idlePct},
					"iowait": map[string]interface{}{"pct": iowaitPct},
					"steal":  map[string]interface{}{"pct": stealPct},
					"cores":  sys.Cores,
				},
			},
		},
		Tags: []string{"cpu", "system", "metric"},
	}
	c.pipeline.Emit(sysEvent)
	log.Printf("cpu collector: emitted metric total=%.1f%% user=%.1f%% sys=%.1f%% idle=%.1f%% cores=%d",
		totalPct, userPct, systemPct, idlePct, sys.Cores)

	// ── Per-process CPU: compute deltas, sort, emit top N ────────────
	type procCpu struct {
		info   ProcessCpuSnapshot
		cpuPct float64
	}

	var ranked []procCpu
	for pid, curr := range proc {
		prev, ok := prevProc[pid]
		if !ok {
			continue // new process since last reading, skip (no delta)
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

	limit := c.topN
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
			Module:    "telemetry.system.cpu",
			AgentID:   c.agentID,
			Hostname:  c.hostname,
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
		c.pipeline.Emit(procEvent)
	}

	if limit > 0 {
		log.Printf("cpu collector: emitted %d process.cpu events (top by CPU%%)", limit)
	}
}

// round2 rounds a float64 to 2 decimal places.
func round2(f float64) float64 {
	return math.Round(f*100) / 100
}

// ── parsing helpers (exported for testing) ───────────────────────────────────

// readProcCmdline reads /proc/[pid]/cmdline, trims trailing NUL bytes, and
// replaces NUL argument separators with spaces to produce a human-readable
// command line string.  Returns empty string on any error.
func readProcCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Trim trailing NUL
	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	// Replace NUL argument separators with spaces
	for i := range data {
		if data[i] == 0 {
			data[i] = ' '
		}
	}
	return string(data)
}

// ReadSystemCpu parses /proc/stat and returns aggregate CPU times and core count.
func ReadSystemCpu(procRoot string) (CpuStats, error) {
	path := filepath.Join(procRoot, "stat")
	f, err := os.Open(path)
	if err != nil {
		return CpuStats{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var stats CpuStats
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			if err := parseCpuLine(line, &stats); err != nil {
				return CpuStats{}, err
			}
		} else if len(line) > 3 && strings.HasPrefix(line, "cpu") && line[3] >= '0' && line[3] <= '9' {
			stats.Cores++
		}
	}

	if stats.Total == 0 {
		return CpuStats{}, fmt.Errorf("no cpu line found in %s", path)
	}

	return stats, nil
}

// parseCpuLine parses the aggregate "cpu  ..." line from /proc/stat.
func parseCpuLine(line string, stats *CpuStats) error {
	fields := strings.Fields(line)
	if len(fields) < 9 { // cpu + 8 numeric fields minimum
		return fmt.Errorf("cpu line too short: %d fields", len(fields))
	}

	vals := make([]uint64, 8)
	for i := 0; i < 8; i++ {
		v, err := strconv.ParseUint(fields[i+1], 10, 64)
		if err != nil {
			return fmt.Errorf("parse cpu field %d: %w", i, err)
		}
		vals[i] = v
	}

	stats.User = vals[0]
	stats.Nice = vals[1]
	stats.System = vals[2]
	stats.Idle = vals[3]
	stats.IOWait = vals[4]
	stats.IRQ = vals[5]
	stats.SoftIRQ = vals[6]
	stats.Steal = vals[7]
	stats.Total = vals[0] + vals[1] + vals[2] + vals[3] + vals[4] + vals[5] + vals[6] + vals[7]

	return nil
}

// ReadProcessCpuTimes scans all numeric directories under procRoot and extracts
// per-process CPU times (utime, stime) from /proc/[pid]/stat.
func ReadProcessCpuTimes(procRoot string) (map[int]ProcessCpuSnapshot, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", procRoot, err)
	}

	result := make(map[int]ProcessCpuSnapshot)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}
		snap, err := ParseProcessStatCpu(procRoot, pid)
		if err != nil {
			continue // process may have vanished
		}
		result[pid] = snap
	}

	return result, nil
}

// ParseProcessStatCpu reads /proc/[pid]/stat and extracts the process name,
// utime (user clock ticks), and stime (kernel clock ticks).
//
// In /proc/[pid]/stat, after the closing ')', the fields are:
//
//	[0]=state [1]=ppid ... [11]=utime [12]=stime
func ParseProcessStatCpu(procRoot string, pid int) (ProcessCpuSnapshot, error) {
	path := filepath.Join(procRoot, strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(path)
	if err != nil {
		return ProcessCpuSnapshot{}, err
	}

	content := strings.TrimSpace(string(data))

	// comm may contain spaces or parens — find first '(' and last ')'.
	openParen := strings.IndexByte(content, '(')
	closeParen := strings.LastIndexByte(content, ')')
	if openParen < 0 || closeParen < 0 || closeParen <= openParen {
		return ProcessCpuSnapshot{}, fmt.Errorf("malformed stat for pid %d", pid)
	}

	name := content[openParen+1 : closeParen]

	rest := strings.TrimSpace(content[closeParen+1:])
	fields := strings.Fields(rest)
	if len(fields) < 13 { // need up to index 12 (stime)
		return ProcessCpuSnapshot{}, fmt.Errorf("too few fields in stat for pid %d: %d", pid, len(fields))
	}

	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return ProcessCpuSnapshot{}, fmt.Errorf("parse utime for pid %d: %w", pid, err)
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return ProcessCpuSnapshot{}, fmt.Errorf("parse stime for pid %d: %w", pid, err)
	}

	// Try to read the executable symlink; fall back to comm name.
	exe := name
	exePath := filepath.Join(procRoot, strconv.Itoa(pid), "exe")
	if link, err := os.Readlink(exePath); err == nil {
		exe = link
	}

	// Read full command line from /proc/[pid]/cmdline (NUL-separated args).
	cmdLine := readProcCmdline(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))

	return ProcessCpuSnapshot{
		PID:         pid,
		Name:        name,
		Executable:  exe,
		CommandLine: cmdLine,
		UTime:       utime,
		STime:       stime,
	}, nil
}
