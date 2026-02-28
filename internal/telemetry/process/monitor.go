// Package process provides real-time process monitoring for the XDR agent.
//
// It detects process creation and termination events by polling /proc,
// and enriches process data with metadata (user, command-line, executable).
//
// Linux implementation options (in order of preference):
//  1. eBPF tracepoints (sched_process_exec, sched_process_exit) — lowest overhead
//  2. Netlink process connector (PROC_EVENT_EXEC, PROC_EVENT_EXIT)
//  3. /proc filesystem polling — fallback for older kernels  ← current implementation
package process

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

const (
	defaultProcRoot     = "/proc"
	defaultProcInterval = 10 * time.Second
)

// ProcessInfo holds metadata about a running process read from /proc/[pid].
type ProcessInfo struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	Name       string `json:"name"`
	Executable string `json:"executable"`
	CmdLine    string `json:"command_line"`
	State      string `json:"state"`
	UID        int    `json:"uid"`
	GID        int    `json:"gid"`
	Threads    int    `json:"threads"`
	StartTime  uint64 `json:"start_time"` // clock ticks since boot
}

// ProcessCollector monitors process creation and termination by periodically
// scanning /proc and diffing the PID set. It implements capability.Capability.
type ProcessCollector struct {
	pipeline *events.Pipeline
	agentID  string
	hostname string
	interval time.Duration
	procRoot string // path to /proc; defaults to /proc

	mu       sync.Mutex
	health   capability.HealthStatus
	cancel   context.CancelFunc
	known    map[int]ProcessInfo
	baseline bool // true after the first scan completes
}

// NewProcessCollector creates a new process telemetry collector.
//
// Parameters:
//   - pipeline: the central event bus to emit events into
//   - agentID:  the enrolled agent identifier
//   - hostname: the host's name (for event enrichment)
//   - interval: how often to scan /proc (0 → 10 s default)
func NewProcessCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *ProcessCollector {
	if interval <= 0 {
		interval = defaultProcInterval
	}
	return &ProcessCollector{
		pipeline: pipeline,
		agentID:  agentID,
		hostname: hostname,
		interval: interval,
		procRoot: defaultProcRoot,
		health:   capability.HealthStopped,
		known:    make(map[int]ProcessInfo),
	}
}

// SetProcRoot overrides the default /proc path (useful for testing with
// synthetic /proc trees).
func (p *ProcessCollector) SetProcRoot(path string) { p.procRoot = path }

// ── capability.Capability interface ──────────────────────────────────────────

func (p *ProcessCollector) Name() string { return "telemetry.process" }

func (p *ProcessCollector) Init(_ capability.Dependencies) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.health = capability.HealthStarting
	return nil
}

func (p *ProcessCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	p.mu.Lock()
	p.cancel = cancel
	p.health = capability.HealthRunning
	p.mu.Unlock()

	go p.loop(childCtx)
	return nil
}

func (p *ProcessCollector) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
	}
	p.health = capability.HealthStopped
	return nil
}

func (p *ProcessCollector) Health() capability.HealthStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.health
}

// ── internal ─────────────────────────────────────────────────────────────────

// loop runs the periodic process scan cycle.
func (p *ProcessCollector) loop(ctx context.Context) {
	p.scan()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.scan()
		}
	}
}

// scan takes a /proc snapshot and emits events for new/gone processes.
func (p *ProcessCollector) scan() {
	snapshot, err := ScanProcesses(p.procRoot)
	if err != nil {
		log.Printf("process collector: scan failed: %v", err)
		p.mu.Lock()
		p.health = capability.HealthDegraded
		p.mu.Unlock()
		return
	}

	p.mu.Lock()
	prevKnown := p.known
	wasBaseline := p.baseline
	p.known = snapshot
	p.baseline = true
	p.health = capability.HealthRunning
	p.mu.Unlock()

	if !wasBaseline {
		// First scan: establish baseline without emitting events for every
		// existing process (that would flood the pipeline on agent start).
		log.Printf("process collector: baseline established with %d processes", len(snapshot))
		return
	}

	// New processes (in snapshot but not in previous)
	for pid, info := range snapshot {
		if _, existed := prevKnown[pid]; !existed {
			p.emitEvent("process.start", info)
		}
	}

	// Terminated processes (in previous but not in snapshot)
	for pid, info := range prevKnown {
		if _, exists := snapshot[pid]; !exists {
			p.emitEvent("process.end", info)
		}
	}
}

// emitEvent publishes a process lifecycle event into the pipeline.
func (p *ProcessCollector) emitEvent(eventType string, info ProcessInfo) {
	event := events.Event{
		ID:        fmt.Sprintf("proc-%s-%d-%d", eventType, info.PID, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		Category:  "process",
		Kind:      "event",
		Severity:  events.SeverityInfo,
		Module:    "telemetry.process",
		AgentID:   p.agentID,
		Hostname:  p.hostname,
		Payload: map[string]interface{}{
			"process": map[string]interface{}{
				"pid":          info.PID,
				"ppid":         info.PPID,
				"name":         info.Name,
				"executable":   info.Executable,
				"command_line": info.CmdLine,
				"state":        info.State,
				"uid":          info.UID,
				"gid":          info.GID,
				"threads":      info.Threads,
				"start_time":   info.StartTime,
			},
		},
		Tags: []string{"process", "telemetry"},
	}

	p.pipeline.Emit(event)
	log.Printf("process collector: %s pid=%d name=%s ppid=%d uid=%d exe=%s",
		eventType, info.PID, info.Name, info.PPID, info.UID, info.Executable)
}

// ── public parsing helpers (testable) ────────────────────────────────────────

// ScanProcesses reads all numeric (PID) directories under procRoot and returns
// a snapshot mapping PID → ProcessInfo. Processes that vanish between the
// directory listing and the individual reads are silently skipped.
func ScanProcesses(procRoot string) (map[int]ProcessInfo, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", procRoot, err)
	}

	result := make(map[int]ProcessInfo)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}
		info, err := ReadProcessInfo(procRoot, pid)
		if err != nil {
			continue // process may have exited between readdir and read
		}
		result[pid] = info
	}
	return result, nil
}

// ReadProcessInfo reads process metadata from /proc/[pid]/{stat,status,cmdline,exe}.
func ReadProcessInfo(procRoot string, pid int) (ProcessInfo, error) {
	pidDir := filepath.Join(procRoot, strconv.Itoa(pid))
	info := ProcessInfo{PID: pid}

	// Parse /proc/[pid]/stat — fields: PID (comm) state ppid ... starttime
	if err := parseStatFile(filepath.Join(pidDir, "stat"), &info); err != nil {
		return ProcessInfo{}, err
	}

	// Parse /proc/[pid]/status — Uid, Gid, Threads
	parseStatusFile(filepath.Join(pidDir, "status"), &info)

	// Read /proc/[pid]/cmdline — NUL-separated arguments
	info.CmdLine = readCmdline(filepath.Join(pidDir, "cmdline"))

	// Read /proc/[pid]/exe — symlink to the executable
	if target, err := os.Readlink(filepath.Join(pidDir, "exe")); err == nil {
		info.Executable = target
	}

	return info, nil
}

// parseStatFile parses /proc/[pid]/stat for name, state, ppid, and starttime.
// The comm field is enclosed in parentheses and may contain spaces, so we
// locate the last ')' to split reliably.
func parseStatFile(path string, info *ProcessInfo) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read stat: %w", err)
	}
	content := string(data)

	openParen := strings.IndexByte(content, '(')
	closeParen := strings.LastIndexByte(content, ')')
	if openParen < 0 || closeParen < 0 || closeParen <= openParen {
		return fmt.Errorf("malformed stat: %s", path)
	}

	info.Name = content[openParen+1 : closeParen]

	// Fields after the closing paren: state(0) ppid(1) ... starttime(19)
	rest := strings.Fields(content[closeParen+2:])
	if len(rest) < 20 {
		return fmt.Errorf("stat has too few fields (%d): %s", len(rest), path)
	}

	info.State = rest[0]

	if ppid, err := strconv.Atoi(rest[1]); err == nil {
		info.PPID = ppid
	}
	// rest[19] is field 22 (starttime — clock ticks since boot)
	if st, err := strconv.ParseUint(rest[19], 10, 64); err == nil {
		info.StartTime = st
	}

	return nil
}

// parseStatusFile reads /proc/[pid]/status for UID, GID, and thread count.
// Errors are silently ignored — the data is optional enrichment.
func parseStatusFile(path string, info *ProcessInfo) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.UID, _ = strconv.Atoi(fields[1])
			}
		case strings.HasPrefix(line, "Gid:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.GID, _ = strconv.Atoi(fields[1])
			}
		case strings.HasPrefix(line, "Threads:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.Threads, _ = strconv.Atoi(fields[1])
			}
		}
	}
}

// readCmdline reads /proc/[pid]/cmdline, trims trailing NUL bytes, and
// replaces NUL argument separators with spaces.
func readCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	data = bytes.TrimRight(data, "\x00")
	return string(bytes.ReplaceAll(data, []byte{0}, []byte{' '}))
}
