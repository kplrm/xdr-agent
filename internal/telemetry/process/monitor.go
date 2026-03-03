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
	"math"
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
// Fields map to ECS process.* unless noted.
type ProcessInfo struct {
	// ── Core identity ────────────────────────────────────────────────────────
	PID        int      `json:"pid"`            // process.pid
	PPID       int      `json:"ppid"`           // process.parent.pid
	Name       string   `json:"name"`           // process.name
	Executable string   `json:"executable"`     // process.executable
	CmdLine    string   `json:"command_line"`   // process.command_line
	Args       []string `json:"args,omitempty"` // process.args
	State      string   `json:"state"`          // process.state (R/S/D/Z/T)
	StartTime  uint64   `json:"start_time"`     // process.start (clock ticks since boot)
	EntityID   string   `json:"entity_id"`      // process.entity_id (computed at emit)

	// ── Session / terminal ───────────────────────────────────────────────────
	SessionID int `json:"session_id"` // process.session_leader.pid approx
	TTY       int `json:"tty"`        // process.tty.char_device.major (raw tty_nr)

	// ── User / group context ─────────────────────────────────────────────────
	UID       int    `json:"uid"`      // process.user.id
	GID       int    `json:"gid"`      // process.group.id
	EUID      int    `json:"euid"`     // process.effective_user.id (privilege escalation)
	EGID      int    `json:"egid"`     // process.effective_group.id
	Username  string `json:"username"` // process.user.name   (resolved at process.start)
	GroupName string `json:"group"`    // process.group.name  (resolved at process.start)

	// ── Security ─────────────────────────────────────────────────────────────
	CapEff    string `json:"cap_eff"`    // Linux effective capability bitmask
	ExeSHA256 string `json:"exe_sha256"` // process.hash.sha256 (computed at process.start)

	// ── Resource metrics ─────────────────────────────────────────────────────
	Threads      int    `json:"threads"`        // process.threads.count
	FDCount      int    `json:"fd_count"`       // open file descriptor count
	MemRSSBytes  int64  `json:"mem_rss_bytes"`  // process.memory.rss (resident set)
	MemVMSBytes  int64  `json:"mem_vms_bytes"`  // process.memory.vms (virtual memory)
	IOReadBytes  uint64 `json:"io_read_bytes"`  // process.io.read_bytes (cumulative)
	IOWriteBytes uint64 `json:"io_write_bytes"` // process.io.write_bytes (cumulative)

	// ── Raw CPU ticks (for delta-based cpu.pct computation) ─────────────────
	UTime uint64 `json:"-"` // /proc/[pid]/stat field 14 (utime)
	STime uint64 `json:"-"` // /proc/[pid]/stat field 15 (stime)

	// ── Context ──────────────────────────────────────────────────────────────
	CWD         string `json:"working_directory"` // process.working_directory
	ContainerID string `json:"container_id"`      // container.id (empty for bare-metal)
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

	tree *ProcessTree // in-memory process lineage tree
	uids *uidCache    // UID → username cache
	gids *gidCache    // GID → group name cache

	// CPU delta tracking
	prevCPU      map[int][2]uint64 // pid → [utime, stime] from last scan
	prevSysTotal uint64            // total system CPU ticks from last scan
	latestCPUPct map[int]float64   // pid → cpu% from most recent delta computation
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
		pipeline:     pipeline,
		agentID:      agentID,
		hostname:     hostname,
		interval:     interval,
		procRoot:     defaultProcRoot,
		health:       capability.HealthStopped,
		known:        make(map[int]ProcessInfo),
		tree:         NewProcessTree(),
		uids:         newUIDCache(),
		gids:         newGIDCache(),
		prevCPU:      make(map[int][2]uint64),
		latestCPUPct: make(map[int]float64),
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

	// Run fast enrichment for every visible process (CWD, args, FDs, IO, container).
	for pid, info := range snapshot {
		enrichProcessInfo(p.procRoot, &info)
		snapshot[pid] = info
	}

	// Always keep the tree up to date so parent lookups are available at emit time.
	for _, info := range snapshot {
		p.tree.Update(info)
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
		// Seed CPU tracking state so the next scan has a delta to compare against.
		seedCPU := make(map[int][2]uint64, len(snapshot))
		for pid, info := range snapshot {
			seedCPU[pid] = [2]uint64{info.UTime, info.STime}
		}
		p.mu.Lock()
		p.prevCPU = seedCPU
		p.prevSysTotal = readSysTotalCPU(p.procRoot)
		p.mu.Unlock()
		return
	}

	// ── Compute per-process CPU deltas before emitting any lifecycle events so
	// that process.end events can carry the last-known cpu.pct of the process.
	p.mu.Lock()
	prevCPU := p.prevCPU
	prevSysTotal := p.prevSysTotal
	p.mu.Unlock()

	cpuPctByPID := make(map[int]float64)
	sysTotal := readSysTotalCPU(p.procRoot)
	if prevSysTotal > 0 && sysTotal > prevSysTotal {
		sysDelta := float64(sysTotal - prevSysTotal)
		for pid, info := range snapshot {
			if prev, ok := prevCPU[pid]; ok {
				utimeDelta := info.UTime - prev[0]
				stimeDelta := info.STime - prev[1]
				pct := math.Round(float64(utimeDelta+stimeDelta)/sysDelta*10000) / 100
				if pct >= 0.01 {
					cpuPctByPID[pid] = pct
				}
			}
		}
	}

	// Persist latest CPU% per PID for next lifecycle event lookups.
	p.mu.Lock()
	for pid, pct := range cpuPctByPID {
		p.latestCPUPct[pid] = pct
	}
	newPrevCPU := make(map[int][2]uint64, len(snapshot))
	for pid, info := range snapshot {
		newPrevCPU[pid] = [2]uint64{info.UTime, info.STime}
	}
	p.prevCPU = newPrevCPU
	p.prevSysTotal = sysTotal
	p.mu.Unlock()

	// New processes (in snapshot but not in previous).
	// New processes have no prior CPU sample, so cpuPct = 0 (field omitted).
	for pid, info := range snapshot {
		if _, existed := prevKnown[pid]; !existed {
			enrichNewProcess(&info, p.uids, p.gids)
			p.emitEvent("process.start", info, 0)
		}
	}

	// Terminated processes (in previous but not in snapshot).
	// Include the last known cpu.pct so the final event is fully enriched.
	for pid, info := range prevKnown {
		if _, exists := snapshot[pid]; !exists {
			p.mu.Lock()
			cpuPct := p.latestCPUPct[pid]
			delete(p.latestCPUPct, pid)
			p.mu.Unlock()
			p.emitEvent("process.end", info, cpuPct)
			p.tree.Remove(pid)
		}
	}
}

// emitEvent publishes a process lifecycle event into the pipeline.
// cpuPct is the process CPU % from the most recent delta (0 = not yet measured;
// the field is omitted from the payload when cpuPct <= 0).
func (p *ProcessCollector) emitEvent(eventType string, info ProcessInfo, cpuPct float64) {
	// ── Entity ID (stable process instance identifier) ───────────────────────
	entityID := buildEntityID(p.hostname, info.PID, info.StartTime)

	// ── Process lineage from tree ────────────────────────────────────────────
	parentPayload := map[string]interface{}{}
	if parent, ok := p.tree.GetParent(info.PID); ok {
		parentEntityID := buildEntityID(p.hostname, parent.PID, parent.StartTime)
		parentPayload = map[string]interface{}{
			"pid":          parent.PID,
			"ppid":         parent.PPID,
			"name":         parent.Name,
			"executable":   parent.Executable,
			"command_line": parent.CmdLine,
			"args":         parent.Args,
			"entity_id":    parentEntityID,
		}
	}

	// Ancestor chain (ordered from direct parent → root).
	rawAncestors := p.tree.Ancestors(info.PID)
	ancestorsPayload := make([]map[string]interface{}, 0, len(rawAncestors))
	for _, anc := range rawAncestors {
		ancEntityID := buildEntityID(p.hostname, anc.PID, anc.StartTime)
		ancestorsPayload = append(ancestorsPayload, map[string]interface{}{
			"pid":        anc.PID,
			"ppid":       anc.PPID,
			"name":       anc.Name,
			"executable": anc.Executable,
			"entity_id":  ancEntityID,
		})
	}

	// Group leader (session leader approximation).
	groupLeaderPayload := map[string]interface{}{}
	if leader, ok := p.tree.GetGroupLeader(info.PID); ok {
		leaderEntityID := buildEntityID(p.hostname, leader.PID, leader.StartTime)
		groupLeaderPayload = map[string]interface{}{
			"pid":       leader.PID,
			"name":      leader.Name,
			"entity_id": leaderEntityID,
		}
	}

	// ── Assemble process payload (ECS-aligned) ───────────────────────────────
	proc := map[string]interface{}{
		// Core identity
		"pid":               info.PID,
		"ppid":              info.PPID,
		"name":              info.Name,
		"executable":        info.Executable,
		"command_line":      info.CmdLine,
		"args":              info.Args,
		"working_directory": info.CWD,
		"state":             info.State,
		"start_time":        info.StartTime, // raw clock ticks; convert to timestamp with SC_CLK_TCK + /proc/uptime
		"entity_id":         entityID,

		// Session / terminal
		"session_id": info.SessionID,
		"tty":        info.TTY,

		// User / group context
		"user": map[string]interface{}{
			"id":   info.UID,
			"name": info.Username,
		},
		"group": map[string]interface{}{
			"id":   info.GID,
			"name": info.GroupName,
		},
		"effective_user": map[string]interface{}{
			"id": info.EUID,
		},
		"effective_group": map[string]interface{}{
			"id": info.EGID,
		},

		// Security
		"cap_eff": info.CapEff,
		"hash": map[string]interface{}{
			"sha256": info.ExeSHA256,
		},

		// Resource metrics
		"threads": map[string]interface{}{
			"count": info.Threads,
		},
		"fd_count": info.FDCount,
		"memory": map[string]interface{}{
			"rss": info.MemRSSBytes,
			"vms": info.MemVMSBytes,
		},
		"io": map[string]interface{}{
			"read_bytes":  info.IOReadBytes,
			"write_bytes": info.IOWriteBytes,
		},

		// Lineage
		"parent":       parentPayload,
		"ancestors":    ancestorsPayload,
		"group_leader": groupLeaderPayload,
	}

	// Embed cpu.pct only when a measured delta is available.
	if cpuPct > 0 {
		proc["cpu"] = map[string]interface{}{
			"pct": cpuPct,
		}
	}

	// ── Phase 2c: process.start enrichment ───────────────────────────────────
	if eventType == "process.start" {
		// Environment variable capture — read filtered env vars from
		// /proc/[pid]/environ (MITRE T1574.006).
		if envVars := readEnvVars(p.procRoot, info.PID, defaultEnvAllowlist); envVars != nil {
			proc["env"] = envVars
		}
		// Script content capture — when the process is an interpreter,
		// read the first 4 KiB of the script file (MITRE T1059).
		if sc := captureScriptPayload(info.Executable, info.Args, 4096); sc != nil {
			proc["script"] = sc
		}
	}

	payload := map[string]interface{}{
		"process": proc,
	}

	// Container context — only include when detected (avoids empty object noise).
	if info.ContainerID != "" {
		payload["container"] = map[string]interface{}{
			"id": info.ContainerID,
		}
	}

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
		Payload:   payload,
		Tags:      []string{"process", "telemetry"},
	}

	p.pipeline.Emit(event)
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

// parseStatFile parses /proc/[pid]/stat for name, state, ppid, session,
// tty_nr, and starttime.  The comm field is enclosed in parentheses and may
// contain spaces, so we locate the last ')' to split reliably.
//
// /proc/[pid]/stat field layout (after comm):
//
//	[0]  state        [1]  ppid          [2]  pgrp
//	[3]  session      [4]  tty_nr        ...
//	[19] starttime    (field 22 in the kernel's numbering)
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

	// Fields after the closing paren: state(0) ppid(1) pgrp(2) session(3) tty_nr(4) ... starttime(19)
	rest := strings.Fields(content[closeParen+2:])
	if len(rest) < 20 {
		return fmt.Errorf("stat has too few fields (%d): %s", len(rest), path)
	}

	info.State = rest[0]

	if ppid, err := strconv.Atoi(rest[1]); err == nil {
		info.PPID = ppid
	}
	// rest[3] = session (process group session leader PID)
	if sid, err := strconv.Atoi(rest[3]); err == nil {
		info.SessionID = sid
	}
	// rest[4] = tty_nr (controlling terminal, encoded as major/minor device)
	if tty, err := strconv.Atoi(rest[4]); err == nil {
		info.TTY = tty
	}
	// rest[11] = utime, rest[12] = stime (cumulative CPU ticks)
	if ut, err := strconv.ParseUint(rest[11], 10, 64); err == nil {
		info.UTime = ut
	}
	if st, err := strconv.ParseUint(rest[12], 10, 64); err == nil {
		info.STime = st
	}

	// rest[19] is field 22 (starttime — clock ticks since boot)
	if st, err := strconv.ParseUint(rest[19], 10, 64); err == nil {
		info.StartTime = st
	}

	return nil
}

// parseStatusFile reads /proc/[pid]/status for UID, GID, effective UID/GID,
// thread count, resident/virtual memory sizes, and Linux capability bitmask.
// Errors are silently ignored — the data is optional enrichment.
//
// Relevant status fields:
//
//	Uid:     ruid  euid  ssuid  fsuid
//	Gid:     rgid  egid  sgid   fsgid
//	Threads: N
//	VmRSS:   N kB   ← resident set size
//	VmSize:  N kB   ← virtual memory size
//	CapEff:  <hex>  ← effective capability bitmask
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
			if len(fields) >= 3 {
				info.EUID, _ = strconv.Atoi(fields[2])
			}
		case strings.HasPrefix(line, "Gid:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.GID, _ = strconv.Atoi(fields[1])
			}
			if len(fields) >= 3 {
				info.EGID, _ = strconv.Atoi(fields[2])
			}
		case strings.HasPrefix(line, "Threads:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.Threads, _ = strconv.Atoi(fields[1])
			}
		case strings.HasPrefix(line, "VmRSS:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				info.MemRSSBytes = kb * 1024
			}
		case strings.HasPrefix(line, "VmSize:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				info.MemVMSBytes = kb * 1024
			}
		case strings.HasPrefix(line, "CapEff:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.CapEff = fields[1]
			}
		}
	}
}

// readSysTotalCPU reads the first "cpu" line of /proc/stat and returns the
// sum of all CPU tick fields (user+nice+system+idle+iowait+irq+softirq+steal).
// Returns 0 on any error.
func readSysTotalCPU(procRoot string) uint64 {
	f, err := os.Open(filepath.Join(procRoot, "stat"))
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 2 || fields[0] != "cpu" {
		return 0
	}
	var total uint64
	for _, field := range fields[1:] {
		v, _ := strconv.ParseUint(field, 10, 64)
		total += v
	}
	return total
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
