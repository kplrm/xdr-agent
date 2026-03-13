//go:build linux

// Package tty monitors terminal (TTY/PTY) sessions on the host.
// It polls /proc/[pid]/stat to detect processes attached to a terminal,
// tracking session starts and ends. Full TTY I/O capture is deferred to
// Phase 7 (eBPF via kprobe on tty_write).
//
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter),
//
//	T1059.004 (Unix Shell)
package tty

import (
	"bufio"
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
	defaultTTYInterval = 5 * time.Second
)

// TTYSession holds metadata for a process that owns a terminal.
type TTYSession struct {
	PID        int
	PPID       int
	Name       string
	Executable string
	CmdLine    string
	UID        int
	GID        int
	TTYNr      int    // tty_nr from /proc/[pid]/stat
	TTYName    string // resolved PTY name (e.g. "pts/0")
	SessionID  int    // kernel session id (setsid)
	StartTime  uint64 // in clock ticks
}

// TTYCollector detects processes attached to a terminal by polling /proc.
// It implements capability.Capability.
type TTYCollector struct {
	pipeline *events.Pipeline
	agentID  string
	hostname string
	interval time.Duration

	mu     sync.Mutex
	known  map[int]TTYSession // pid → session
	health capability.HealthStatus
	cancel context.CancelFunc
}

// NewTTYCollector creates a new TTY session telemetry collector.
// Pass 0 for interval to use the 5 s default.
func NewTTYCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *TTYCollector {
	if interval <= 0 {
		interval = defaultTTYInterval
	}
	return &TTYCollector{
		pipeline: pipeline,
		agentID:  agentID,
		hostname: hostname,
		interval: interval,
		known:    make(map[int]TTYSession),
		health:   capability.HealthStopped,
	}
}

// ── capability.Capability ────────────────────────────────────────────────────

func (t *TTYCollector) Name() string { return "telemetry.tty" }

func (t *TTYCollector) Init(_ capability.Dependencies) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.health = capability.HealthStarting
	return nil
}

func (t *TTYCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	t.mu.Lock()
	t.cancel = cancel
	t.health = capability.HealthRunning
	t.mu.Unlock()

	go t.loop(childCtx)
	return nil
}

func (t *TTYCollector) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		t.cancel()
	}
	t.health = capability.HealthStopped
	return nil
}

func (t *TTYCollector) Health() capability.HealthStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.health
}

// ── internal ─────────────────────────────────────────────────────────────────

func (t *TTYCollector) loop(ctx context.Context) {
	// First scan builds baseline without emitting events
	t.scan(ctx, true)

	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.scan(ctx, false)
		}
	}
}

func (t *TTYCollector) scan(ctx context.Context, baseline bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("tty: read /proc: %v", err)
		t.mu.Lock()
		t.health = capability.HealthDegraded
		t.mu.Unlock()
		return
	}

	snapshot := make(map[int]TTYSession)

	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 {
			continue
		}

		sess, scanErr := readTTYSession(pid)
		if scanErr != nil {
			continue
		}
		// Only track processes that own a terminal
		if sess.TTYNr != 0 {
			snapshot[pid] = sess
		}
	}

	t.mu.Lock()
	previous := t.known
	t.known = snapshot
	t.health = capability.HealthRunning
	t.mu.Unlock()

	if baseline {
		log.Printf("tty: baseline — %d processes with terminal", len(snapshot))
		return
	}

	if ctx.Err() != nil {
		return
	}

	// New terminal sessions
	for pid, sess := range snapshot {
		if _, existed := previous[pid]; !existed {
			t.emitEvent("tty.session_start", events.SeverityInfo, sess)
		}
	}

	// Ended terminal sessions
	for pid, sess := range previous {
		if _, exists := snapshot[pid]; !exists {
			t.emitEvent("tty.session_end", events.SeverityInfo, sess)
		}
	}
}

func (t *TTYCollector) emitEvent(eventType string, severity events.Severity, sess TTYSession) {
	processPayload := map[string]interface{}{
		"pid":          sess.PID,
		"ppid":         sess.PPID,
		"name":         sess.Name,
		"executable":   sess.Executable,
		"command_line": sess.CmdLine,
		"session_id":   sess.SessionID,
		"user": map[string]interface{}{
			"id": sess.UID,
		},
		"group": map[string]interface{}{
			"id": sess.GID,
		},
		"tty": map[string]interface{}{
			"nr":   sess.TTYNr,
			"name": sess.TTYName,
		},
	}

	ev := events.Event{
		ID:            fmt.Sprintf("tty-%s-%d-%d", eventType, sess.PID, time.Now().UnixNano()),
		Timestamp:     time.Now().UTC(),
		Type:          eventType,
		Category:      "process",
		Kind:          "event",
		Severity:      severity,
		Module:        "telemetry.tty",
		AgentID:       t.agentID,
		Hostname:      t.hostname,
		MitreTactic:   "Execution",
		MitreTechique: "T1059.004",
		Tags:          []string{"tty", "terminal", "session", "telemetry"},
		Payload: map[string]interface{}{
			"process": processPayload,
		},
	}
	t.pipeline.Emit(ev)
}

// ── /proc parsers ─────────────────────────────────────────────────────────────

// readTTYSession reads /proc/[pid]/stat and enriches with comm/exe/cmdline.
func readTTYSession(pid int) (TTYSession, error) {
	procDir := fmt.Sprintf("/proc/%d", pid)

	statBytes, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err != nil {
		return TTYSession{}, err
	}

	sess := TTYSession{PID: pid}

	// /proc/[pid]/stat format:
	// pid (comm) state ppid pgrp session tty_nr ...
	// The comm field may contain spaces and parentheses — find last ')' to split.
	statStr := string(statBytes)
	rp := strings.LastIndex(statStr, ")")
	if rp < 0 {
		return TTYSession{}, fmt.Errorf("malformed stat for pid %d", pid)
	}

	// Extract comm (between first '(' and last ')')
	lp := strings.Index(statStr, "(")
	if lp >= 0 && rp > lp {
		sess.Name = statStr[lp+1 : rp]
	}

	// Fields after the closing ')':
	rest := strings.TrimSpace(statStr[rp+1:])
	fields := strings.Fields(rest)
	// fields[0] = state, [1] = ppid, [2] = pgrp, [3] = session, [4] = tty_nr
	if len(fields) < 5 {
		return TTYSession{}, fmt.Errorf("too few stat fields for pid %d", pid)
	}

	if v, e := strconv.Atoi(fields[1]); e == nil {
		sess.PPID = v
	}
	if v, e := strconv.Atoi(fields[3]); e == nil {
		sess.SessionID = v
	}
	if v, e := strconv.Atoi(fields[4]); e == nil {
		sess.TTYNr = v
	}
	if len(fields) > 19 {
		if v, e := strconv.ParseUint(fields[19], 10, 64); e == nil {
			sess.StartTime = v
		}
	}

	// Resolve TTY name from tty_nr (major/minor device numbers).
	if sess.TTYNr != 0 {
		major := (sess.TTYNr >> 8) & 0xff
		minor := sess.TTYNr & 0xff
		if major == 136 { // PTY slave (pts/N)
			sess.TTYName = fmt.Sprintf("pts/%d", minor)
		} else {
			sess.TTYName = fmt.Sprintf("tty%d", minor)
		}
	}

	// Enrich with exe, cmdline, uid/gid
	if exePath, exeErr := os.Readlink(filepath.Join(procDir, "exe")); exeErr == nil {
		sess.Executable = exePath
	}

	if cmdBytes, cmdErr := os.ReadFile(filepath.Join(procDir, "cmdline")); cmdErr == nil {
		cmdStr := strings.ReplaceAll(string(cmdBytes), "\x00", " ")
		sess.CmdLine = strings.TrimSpace(cmdStr)
	}

	// Read UID/GID from /proc/[pid]/status
	if f, statusErr := os.Open(filepath.Join(procDir, "status")); statusErr == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Uid:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					sess.UID, _ = strconv.Atoi(parts[1])
				}
			} else if strings.HasPrefix(line, "Gid:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					sess.GID, _ = strconv.Atoi(parts[1])
				}
			}
		}
		_ = f.Close()
	}

	return sess, nil
}
