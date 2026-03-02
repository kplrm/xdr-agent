//go:build linux

// Package scheduled monitors scheduled task changes: cron jobs, systemd timers, and at jobs.
// It watches key crontab and systemd timer directories with inotify and performs a
// periodic full rescan to catch changes that may have been missed.
//
// MITRE ATT&CK: T1053.003 (Scheduled Task/Job: Cron),
//
//	T1053.006 (Scheduled Task/Job: Systemd Timers)
package scheduled

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

const (
	defaultRescanInterval   = 5 * time.Minute
	inotifyScheduledBufSize = 65536
)

// cronWatchPaths are directories / files monitored for crontab changes.
var cronWatchPaths = []string{
	"/etc/crontab",
	"/etc/anacrontab",
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/etc/cron.hourly",
	"/var/spool/cron/crontabs",
}

// timerWatchPaths are directories monitored for systemd .timer unit changes.
var timerWatchPaths = []string{
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
	"/run/systemd/generator",
	"/run/systemd/generator.late",
}

// taskRecord holds a snapshot of a cron entry or systemd timer for diffing.
type taskRecord struct {
	Path    string
	ModTime int64
	Content string // full file content for comparison
}

// ScheduledTaskCollector monitors cron and systemd timer files.
// It implements capability.Capability.
type ScheduledTaskCollector struct {
	pipeline *events.Pipeline
	agentID  string
	hostname string
	interval time.Duration // rescan interval

	inotifyFd int
	inotifyMu sync.Mutex
	wdToPath  map[int32]string

	mu     sync.Mutex
	known  map[string]taskRecord // path → snapshot
	health capability.HealthStatus
	cancel context.CancelFunc
}

// NewScheduledTaskCollector creates a new scheduled task telemetry collector.
// Pass 0 for interval to use the 5 min default.
func NewScheduledTaskCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *ScheduledTaskCollector {
	if interval <= 0 {
		interval = defaultRescanInterval
	}
	return &ScheduledTaskCollector{
		pipeline:  pipeline,
		agentID:   agentID,
		hostname:  hostname,
		interval:  interval,
		inotifyFd: -1,
		wdToPath:  make(map[int32]string),
		known:     make(map[string]taskRecord),
		health:    capability.HealthStopped,
	}
}

// ── capability.Capability ────────────────────────────────────────────────────

func (s *ScheduledTaskCollector) Name() string { return "telemetry.scheduled" }

func (s *ScheduledTaskCollector) Init(_ capability.Dependencies) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health = capability.HealthStarting
	return nil
}

func (s *ScheduledTaskCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.health = capability.HealthRunning
	s.mu.Unlock()

	if err := s.setupInotify(); err != nil {
		log.Printf("scheduled: inotify unavailable (%v) — rescan only", err)
	} else {
		go s.inotifyLoop(childCtx)
	}

	go s.rescanLoop(childCtx)
	return nil
}

func (s *ScheduledTaskCollector) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	s.inotifyMu.Lock()
	if s.inotifyFd >= 0 {
		_ = syscall.Close(s.inotifyFd)
		s.inotifyFd = -1
	}
	s.inotifyMu.Unlock()

	s.health = capability.HealthStopped
	return nil
}

func (s *ScheduledTaskCollector) Health() capability.HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.health
}

// ── inotify setup ────────────────────────────────────────────────────────────

func (s *ScheduledTaskCollector) setupInotify() error {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}

	s.inotifyMu.Lock()
	s.inotifyFd = fd
	s.inotifyMu.Unlock()

	mask := uint32(syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_CREATE | syscall.IN_DELETE)

	watchAll := append(cronWatchPaths, timerWatchPaths...)
	for _, p := range watchAll {
		if _, statErr := os.Stat(p); os.IsNotExist(statErr) {
			continue
		}
		wd, addErr := syscall.InotifyAddWatch(fd, p, mask)
		if addErr != nil {
			log.Printf("scheduled: inotify_add_watch %s: %v", p, addErr)
			continue
		}
		s.inotifyMu.Lock()
		s.wdToPath[int32(wd)] = p
		s.inotifyMu.Unlock()
	}
	return nil
}

// ── inotify loop ─────────────────────────────────────────────────────────────

func (s *ScheduledTaskCollector) inotifyLoop(ctx context.Context) {
	buf := make([]byte, inotifyScheduledBufSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.inotifyMu.Lock()
		fd := s.inotifyFd
		s.inotifyMu.Unlock()

		if fd < 0 {
			return
		}

		n, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return
		}
		if n == 0 {
			continue
		}

		s.parseInotifyEvents(ctx, buf[:n])
	}
}

func (s *ScheduledTaskCollector) parseInotifyEvents(ctx context.Context, buf []byte) {
	const hdrSize = syscall.SizeofInotifyEvent

	for offset := 0; offset+hdrSize <= len(buf); {
		//nolint:gosec
		hdr := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))

		nameLen := int(hdr.Len)
		totalLen := hdrSize + nameLen
		if offset+totalLen > len(buf) {
			break
		}

		var name string
		if nameLen > 0 {
			name = strings.TrimRight(string(buf[offset+hdrSize:offset+totalLen]), "\x00")
		}

		if ctx.Err() == nil {
			s.inotifyMu.Lock()
			watchedPath, ok := s.wdToPath[hdr.Wd]
			s.inotifyMu.Unlock()

			if ok {
				var fullPath string
				if name != "" {
					fullPath = filepath.Join(watchedPath, name)
				} else {
					fullPath = watchedPath
				}
				isDelete := hdr.Mask&syscall.IN_DELETE != 0
				s.handleFileEvent(ctx, fullPath, isDelete)
			}
		}

		offset += totalLen
	}
}

func (s *ScheduledTaskCollector) handleFileEvent(ctx context.Context, path string, deleted bool) {
	if ctx.Err() != nil {
		return
	}

	if deleted {
		s.mu.Lock()
		old, exists := s.known[path]
		delete(s.known, path)
		s.mu.Unlock()
		if exists {
			s.emitEvent("scheduled.task_deleted", events.SeverityHigh, path, old.Content, "", detectTaskType(path))
		}
		return
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	newContent := string(content)

	info, statErr := os.Stat(path)
	modTime := int64(0)
	if statErr == nil {
		modTime = info.ModTime().Unix()
	}

	s.mu.Lock()
	old, existed := s.known[path]
	s.known[path] = taskRecord{Path: path, ModTime: modTime, Content: newContent}
	s.mu.Unlock()

	taskType := detectTaskType(path)

	if !existed {
		s.emitEvent("scheduled.task_created", events.SeverityHigh, path, newContent, "", taskType)
	} else if old.Content != newContent {
		s.emitEvent("scheduled.task_modified", events.SeverityHigh, path, newContent, old.Content, taskType)
	}
}

// ── rescan loop ───────────────────────────────────────────────────────────────

func (s *ScheduledTaskCollector) rescanLoop(ctx context.Context) {
	// Baseline scan — no events emitted
	s.runScan(ctx, true)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runScan(ctx, false)
		}
	}
}

func (s *ScheduledTaskCollector) runScan(ctx context.Context, baseline bool) {
	allPaths := append(cronWatchPaths, timerWatchPaths...)
	seen := make(map[string]struct{})

	for _, root := range allPaths {
		if ctx.Err() != nil {
			return
		}

		info, err := os.Stat(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue
		}

		if info.IsDir() {
			entries, readErr := os.ReadDir(root)
			if readErr != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
					continue
				}
				// For timer paths, only care about .timer files
				p := filepath.Join(root, entry.Name())
				if isTimerPath(root) && !strings.HasSuffix(entry.Name(), ".timer") {
					continue
				}
				seen[p] = struct{}{}
				if !baseline {
					s.checkFile(ctx, p)
				} else {
					s.baselineFile(p)
				}
			}
		} else {
			seen[root] = struct{}{}
			if !baseline {
				s.checkFile(ctx, root)
			} else {
				s.baselineFile(root)
			}
		}
	}

	if !baseline {
		// Detect deleted files
		s.mu.Lock()
		var deleted []string
		for p := range s.known {
			if _, wasSeen := seen[p]; !wasSeen {
				deleted = append(deleted, p)
			}
		}
		for _, p := range deleted {
			old := s.known[p]
			delete(s.known, p)
			s.mu.Unlock()
			s.emitEvent("scheduled.task_deleted", events.SeverityHigh, p, old.Content, "", detectTaskType(p))
			s.mu.Lock()
		}
		s.mu.Unlock()
	}

	if baseline {
		s.mu.Lock()
		log.Printf("scheduled: baseline — %d task files recorded", len(s.known))
		s.mu.Unlock()
	}
}

func (s *ScheduledTaskCollector) baselineFile(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	info, statErr := os.Stat(path)
	modTime := int64(0)
	if statErr == nil {
		modTime = info.ModTime().Unix()
	}
	s.mu.Lock()
	s.known[path] = taskRecord{Path: path, ModTime: modTime, Content: string(content)}
	s.mu.Unlock()
}

func (s *ScheduledTaskCollector) checkFile(ctx context.Context, path string) {
	if ctx.Err() != nil {
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	newContent := string(content)
	info, statErr := os.Stat(path)
	modTime := int64(0)
	if statErr == nil {
		modTime = info.ModTime().Unix()
	}

	s.mu.Lock()
	old, existed := s.known[path]
	s.known[path] = taskRecord{Path: path, ModTime: modTime, Content: newContent}
	s.mu.Unlock()

	taskType := detectTaskType(path)

	if !existed {
		s.emitEvent("scheduled.task_created", events.SeverityHigh, path, newContent, "", taskType)
	} else if old.Content != newContent {
		s.emitEvent("scheduled.task_modified", events.SeverityHigh, path, newContent, old.Content, taskType)
	}
}

// ── emit ──────────────────────────────────────────────────────────────────────

func (s *ScheduledTaskCollector) emitEvent(
	action string,
	severity events.Severity,
	path string,
	content string,
	previousContent string,
	taskType string,
) {
	entries := []map[string]interface{}{}
	if taskType == "cron" || taskType == "crontab" || taskType == "user-crontab" {
		entries = parseCronEntries(content, path)
	} else if taskType == "systemd-timer" {
		entries = parseTimerUnit(content, path)
	}

	xdrPayload := map[string]interface{}{
		"scheduled_task": map[string]interface{}{
			"path":             path,
			"type":             taskType,
			"entries":          entries,
			"raw_content":      truncate(content, 4096),
			"previous_content": truncate(previousContent, 4096),
		},
	}

	mitreTechnique := "T1053.003"
	if taskType == "systemd-timer" {
		mitreTechnique = "T1053.006"
	}

	ev := events.Event{
		ID:            fmt.Sprintf("sched-%s-%d", action, time.Now().UnixNano()),
		Timestamp:     time.Now().UTC(),
		Type:          action,
		Category:      "configuration",
		Kind:          "event",
		Severity:      severity,
		Module:        "telemetry.scheduled",
		AgentID:       s.agentID,
		Hostname:      s.hostname,
		MitreTactic:   "Persistence",
		MitreTechique: mitreTechnique,
		Tags:          []string{"scheduled", "cron", "persistence", "telemetry"},
		Payload: map[string]interface{}{
			"file": map[string]interface{}{
				"path": path,
				"name": filepath.Base(path),
			},
			"xdr": xdrPayload,
		},
	}
	s.pipeline.Emit(ev)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// detectTaskType returns a label for the type of scheduled task file.
func detectTaskType(path string) string {
	base := filepath.Base(path)
	switch {
	case strings.HasSuffix(base, ".timer"):
		return "systemd-timer"
	case strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".target"):
		return "systemd-unit"
	case base == "crontab" || base == "anacrontab":
		return "crontab"
	case strings.HasPrefix(path, "/var/spool/cron"):
		return "user-crontab"
	default:
		return "cron"
	}
}

// isTimerPath returns true if the root directory is a systemd timer path.
func isTimerPath(dir string) bool {
	for _, p := range timerWatchPaths {
		if dir == p {
			return true
		}
	}
	return false
}

// parseCronEntries extracts schedule entries from crontab file content.
func parseCronEntries(content, path string) []map[string]interface{} {
	var entries []map[string]interface{}

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip variable assignments (KEY=value without spaces in key)
		if eqIdx := strings.Index(line, "="); eqIdx > 0 && !strings.Contains(line[:eqIdx], " ") {
			continue
		}

		entry := map[string]interface{}{
			"line":   lineNum,
			"raw":    line,
			"source": path,
		}

		fields := strings.Fields(line)
		if strings.HasPrefix(line, "@") {
			// Special schedule: @reboot, @hourly, etc.
			if len(fields) >= 2 {
				entry["schedule"] = fields[0]
				entry["command"] = strings.Join(fields[1:], " ")
			}
		} else if len(fields) >= 6 {
			entry["schedule"] = strings.Join(fields[:5], " ")
			// /etc/crontab includes a username field before the command
			if len(fields) >= 7 && !strings.Contains(fields[5], "/") {
				entry["user"] = fields[5]
				entry["command"] = strings.Join(fields[6:], " ")
			} else {
				entry["command"] = strings.Join(fields[5:], " ")
			}
		}

		entries = append(entries, entry)
	}

	return entries
}

// parseTimerUnit extracts scheduling keys from a systemd .timer unit file.
func parseTimerUnit(content, path string) []map[string]interface{} {
	entry := map[string]interface{}{
		"source": path,
		"name":   strings.TrimSuffix(filepath.Base(path), ".timer"),
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "OnCalendar", "OnUnitActiveSec", "OnBootSec", "OnActiveSec",
			"OnStartupSec", "OnUnitInactiveSec", "Unit", "Description", "Persistent":
			entry[strings.ToLower(key)] = val
		}
	}

	return []map[string]interface{}{entry}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}
