//go:build linux

// Package library monitors shared library loading events on the host.
// It watches key library directories for new or modified .so files (potential
// LD_PRELOAD / library-hijacking attacks) and periodically diffs /proc/[pid]/maps
// to detect libraries loaded into running processes.
//
// MITRE ATT&CK: T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking),
//               T1055.001 (Process Injection: Dynamic-link Library Injection)
package library

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	defaultSOScanInterval = 15 * time.Second
	inotifySOBufSize      = 65536
	soMaxHashSize         = 256 << 20 // 256 MiB
)

// defaultSOWatchPaths are standard Linux shared library directories plus
// suspicious staging areas (attacker-favoured LD_PRELOAD locations).
var defaultSOWatchPaths = []string{
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	"/usr/local/lib",
	"/usr/local/lib64",
	"/tmp",     // LD_PRELOAD from /tmp is a red flag
	"/dev/shm", // memfd-based injection often stages here
}

// SOCollector monitors shared-library directories for new / modified .so files
// and scans /proc/[pid]/maps for LD_PRELOAD-loaded libraries.
// It implements capability.Capability.
type SOCollector struct {
	pipeline  *events.Pipeline
	agentID   string
	hostname  string
	watchDirs []string
	interval  time.Duration

	inotifyFd int
	inotifyMu sync.Mutex
	wdToDir   map[int32]string

	// /proc/[pid]/maps tracking: pid → set of so paths
	mu         sync.Mutex
	knownMaps  map[int]map[string]struct{}
	health     capability.HealthStatus
	cancel     context.CancelFunc
}

// NewSOCollector creates a new shared-library telemetry collector.
// Pass nil for watchDirs to use defaults; pass 0 for interval to use the 15 s default.
func NewSOCollector(pipeline *events.Pipeline, agentID, hostname string, watchDirs []string, interval time.Duration) *SOCollector {
	if len(watchDirs) == 0 {
		watchDirs = defaultSOWatchPaths
	}
	if interval <= 0 {
		interval = defaultSOScanInterval
	}
	return &SOCollector{
		pipeline:  pipeline,
		agentID:   agentID,
		hostname:  hostname,
		watchDirs: watchDirs,
		interval:  interval,
		inotifyFd: -1,
		wdToDir:   make(map[int32]string),
		knownMaps: make(map[int]map[string]struct{}),
		health:    capability.HealthStopped,
	}
}

// ── capability.Capability ────────────────────────────────────────────────────

func (s *SOCollector) Name() string { return "telemetry.library" }

func (s *SOCollector) Init(_ capability.Dependencies) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health = capability.HealthStarting
	return nil
}

func (s *SOCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.health = capability.HealthRunning
	s.mu.Unlock()

	if err := s.setupInotify(); err != nil {
		log.Printf("library: inotify unavailable (%v) — maps-scan only", err)
	} else {
		go s.inotifyLoop(childCtx)
	}

	go s.mapsLoop(childCtx)
	return nil
}

func (s *SOCollector) Stop() error {
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

func (s *SOCollector) Health() capability.HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.health
}

// ── inotify ──────────────────────────────────────────────────────────────────

func (s *SOCollector) setupInotify() error {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}

	s.inotifyMu.Lock()
	s.inotifyFd = fd
	s.inotifyMu.Unlock()

	for _, dir := range s.watchDirs {
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			continue
		}
		mask := uint32(syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_CREATE)
		wd, addErr := syscall.InotifyAddWatch(fd, dir, mask)
		if addErr != nil {
			log.Printf("library: inotify_add_watch %s: %v", dir, addErr)
			continue
		}
		s.inotifyMu.Lock()
		s.wdToDir[int32(wd)] = dir
		s.inotifyMu.Unlock()
	}
	return nil
}

func (s *SOCollector) inotifyLoop(ctx context.Context) {
	buf := make([]byte, inotifySOBufSize)

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

func (s *SOCollector) parseInotifyEvents(ctx context.Context, buf []byte) {
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

		if ctx.Err() == nil && name != "" {
			s.inotifyMu.Lock()
			dir, ok := s.wdToDir[hdr.Wd]
			s.inotifyMu.Unlock()

			if ok {
				path := filepath.Join(dir, name)
				// Only care about shared library files and suspicious staging
				if isSOFile(path) || isSuspiciousStagingPath(dir) {
					s.handleSOEvent(path)
				}
			}
		}

		offset += totalLen
	}
}

func (s *SOCollector) handleSOEvent(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return // File may have been transient
	}

	var sha256sum string
	if info.Size() > 0 && info.Size() <= int64(soMaxHashSize) {
		if h, hErr := hashFile(path); hErr == nil {
			sha256sum = h
		}
	}

	severity := events.SeverityMedium
	if isSuspiciousStagingPath(filepath.Dir(path)) {
		severity = events.SeverityHigh
	}

	s.emit("library.loaded", severity, path, sha256sum, info.Size(), 0, "", "")
}

// ── /proc maps polling ────────────────────────────────────────────────────────

func (s *SOCollector) mapsLoop(ctx context.Context) {
	// Initial baseline: record known maps without emitting events.
	s.scanMaps(ctx, true)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scanMaps(ctx, false)
		}
	}
}

// scanMaps reads /proc/[pid]/maps for every visible process and emits events
// for any shared-library paths that were not present in the previous scan.
// On baseline (first pass) it silently records the known state.
func (s *SOCollector) scanMaps(ctx context.Context, baseline bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		pid := parsePID(entry.Name())
		if pid == 0 {
			continue
		}

		current := s.readProcMaps(pid)
		if current == nil {
			continue
		}

		s.mu.Lock()
		previous := s.knownMaps[pid]
		s.knownMaps[pid] = current
		s.mu.Unlock()

		if baseline {
			continue
		}

		// Emit events for newly loaded libraries since the last scan.
		for soPath := range current {
			if _, known := previous[soPath]; !known {
				// Only emit for suspicious paths (LD_PRELOAD from non-standard locations)
				// to avoid flooding; standard /lib/* are handled by inotify on write.
				if isSuspiciousStagingPath(filepath.Dir(soPath)) || isNonStandardSOPath(soPath) {
					s.emitMapsEvent(pid, soPath)
				}
			}
		}
	}

	// Clean up pids that no longer exist.
	s.mu.Lock()
	for pid := range s.knownMaps {
		if _, statErr := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(statErr) {
			delete(s.knownMaps, pid)
		}
	}
	s.mu.Unlock()
}

// readProcMaps parses /proc/[pid]/maps and returns a set of .so paths.
func (s *SOCollector) readProcMaps(pid int) map[string]struct{} {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// /proc/[pid]/maps fields: addr perms offset dev inode pathname
		// We only care about lines with a pathname that contains .so
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[5]
		if isSOFile(path) || strings.Contains(path, "memfd:") {
			seen[path] = struct{}{}
		}
	}
	return seen
}

func (s *SOCollector) emitMapsEvent(pid int, soPath string) {
	// Try to read process name from /proc/[pid]/comm
	commBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	processName := strings.TrimSpace(string(commBytes))

	var sha256sum string
	info, err := os.Stat(soPath)
	if err == nil && info.Size() > 0 && info.Size() <= int64(soMaxHashSize) {
		if h, hErr := hashFile(soPath); hErr == nil {
			sha256sum = h
		}
	}

	size := int64(0)
	if err == nil {
		size = info.Size()
	}

	s.emit("library.loaded_into_process", events.SeverityHigh, soPath, sha256sum, size, pid, processName, "")
}

// ── emit ──────────────────────────────────────────────────────────────────────

func (s *SOCollector) emit(
	action string,
	severity events.Severity,
	path string,
	sha256sum string,
	size int64,
	pid int,
	processName string,
	description string,
) {
	dllPayload := map[string]interface{}{
		"name": filepath.Base(path),
		"path": path,
		"hash": map[string]interface{}{
			"sha256": sha256sum,
		},
		"size": size,
	}

	processPayload := map[string]interface{}{}
	if pid != 0 {
		processPayload["pid"] = pid
		processPayload["name"] = processName
	}

	mitreTechnique := "T1574.006"
	mitreTactic := "Defense Evasion"
	if strings.Contains(path, "memfd:") {
		mitreTechnique = "T1055.001"
		mitreTactic = "Defense Evasion"
	}

	ev := events.Event{
		ID:            fmt.Sprintf("lib-%s-%d", action, time.Now().UnixNano()),
		Timestamp:     time.Now().UTC(),
		Type:          action,
		Category:      "library",
		Kind:          "event",
		Severity:      severity,
		Module:        "telemetry.library",
		AgentID:       s.agentID,
		Hostname:      s.hostname,
		MitreTactic:   mitreTactic,
		MitreTechique: mitreTechnique,
		Tags:          []string{"library", "telemetry", "so-loading"},
		Payload: map[string]interface{}{
			"dll":         dllPayload,
			"process":     processPayload,
			"description": description,
		},
	}
	s.pipeline.Emit(ev)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func isSOFile(path string) bool {
	base := filepath.Base(path)
	return strings.HasSuffix(base, ".so") ||
		strings.Contains(base, ".so.") ||
		strings.HasSuffix(base, ".so.0") // versioned libs
}

func isSuspiciousStagingPath(dir string) bool {
	suspicious := []string{"/tmp", "/dev/shm", "/run", "/var/tmp"}
	for _, p := range suspicious {
		if dir == p || strings.HasPrefix(dir, p+"/") {
			return true
		}
	}
	return false
}

func isNonStandardSOPath(path string) bool {
	standard := []string{
		"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
		"/usr/local/lib/", "/usr/local/lib64/",
		"/usr/share/", "/opt/",
	}
	for _, prefix := range standard {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

func parsePID(name string) int {
	var pid int
	_, err := fmt.Sscanf(name, "%d", &pid)
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

func hashFile(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()

	h := sha256.New()
	if _, err = io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
