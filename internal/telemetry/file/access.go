//go:build linux

// Package file — access.go
//
// FileAccessCollector monitors a configurable set of sensitive files and
// directories for read-access events using the Linux inotify IN_ACCESS and
// IN_OPEN flags.
//
// This enables detection of credential harvesting — e.g. an attacker reading
// /etc/shadow, /etc/gshadow, or SSH host keys — without requiring eBPF or
// auditd (MITRE T1003.008, T1552.004).
//
// ECS fields emitted:
//   - file.path, file.name, file.directory — the accessed file
//   - file.event.action: "access"          — ECS action value
//   - event.action: "file-accessed"        — top-level action
//   - event.category: "file"
//   - event.kind: "event"
//   - threat.technique.id: ["T1003.008","T1552.004"]
package file

import (
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

// defaultSensitiveAccessPaths are the paths monitored by default for
// read-access events.  These are the most common credential-harvesting targets.
var defaultSensitiveAccessPaths = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/security/opasswd",
	"/root/.ssh",
	"/etc/ssh",
}

// FileAccessCollector watches sensitive files and directories for read-access
// events via inotify IN_ACCESS | IN_OPEN.  It implements capability.Capability.
type FileAccessCollector struct {
	pipeline     *events.Pipeline
	agentID      string
	hostname     string
	watchPaths   []string
	inotifyFd    int
	inotifyMu    sync.Mutex
	wdToPath     map[int32]string
	mu           sync.Mutex
	health       capability.HealthStatus
	cancel       context.CancelFunc
}

// NewFileAccessCollector creates a FileAccessCollector.
// Pass nil for watchPaths to use the default sensitive path list.
func NewFileAccessCollector(
	pipeline *events.Pipeline,
	agentID, hostname string,
	watchPaths []string,
) *FileAccessCollector {
	if len(watchPaths) == 0 {
		watchPaths = defaultSensitiveAccessPaths
	}
	return &FileAccessCollector{
		pipeline:   pipeline,
		agentID:    agentID,
		hostname:   hostname,
		watchPaths: watchPaths,
		inotifyFd:  -1,
		wdToPath:   make(map[int32]string),
		health:     capability.HealthStopped,
	}
}

// ── capability.Capability interface ──────────────────────────────────────────

func (a *FileAccessCollector) Name() string { return "telemetry.file.access" }

func (a *FileAccessCollector) Init(_ capability.Dependencies) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.health = capability.HealthStarting
	return nil
}

func (a *FileAccessCollector) Start(ctx context.Context) error {
	if err := a.setupInotify(); err != nil {
		log.Printf("file.access: inotify setup failed: %v — access monitoring disabled", err)
		a.mu.Lock()
		a.health = capability.HealthDegraded
		a.mu.Unlock()
		// Return nil so the agent continues without access monitoring.
		return nil
	}

	childCtx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancel = cancel
	a.health = capability.HealthRunning
	a.mu.Unlock()

	go a.loop(childCtx)
	return nil
}

func (a *FileAccessCollector) Stop() error {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Unlock()

	a.inotifyMu.Lock()
	if a.inotifyFd >= 0 {
		_ = syscall.Close(a.inotifyFd)
		a.inotifyFd = -1
	}
	a.inotifyMu.Unlock()

	a.mu.Lock()
	a.health = capability.HealthStopped
	a.mu.Unlock()
	return nil
}

func (a *FileAccessCollector) Health() capability.HealthStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.health
}

// ── inotify setup ─────────────────────────────────────────────────────────────

func (a *FileAccessCollector) setupInotify() error {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}

	a.inotifyMu.Lock()
	a.inotifyFd = fd
	a.inotifyMu.Unlock()

	// IN_ACCESS fires on every read(); IN_OPEN on every open().
	// We use IN_ACCESS | IN_OPEN for files and IN_ACCESS | IN_OPEN for dirs
	// (directory-level access means a file within was opened).
	const mask = uint32(syscall.IN_ACCESS | syscall.IN_OPEN)

	for _, p := range a.watchPaths {
		info, err := os.Lstat(p)
		if os.IsNotExist(err) {
			continue // Optional path — will be watched if it appears later
		}
		if err != nil {
			log.Printf("file.access: stat %s: %v", p, err)
			continue
		}

		watchMask := mask
		if info.IsDir() {
			// For directories, watch only direct children (non-recursive).
			// Recursive access monitoring would be too noisy.
			watchMask |= syscall.IN_ONLYDIR
		}

		wd, wErr := syscall.InotifyAddWatch(fd, p, watchMask)
		if wErr != nil {
			log.Printf("file.access: inotify_add_watch %s: %v", p, wErr)
			continue
		}

		a.inotifyMu.Lock()
		a.wdToPath[int32(wd)] = p
		a.inotifyMu.Unlock()

		log.Printf("file.access: watching %s", p)
	}

	return nil
}

// ── event loop ────────────────────────────────────────────────────────────────

const accessBufSize = 65536

func (a *FileAccessCollector) loop(ctx context.Context) {
	buf := make([]byte, accessBufSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		a.inotifyMu.Lock()
		fd := a.inotifyFd
		a.inotifyMu.Unlock()

		if fd < 0 {
			return
		}

		n, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		if n == 0 {
			continue
		}

		a.parseAccessEvents(ctx, buf[:n])
	}
}

// parseAccessEvents processes a raw inotify buffer.
func (a *FileAccessCollector) parseAccessEvents(ctx context.Context, buf []byte) {
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
			name = strings.TrimRight(
				string(buf[offset+hdrSize:offset+totalLen]), "\x00",
			)
		}

		if ctx.Err() == nil {
			a.handleAccessEvent(hdr.Wd, hdr.Mask, name)
		}
		offset += totalLen
	}
}

// handleAccessEvent dispatches a decoded inotify event to the appropriate handler.
func (a *FileAccessCollector) handleAccessEvent(wd int32, mask uint32, name string) {
	a.inotifyMu.Lock()
	watchedPath, ok := a.wdToPath[wd]
	a.inotifyMu.Unlock()

	if !ok {
		return
	}

	// Ignore access events for the directory itself (triggered when the
	// directory is listed, not when a file inside is accessed).
	if mask&syscall.IN_ISDIR != 0 {
		return
	}

	var fullPath string
	if name != "" {
		fullPath = filepath.Join(watchedPath, name)
	} else {
		fullPath = watchedPath
	}

	a.emitAccessEvent(fullPath)
}

// emitAccessEvent emits an ECS-compatible file access event.
func (a *FileAccessCollector) emitAccessEvent(path string) {
	filePayload := map[string]interface{}{
		"path":      path,
		"name":      filepath.Base(path),
		"directory": filepath.Dir(path),
		"event": map[string]interface{}{
			"action": "access",
		},
	}

	ev := events.Event{
		ID:        fmt.Sprintf("faccess-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "file.access",
		Category:  "file",
		Kind:      "event",
		Severity:  events.SeverityHigh,
		Module:    "telemetry.file.access",
		AgentID:   a.agentID,
		Hostname:  a.hostname,
		Payload: map[string]interface{}{
			"file": filePayload,
			"event": map[string]interface{}{
				"action": "file-accessed",
			},
			"threat": map[string]interface{}{
				"technique": map[string]interface{}{
					"id": []string{"T1003.008", "T1552.004"},
				},
			},
		},
		Tags: []string{"file", "access", "credential-access", "telemetry"},
	}
	a.pipeline.Emit(ev)
}
