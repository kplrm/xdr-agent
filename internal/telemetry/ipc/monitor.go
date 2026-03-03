//go:build linux

// Package ipc monitors Inter-Process Communication (IPC) channels:
// Unix domain sockets and named pipes (FIFOs).
//
// Two collection mechanisms run concurrently:
//  1. /proc/net/unix polling -- detect new Unix domain socket paths by diffing
//     the kernel's socket table at a configurable interval (default 15 s).
//  2. inotify IN_CREATE on common IPC directories -- detect named pipe (FIFO)
//     creation in /tmp, /run, /var/run, and /tmp/.X11-unix.
//
// MITRE ATT&CK: T1559 (Inter-Process Communication)
//
// ECS fields emitted:
//   - network.unix_socket.path  -- Unix domain socket path
//   - process.io.pipe_name      -- named pipe path
//   - event.action              -- "unix_socket.created" or "named_pipe.created"
//   - event.category            -- "network" (sockets) or "file" (pipes)
package ipc

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
	defaultIPCScanInterval = 15 * time.Second
	ipcInotifyBufSize      = 65536
)

// defaultIPCWatchDirs are directories monitored via inotify for FIFO creation.
var defaultIPCWatchDirs = []string{
	"/tmp",
	"/run",
	"/var/run",
	"/tmp/.X11-unix",
}

// IPCCollector monitors Unix domain sockets and named pipes.
// It implements capability.Capability.
type IPCCollector struct {
	pipeline  *events.Pipeline
	agentID   string
	hostname  string
	interval  time.Duration
	watchDirs []string

	knownSockets map[string]struct{}

	inotifyFd int
	inotifyMu sync.Mutex
	wdToDir   map[int32]string

	mu     sync.Mutex
	health capability.HealthStatus
	cancel context.CancelFunc
}

// NewIPCCollector creates a new IPC telemetry collector.
// Pass nil watchDirs to use the defaults; pass 0 interval for the 15 s default.
func NewIPCCollector(
	pipeline *events.Pipeline,
	agentID, hostname string,
	watchDirs []string,
	interval time.Duration,
) *IPCCollector {
	if interval <= 0 {
		interval = defaultIPCScanInterval
	}
	if len(watchDirs) == 0 {
		watchDirs = defaultIPCWatchDirs
	}
	return &IPCCollector{
		pipeline:     pipeline,
		agentID:      agentID,
		hostname:     hostname,
		interval:     interval,
		watchDirs:    watchDirs,
		knownSockets: make(map[string]struct{}),
		inotifyFd:    -1,
		wdToDir:      make(map[int32]string),
		health:       capability.HealthStopped,
	}
}

// capability.Capability interface

func (c *IPCCollector) Name() string { return "telemetry.ipc" }

func (c *IPCCollector) Init(_ capability.Dependencies) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing := readUnixSockets()
	for _, p := range existing {
		c.knownSockets[p] = struct{}{}
	}
	c.health = capability.HealthStarting
	return nil
}

func (c *IPCCollector) Start(ctx context.Context) error {
	if err := c.setupInotify(); err != nil {
		log.Printf("ipc: inotify setup failed: %v -- pipe monitoring disabled", err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	c.health = capability.HealthRunning
	c.mu.Unlock()

	go c.socketLoop(childCtx)
	go c.inotifyLoop(childCtx)
	return nil
}

func (c *IPCCollector) Stop() error {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()

	c.inotifyMu.Lock()
	if c.inotifyFd >= 0 {
		_ = syscall.Close(c.inotifyFd)
		c.inotifyFd = -1
	}
	c.inotifyMu.Unlock()

	c.mu.Lock()
	c.health = capability.HealthStopped
	c.mu.Unlock()
	return nil
}

func (c *IPCCollector) Health() capability.HealthStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

// /proc/net/unix polling

func (c *IPCCollector) socketLoop(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.scanSockets()
		}
	}
}

func (c *IPCCollector) scanSockets() {
	current := readUnixSockets()

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, path := range current {
		if _, known := c.knownSockets[path]; !known {
			c.knownSockets[path] = struct{}{}
			c.emitUnixSocketEvent(path)
		}
	}

	currentSet := make(map[string]struct{}, len(current))
	for _, p := range current {
		currentSet[p] = struct{}{}
	}
	for path := range c.knownSockets {
		if _, exists := currentSet[path]; !exists {
			delete(c.knownSockets, path)
		}
	}
}

// readUnixSockets parses /proc/net/unix and returns all named socket paths.
//
// Format (space-separated):
//
//	Num       RefCount Protocol Flags    Type St Inode Path
//	0000...:  00000002 00000000 00010000 0001 01 12345 /run/foo.sock
func readUnixSockets() []string {
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		return nil
	}
	defer f.Close()

	var paths []string
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return nil
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		socketPath := fields[7]
		if socketPath == "" || strings.HasPrefix(socketPath, "@") {
			continue
		}
		paths = append(paths, socketPath)
	}
	return paths
}

func (c *IPCCollector) emitUnixSocketEvent(socketPath string) {
	ev := events.Event{
		ID:        fmt.Sprintf("ipc-sock-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "ipc.unix_socket.created",
		Category:  "network",
		Kind:      "event",
		Severity:  events.SeverityInfo,
		Module:    "telemetry.ipc",
		AgentID:   c.agentID,
		Hostname:  c.hostname,
		Payload: map[string]interface{}{
			"network": map[string]interface{}{
				"unix_socket": map[string]interface{}{
					"path": socketPath,
				},
				"type":      "unix",
				"transport": "unix",
			},
			"event": map[string]interface{}{
				"action":   "unix_socket.created",
				"category": []string{"network"},
				"type":     []string{"connection", "start"},
			},
			"threat": map[string]interface{}{
				"technique": map[string]interface{}{
					"id": []string{"T1559"},
				},
			},
		},
		Tags: []string{"ipc", "unix-socket", "network", "telemetry"},
	}
	c.pipeline.Emit(ev)
}

// inotify for FIFO creation

func (c *IPCCollector) setupInotify() error {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}

	c.inotifyMu.Lock()
	c.inotifyFd = fd
	c.inotifyMu.Unlock()

	for _, dir := range c.watchDirs {
		if _, statErr := os.Lstat(dir); os.IsNotExist(statErr) {
			continue
		}
		wd, wErr := syscall.InotifyAddWatch(fd, dir, syscall.IN_CREATE)
		if wErr != nil {
			log.Printf("ipc: inotify_add_watch %s: %v", dir, wErr)
			continue
		}
		c.inotifyMu.Lock()
		c.wdToDir[int32(wd)] = dir
		c.inotifyMu.Unlock()
	}
	return nil
}

func (c *IPCCollector) inotifyLoop(ctx context.Context) {
	buf := make([]byte, ipcInotifyBufSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.inotifyMu.Lock()
		fd := c.inotifyFd
		c.inotifyMu.Unlock()

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

		c.parseInotifyEvents(ctx, buf[:n])
	}
}

func (c *IPCCollector) parseInotifyEvents(ctx context.Context, buf []byte) {
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

		if ctx.Err() == nil && name != "" {
			c.handleCreate(hdr.Wd, name)
		}
		offset += totalLen
	}
}

func (c *IPCCollector) handleCreate(wd int32, name string) {
	c.inotifyMu.Lock()
	dir, ok := c.wdToDir[wd]
	c.inotifyMu.Unlock()

	if !ok {
		return
	}

	fullPath := filepath.Join(dir, name)

	info, err := os.Lstat(fullPath)
	if err != nil {
		return
	}

	if info.Mode()&os.ModeNamedPipe == 0 {
		return
	}

	c.emitPipeEvent(fullPath)
}

func (c *IPCCollector) emitPipeEvent(pipePath string) {
	ev := events.Event{
		ID:        fmt.Sprintf("ipc-pipe-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "ipc.pipe.created",
		Category:  "file",
		Kind:      "event",
		Severity:  events.SeverityMedium,
		Module:    "telemetry.ipc",
		AgentID:   c.agentID,
		Hostname:  c.hostname,
		Payload: map[string]interface{}{
			"process": map[string]interface{}{
				"io": map[string]interface{}{
					"pipe_name": pipePath,
				},
			},
			"file": map[string]interface{}{
				"path":      pipePath,
				"name":      filepath.Base(pipePath),
				"directory": filepath.Dir(pipePath),
				"type":      "pipe",
			},
			"event": map[string]interface{}{
				"action":   "named_pipe.created",
				"category": []string{"file"},
				"type":     []string{"creation"},
			},
			"threat": map[string]interface{}{
				"technique": map[string]interface{}{
					"id": []string{"T1559"},
				},
			},
		},
		Tags: []string{"ipc", "named-pipe", "file", "telemetry"},
	}
	c.pipeline.Emit(ev)
}
