// Package linux provides the Linux execution permission boundary.
package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxExecutionDirectoryWatches = 2048
	executionDecisionTimeout     = 500 * time.Millisecond
	executionScanWorkers         = 2
)

var errExecutionWatchLimit = errors.New("execution watch limit reached")

// ExecGuard watches explicit directories. It never marks an entire filesystem.
// scan returns true to deny the pending executable; errors fail open and report
// degraded health. The caller must keep scan bounded by the supplied context.
type ExecGuard struct {
	RecordDecision func(pid int, denied bool, err error)
	fd             int
	paths          []string
	marked         map[string]os.FileInfo
	helpers        []os.FileInfo
	scan           func(context.Context, *os.File, int) (bool, error)
	report         func(error)
	cancel         context.CancelFunc
	ready          chan struct{}
	done           chan struct{}
	watchDone      chan struct{}
}

type execRequest struct {
	fd, pid  int
	deadline time.Time // Starts when the kernel request is read, including queue time.
}

func NewExecGuard(paths, helpers []string, scan func(context.Context, *os.File, int) (bool, error), report func(error)) (*ExecGuard, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify requires Linux 5.1+ and CAP_SYS_ADMIN: %w", err)
	}
	g := &ExecGuard{fd: fd, paths: paths, marked: make(map[string]os.FileInfo), scan: scan, report: report, ready: make(chan struct{}), done: make(chan struct{}), watchDone: make(chan struct{})}
	for _, path := range helpers {
		if info, err := os.Stat(path); err == nil {
			g.helpers = append(g.helpers, info)
		}
	}
	return g, nil
}

// Count first so an oversized configured tree never installs blocking marks.
func preflightExecutionRoots(paths []string, limit int) error {
	seen := make(map[string]struct{})
	for _, root := range paths {
		if !filepath.IsAbs(root) || filepath.Clean(root) == "/" {
			return fmt.Errorf("execution watch must be an explicit absolute directory: %q", root)
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if os.IsNotExist(walkErr) {
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() {
				return nil
			}
			if _, ok := seen[path]; !ok {
				seen[path] = struct{}{}
				if len(seen) > limit {
					return fmt.Errorf("%w (%d directories)", errExecutionWatchLimit, limit)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *ExecGuard) markDirectories() error {
	mark := func(path string) error {
		mask := uint64(unix.FAN_OPEN_EXEC_PERM | unix.FAN_EVENT_ON_CHILD)
		return unix.FanotifyMark(g.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR, mask, unix.AT_FDCWD, path)
	}
	return g.markDirectoriesWith(mark)
}

// An incomplete watch set is unsafe to leave active: every marked launch still blocks.
func (g *ExecGuard) markDirectoriesWith(mark func(string) error) error {
	var firstError error
	initial := len(g.marked) == 0
	for _, root := range g.paths {
		if !filepath.IsAbs(root) || filepath.Clean(root) == "/" {
			return fmt.Errorf("execution watch must be an explicit absolute directory: %q", root)
		}
		if initial {
			log.Printf("execution watch: scanning %s", root)
		}
		added, err := walkExecutionRoot(root, g.marked, mark)
		if initial && added > 0 {
			log.Printf("execution watch: %s added %d directories (%d/%d total)", root, added, len(g.marked), maxExecutionDirectoryWatches)
		}
		if errors.Is(err, errExecutionWatchLimit) || errors.Is(err, unix.ENOSPC) {
			return fmt.Errorf("execution watch setup incomplete; blocking disabled: %w", err)
		}
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	if len(g.marked) == 0 {
		return fmt.Errorf("no execution directories could be watched: %v", firstError)
	}
	if firstError != nil && g.report != nil {
		g.report(firstError)
	}
	return nil
}

// The cap applies across all roots and refreshes; each successful mark persists.
func walkExecutionRoot(root string, marked map[string]os.FileInfo, mark func(string) error) (int, error) {
	added := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		previous, exists := marked[path]
		if exists && sameWatchedDirectory(previous, info) {
			return nil
		}
		if !exists && len(marked) >= maxExecutionDirectoryWatches {
			return fmt.Errorf("%w (%d directories); %s and later directories have no pre-execution blocking", errExecutionWatchLimit, maxExecutionDirectoryWatches, path)
		}
		if err := mark(path); err != nil {
			return fmt.Errorf("mark %s: %w", path, err)
		}
		marked[path] = info
		added++
		return nil
	})
	return added, err
}

func sameWatchedDirectory(previous, current os.FileInfo) bool {
	if previous == nil || !os.SameFile(previous, current) {
		return false
	}
	oldStat, oldOK := previous.Sys().(*syscall.Stat_t)
	newStat, newOK := current.Sys().(*syscall.Stat_t)
	return oldOK && newOK && oldStat.Ctim == newStat.Ctim
}

// Start begins reading permission requests before installing any watches.
// Marking first can block every launch in /usr/bin until a large tree walk ends.
func (g *ExecGuard) Start(ctx context.Context) error {
	if err := preflightExecutionRoots(g.paths, maxExecutionDirectoryWatches); err != nil {
		g.Close()
		return fmt.Errorf("blocking disabled before marks are installed: %w", err)
	}
	ctx, g.cancel = context.WithCancel(ctx)
	go g.run(ctx)
	<-g.ready
	if err := g.markDirectories(); err != nil {
		close(g.watchDone)
		g.Close()
		return err
	}
	go g.refreshWatches(ctx)
	return nil
}

func (g *ExecGuard) Close() {
	if g.cancel != nil {
		g.cancel()
		<-g.done
		<-g.watchDone
	} else {
		_ = unix.Close(g.fd)
	}
}

// Refresh marks in a separate goroutine so the reader can always respond.
func (g *ExecGuard) refreshWatches(ctx context.Context) {
	defer close(g.watchDone)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := preflightExecutionRoots(g.paths, maxExecutionDirectoryWatches); err != nil {
				g.failOpen(err)
				return
			}
			if err := g.markDirectories(); err != nil {
				g.failOpen(err)
				return
			}
		}
	}
}

func (g *ExecGuard) run(ctx context.Context) {
	defer close(g.done)
	defer unix.Close(g.fd)
	queue := make(chan execRequest, 8)
	var workers sync.WaitGroup
	for i := 0; i < executionScanWorkers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for request := range queue {
				g.decide(ctx, request)
			}
		}()
	}
	defer func() { close(queue); workers.Wait() }()
	close(g.ready)
	buffer := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := unix.Read(g.fd, buffer)
		if err == unix.EAGAIN || err == unix.EINTR {
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			g.failOpen(err)
			return
		}
		requests, err := parseExecRequests(buffer[:n])
		if err != nil {
			g.failOpen(err)
		}
		for _, request := range requests {
			// Scanner subprocesses must be allowed by the reader, which remains free
			// while workers wait for their YARA child. Otherwise scanning deadlocks.
			if g.isOwnHelper(request) {
				g.respond(request, false)
				continue
			}
			if ctx.Err() != nil {
				g.respond(request, false)
				continue
			}
			select {
			case queue <- request:
			default:
				// A saturated permission queue must not hold host launches.
				g.failOpen(fmt.Errorf("execution scan queue full; blocking disabled until restart"))
				g.respond(request, false)
			}
		}
	}
}

func parseExecRequests(data []byte) ([]execRequest, error) {
	var result []execRequest
	var warning error
	for len(data) >= 24 {
		length := int(binary.NativeEndian.Uint32(data[:4]))
		if length < 24 || length > len(data) || data[4] != unix.FANOTIFY_METADATA_VERSION {
			return result, fmt.Errorf("invalid fanotify metadata")
		}
		mask := binary.NativeEndian.Uint64(data[8:16])
		fd, pid := int(int32(binary.NativeEndian.Uint32(data[16:20]))), int(int32(binary.NativeEndian.Uint32(data[20:24])))
		if mask&unix.FAN_Q_OVERFLOW != 0 {
			warning = fmt.Errorf("fanotify queue overflow; execution coverage degraded")
		}
		if fd >= 0 {
			if mask&unix.FAN_OPEN_EXEC_PERM != 0 {
				result = append(result, execRequest{fd: fd, pid: pid, deadline: time.Now().Add(executionDecisionTimeout)})
			} else {
				_ = unix.Close(fd)
			}
		}
		data = data[length:]
	}
	if len(data) != 0 {
		return result, fmt.Errorf("truncated fanotify metadata")
	}
	return result, warning
}

func (g *ExecGuard) isOwnHelper(request execRequest) bool {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", request.pid))
	if err != nil {
		return false
	}
	parent := ""
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			parent = strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
		}
	}
	if parent != strconv.Itoa(os.Getpid()) {
		return false
	}
	info, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", request.fd))
	if err != nil {
		return false
	}
	for _, helper := range g.helpers {
		if os.SameFile(info, helper) {
			return true
		}
	}
	return false
}

func (g *ExecGuard) decide(ctx context.Context, request execRequest) {
	file := os.NewFile(uintptr(request.fd), "pending-executable")
	deny := false
	// A queued request must never wait for every earlier scan to finish.
	scanCtx, cancel := context.WithDeadline(ctx, request.deadline)
	defer cancel()
	if scanCtx.Err() == nil {
		var err error
		deny, err = g.scan(scanCtx, file, request.pid)
		if err != nil {
			g.report(err)
			deny = false
		}
		if scanCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			deny = false
			g.failOpen(fmt.Errorf("execution scan deadline exceeded; blocking disabled until restart"))
		}
	} else if ctx.Err() == nil {
		g.failOpen(fmt.Errorf("execution scan deadline exceeded in queue; blocking disabled until restart"))
	}
	response := permissionResponse(request.fd, deny)
	_, err := unix.Write(g.fd, response)
	if err != nil {
		g.failOpen(fmt.Errorf("execution permission response failed: %w", err))
	}
	if g.RecordDecision != nil {
		g.RecordDecision(request.pid, deny, err)
	}
	file.Close()
}
func permissionResponse(fd int, deny bool) []byte {
	response := make([]byte, 8)
	binary.NativeEndian.PutUint32(response[:4], uint32(fd))
	decision := uint32(unix.FAN_ALLOW)
	if deny {
		decision = unix.FAN_DENY
	}
	binary.NativeEndian.PutUint32(response[4:], decision)
	return response
}
func (g *ExecGuard) respond(request execRequest, deny bool) {
	if _, err := unix.Write(g.fd, permissionResponse(request.fd, deny)); err != nil {
		g.failOpen(fmt.Errorf("execution permission response failed: %w", err))
	}
	_ = unix.Close(request.fd)
}

// Closing the fanotify group releases pending permission requests after an
// overload. Process telemetry and YARA scanning continue independently.
func (g *ExecGuard) failOpen(err error) {
	if g.report != nil {
		g.report(err)
	}
	if g.cancel != nil {
		g.cancel()
	}
}
