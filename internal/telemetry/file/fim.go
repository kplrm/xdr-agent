// Package file provides file integrity monitoring (FIM) and real-time
// filesystem event detection for XDR endpoint security.
//
// FIMCollector implements two complementary detection layers:
//  1. Real-time event detection via Linux inotify — any write, attribute
//     change, create, delete, or rename in watched paths fires immediately.
//  2. Periodic SHA-256 rescan — a full tree walk that validates every
//     monitored file against the stored baseline.  This catches changes
//     missed by inotify (e.g., after an overflow) and acts as ground truth.
//
// Baseline storage: BoltDB (go.etcd.io/bbolt) at /var/lib/xdr-agent/fim_baseline.db.
//
// Events are ECS-compatible (file.*, fim.*) and indexed in OpenSearch as
// event.category="file" with event.kind="event".
//
// Supported Linux distributions: Debian/Ubuntu, RedHat/CentOS (via DefaultLinuxCriticalPaths).
package file

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	bolt "go.etcd.io/bbolt"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	// fimBucket is the BoltDB bucket name for the file baseline.
	fimBucket = "fim_baseline"

	// defaultDBPath is where BoltDB stores the baseline on disk.
	defaultDBPath = "/var/lib/xdr-agent/fim_baseline.db"

	// defaultRescanInterval is how often to re-hash all monitored files.
	defaultRescanInterval = time.Hour

	// inotifyBufSize is the read buffer for inotify events.
	// Each event is at least 16 bytes; 64 KiB holds ~4000 minimal events.
	inotifyBufSize = 65536

	// inotifyMask covers the events relevant for security monitoring.
	inotifyMask = syscall.IN_CLOSE_WRITE |
		syscall.IN_MOVED_FROM |
		syscall.IN_MOVED_TO |
		syscall.IN_CREATE |
		syscall.IN_DELETE |
		syscall.IN_DELETE_SELF |
		syscall.IN_MOVE_SELF |
		syscall.IN_ATTRIB
)

// ── Data types ────────────────────────────────────────────────────────────────

// fileRecord is the schema persisted in BoltDB for each monitored file.
type fileRecord struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"` // octal permission string e.g. "0644"
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	MtimeSec int64  `json:"mtime_sec"` // Unix seconds
	CtimeSec int64  `json:"ctime_sec"` // Unix seconds
	SHA256   string `json:"sha256"`    // hex; empty for directories/symlinks
	FileType string `json:"file_type"` // "file", "dir", or "symlink"
}

// ── FIMCollector ──────────────────────────────────────────────────────────────

// FIMCollector monitors filesystem paths for integrity changes using inotify
// and periodic SHA-256 rescans. It implements capability.Capability.
type FIMCollector struct {
	pipeline       *events.Pipeline
	agentID        string
	hostname       string
	watchPaths     []WatchPath
	dbPath         string
	rescanInterval time.Duration

	// BoltDB baseline store — opened in Init, closed in Stop.
	db *bolt.DB

	// inotify state — only accessed while holding inotifyMu.
	inotifyMu     sync.Mutex
	inotifyFd     int              // -1 when closed
	wdToPath      map[int32]string // watch descriptor → absolute directory path
	pathToWd      map[string]int32 // absolute directory path → watch descriptor
	recursiveDirs map[string]bool  // directories that expand watches into new subdirs

	mu     sync.Mutex
	health capability.HealthStatus
	cancel context.CancelFunc
}

// NewFIMCollector constructs a FIMCollector.
//
// Supply nil watchPaths to use DefaultLinuxCriticalPaths().
// Supply empty dbPath to use /var/lib/xdr-agent/fim_baseline.db.
// Supply 0 rescanInterval to use 1 hour.
func NewFIMCollector(
	pipeline *events.Pipeline,
	agentID, hostname string,
	watchPaths []WatchPath,
	rescanInterval time.Duration,
	dbPath string,
) *FIMCollector {
	if rescanInterval <= 0 {
		rescanInterval = defaultRescanInterval
	}
	if dbPath == "" {
		dbPath = defaultDBPath
	}
	if len(watchPaths) == 0 {
		watchPaths = DefaultLinuxCriticalPaths()
	}
	return &FIMCollector{
		pipeline:       pipeline,
		agentID:        agentID,
		hostname:       hostname,
		watchPaths:     watchPaths,
		dbPath:         dbPath,
		rescanInterval: rescanInterval,
		inotifyFd:      -1,
		wdToPath:       make(map[int32]string),
		pathToWd:       make(map[string]int32),
		recursiveDirs:  make(map[string]bool),
		health:         capability.HealthStopped,
	}
}

// ── capability.Capability interface ──────────────────────────────────────────

func (f *FIMCollector) Name() string { return "telemetry.file" }

// Init opens the BoltDB database and creates the baseline bucket.
func (f *FIMCollector) Init(_ capability.Dependencies) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(f.dbPath), 0750); err != nil {
		return fmt.Errorf("fim: create db dir: %w", err)
	}

	db, err := bolt.Open(f.dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return fmt.Errorf("fim: open db: %w", err)
	}

	if err = db.Update(func(tx *bolt.Tx) error {
		_, txErr := tx.CreateBucketIfNotExists([]byte(fimBucket))
		return txErr
	}); err != nil {
		_ = db.Close()
		return fmt.Errorf("fim: create bucket: %w", err)
	}

	f.db = db
	f.health = capability.HealthStarting
	return nil
}

// Start sets up inotify watches, runs the initial baseline scan, and
// launches the real-time event loop and periodic rescan goroutines.
func (f *FIMCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	f.mu.Lock()
	f.cancel = cancel
	f.health = capability.HealthRunning
	f.mu.Unlock()

	if err := f.setupInotify(); err != nil {
		log.Printf("fim: inotify unavailable (%v) — periodic rescan only", err)
	} else {
		go f.inotifyLoop(childCtx)
	}

	go f.scanLoop(childCtx)
	return nil
}

// Stop cancels all goroutines, closes inotify, and flushes BoltDB.
func (f *FIMCollector) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.cancel != nil {
		f.cancel()
	}

	f.inotifyMu.Lock()
	if f.inotifyFd >= 0 {
		_ = syscall.Close(f.inotifyFd)
		f.inotifyFd = -1
	}
	f.inotifyMu.Unlock()

	if f.db != nil {
		_ = f.db.Close()
		f.db = nil
	}

	f.health = capability.HealthStopped
	return nil
}

func (f *FIMCollector) Health() capability.HealthStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.health
}

// ── inotify setup ─────────────────────────────────────────────────────────────

// setupInotify opens an IN_NONBLOCK inotify instance and adds watches for all
// configured watchPaths.
func (f *FIMCollector) setupInotify() error {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}

	f.inotifyMu.Lock()
	f.inotifyFd = fd
	f.inotifyMu.Unlock()

	for _, wp := range f.watchPaths {
		f.addWatch(wp.Path, wp.Recursive)
	}
	return nil
}

// addWatch dispatches to addDirWatch or addFileWatch based on the path type.
func (f *FIMCollector) addWatch(path string, recursive bool) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return // Optional path — skip silently
	}
	if err != nil {
		log.Printf("fim: stat %s: %v", path, err)
		return
	}

	if info.IsDir() {
		f.addDirWatch(path, recursive)
	} else {
		f.addFileWatch(path)
	}
}

// addDirWatch registers an inotify watch on a directory.
// When recursive is true, all existing subdirectories are also watched, and
// newly created subdirs are automatically watched on IN_CREATE|IN_ISDIR.
func (f *FIMCollector) addDirWatch(dirPath string, recursive bool) {
	f.inotifyMu.Lock()
	fd := f.inotifyFd
	f.inotifyMu.Unlock()

	if fd < 0 {
		return
	}

	mask := uint32(inotifyMask | syscall.IN_ONLYDIR)

	wd, err := syscall.InotifyAddWatch(fd, dirPath, mask)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("fim: inotify_add_watch %s: %v", dirPath, err)
		}
		return
	}

	f.inotifyMu.Lock()
	f.wdToPath[int32(wd)] = dirPath
	f.pathToWd[dirPath] = int32(wd)
	if recursive {
		f.recursiveDirs[dirPath] = true
	}
	f.inotifyMu.Unlock()

	if !recursive {
		return
	}
	// Recursively watch existing subdirectories.
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			f.addDirWatch(filepath.Join(dirPath, e.Name()), true)
		}
	}
}

// addFileWatch registers an inotify watch on a single file.
func (f *FIMCollector) addFileWatch(filePath string) {
	f.inotifyMu.Lock()
	fd := f.inotifyFd
	f.inotifyMu.Unlock()

	if fd < 0 {
		return
	}

	mask := uint32(syscall.IN_CLOSE_WRITE | syscall.IN_ATTRIB | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF)

	wd, err := syscall.InotifyAddWatch(fd, filePath, mask)
	if err != nil {
		return
	}

	f.inotifyMu.Lock()
	f.wdToPath[int32(wd)] = filepath.Dir(filePath)
	f.pathToWd[filePath] = int32(wd)
	f.inotifyMu.Unlock()
}

// ── inotify event loop ────────────────────────────────────────────────────────

// inotifyLoop polls the inotify fd every 100 ms and dispatches events.
// Non-blocking fd (IN_NONBLOCK) allows clean cancellation via context.
func (f *FIMCollector) inotifyLoop(ctx context.Context) {
	buf := make([]byte, inotifyBufSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f.inotifyMu.Lock()
		fd := f.inotifyFd
		f.inotifyMu.Unlock()

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

		f.parseInotifyEvents(ctx, buf[:n])
	}
}

// parseInotifyEvents processes a raw inotify read buffer that may contain
// one or more variable-length inotify_event structures.
//
// Kernel ABI (from <sys/inotify.h>):
//
//	struct inotify_event {
//	    int32  wd;
//	    uint32 mask;
//	    uint32 cookie;
//	    uint32 len;       // length of `name` including null padding
//	    char   name[len]; // null-padded to 4-byte boundary
//	};
func (f *FIMCollector) parseInotifyEvents(ctx context.Context, buf []byte) {
	const hdrSize = syscall.SizeofInotifyEvent // 16 bytes on Linux

	for offset := 0; offset+hdrSize <= len(buf); {
		// Cast to *syscall.InotifyEvent — safe: kernel guarantees alignment
		// and we own the buffer lifetime.
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

		f.handleInotifyEvent(ctx, hdr.Wd, hdr.Mask, name)
		offset += totalLen
	}
}

// handleInotifyEvent translates a decoded inotify event to a security action.
func (f *FIMCollector) handleInotifyEvent(ctx context.Context, wd int32, mask uint32, name string) {
	if ctx.Err() != nil {
		return
	}

	// IN_Q_OVERFLOW: event queue overflowed — trigger a full rescan.
	if mask&syscall.IN_Q_OVERFLOW != 0 {
		log.Printf("fim: inotify event queue overflow — scheduling full rescan")
		go f.runRescan(ctx)
		return
	}

	f.inotifyMu.Lock()
	dirPath, ok := f.wdToPath[wd]
	isRecursive := f.recursiveDirs[dirPath]
	f.inotifyMu.Unlock()

	if !ok {
		return
	}

	var filePath string
	if name != "" {
		filePath = filepath.Join(dirPath, name)
	} else {
		filePath = dirPath // event on the watched item itself (DELETE_SELF, etc.)
	}

	isDir := mask&syscall.IN_ISDIR != 0

	switch {
	case mask&syscall.IN_CREATE != 0:
		if isDir && isRecursive {
			f.addDirWatch(filePath, true)
		}
		if !isDir {
			f.onFileCreated(filePath)
		}

	case mask&syscall.IN_CLOSE_WRITE != 0:
		// File was written and closed — most reliable signal for content change.
		if !isDir {
			f.onFileModified(filePath)
		}

	case mask&syscall.IN_ATTRIB != 0:
		if !isDir {
			f.onFileAttrsChanged(filePath)
		}

	case mask&syscall.IN_MOVED_FROM != 0:
		if !isDir {
			f.onFileDeleted(filePath) // moved away → treat as delete from old path
		}

	case mask&syscall.IN_MOVED_TO != 0:
		if !isDir {
			f.onFileCreated(filePath) // moved into dir → treat as create at new path
		} else if isRecursive {
			f.addDirWatch(filePath, true)
		}

	case mask&(syscall.IN_DELETE|syscall.IN_DELETE_SELF) != 0:
		if !isDir {
			f.onFileDeleted(filePath)
		}
	}
}

// ── Scan loop (baseline + periodic rescan) ────────────────────────────────────

// scanLoop runs the initial baseline then periodically rescans.
func (f *FIMCollector) scanLoop(ctx context.Context) {
	f.runBaselineScan(ctx)

	ticker := time.NewTicker(f.rescanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.runRescan(ctx)
		}
	}
}

// runBaselineScan walks all watched paths and populates BoltDB without emitting
// events.  Files already in the DB are left unchanged (supports warm restarts).
func (f *FIMCollector) runBaselineScan(ctx context.Context) {
	distroName := "unknown"
	switch DetectDistro() {
	case DistroDebian:
		distroName = "debian"
	case DistroRHEL:
		distroName = "rhel"
	}
	log.Printf("fim: starting initial baseline scan (%d watch paths, distro=%s)", len(f.watchPaths), distroName)
	count := 0
	skipped := 0

	for _, wp := range f.watchPaths {
		if ctx.Err() != nil {
			return
		}
		pathCount := 0
		f.walkPath(ctx, wp.Path, wp.Recursive, func(rec *fileRecord) {
			if _, err := f.loadRecord(rec.Path); err != nil {
				if storeErr := f.storeRecord(rec); storeErr != nil {
					log.Printf("fim: baseline store error for %s: %v", rec.Path, storeErr)
				} else {
					count++
					pathCount++
				}
			} else {
				// Already in DB from a previous run — warm restart.
				skipped++
				pathCount++
			}
		})
		if pathCount == 0 {
			// Log unexpected errors (e.g. EPERM) but not plain "not found" —
			// non-existent paths are expected for optional distro-specific entries.
			if _, statErr := os.Lstat(wp.Path); statErr != nil && !os.IsNotExist(statErr) {
				log.Printf("fim: baseline skip %s: %v", wp.Path, statErr)
			}
		}
	}

	if skipped > 0 {
		log.Printf("fim: baseline complete — %d files newly recorded, %d already in DB (warm restart)", count, skipped)
	} else {
		log.Printf("fim: baseline complete — %d files recorded", count)
	}
}

// runRescan re-walks all paths, compares against the DB, and emits events for
// changes.  Also detects files present in DB but missing on disk (deleted).
func (f *FIMCollector) runRescan(ctx context.Context) {
	log.Printf("fim: starting periodic rescan")

	seenOnDisk := make(map[string]struct{}, 2048)

	for _, wp := range f.watchPaths {
		if ctx.Err() != nil {
			return
		}
		f.walkPath(ctx, wp.Path, wp.Recursive, func(rec *fileRecord) {
			seenOnDisk[rec.Path] = struct{}{}

			old, err := f.loadRecord(rec.Path)
			if err != nil {
				// New file not previously known — emit created.
				_ = f.storeRecord(rec)
				f.emitFIMEvent("file.created", "created", events.SeverityMedium, rec, nil)
				return
			}

			// Detect content change for regular files.
			if rec.FileType == "file" && rec.SHA256 != "" && rec.SHA256 != old.SHA256 {
				_ = f.storeRecord(rec)
				sev := events.SeverityHigh
				if !isCriticalPath(rec.Path) {
					sev = events.SeverityMedium
				}
				f.emitFIMEvent("file.modified", "modified", sev, rec, old)
				return
			}

			// Detect metadata changes.
			if rec.Mode != old.Mode || rec.UID != old.UID || rec.GID != old.GID {
				_ = f.storeRecord(rec)
				f.emitFIMEvent("file.attrs_changed", "attributes_modified", events.SeverityMedium, rec, old)
			}
		})
	}

	// Detect deleted files.
	_ = f.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(fimBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			path := string(k)
			if _, seen := seenOnDisk[path]; !seen {
				var rec fileRecord
				if jsonErr := json.Unmarshal(v, &rec); jsonErr == nil {
					f.onFileDeleted(path)
				}
			}
			return nil
		})
	})

	log.Printf("fim: periodic rescan complete")
}

// walkPath recursively (if requested) walks root and calls fn for every
// regular file and symlink found.
func (f *FIMCollector) walkPath(ctx context.Context, root string, recursive bool, fn func(*fileRecord)) {
	info, err := os.Lstat(root)
	if err != nil {
		// Log permission errors so they are visible; pure not-found is noise.
		if !os.IsNotExist(err) {
			log.Printf("fim: walkPath lstat error %s: %v", root, err)
		}
		return
	}

	if !info.IsDir() {
		rec, recErr := f.buildFileRecord(root)
		if recErr == nil {
			fn(rec)
		}
		return
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("fim: walkPath readdir error %s: %v", root, err)
		}
		return
	}

	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		childPath := filepath.Join(root, e.Name())
		childInfo, statErr := os.Lstat(childPath)
		if statErr != nil {
			continue
		}

		if childInfo.IsDir() {
			if recursive {
				f.walkPath(ctx, childPath, true, fn)
			}
			continue
		}

		rec, recErr := f.buildFileRecord(childPath)
		if recErr == nil {
			fn(rec)
		}
	}
}

// ── File event handlers ───────────────────────────────────────────────────────

func (f *FIMCollector) onFileCreated(path string) {
	rec, err := f.buildFileRecord(path)
	if err != nil {
		return
	}
	_ = f.storeRecord(rec)
	f.emitFIMEvent("file.created", "created", events.SeverityMedium, rec, nil)
}

func (f *FIMCollector) onFileModified(path string) {
	rec, err := f.buildFileRecord(path)
	if err != nil {
		return
	}
	old, _ := f.loadRecord(path)
	_ = f.storeRecord(rec)

	sev := events.SeverityMedium
	if isCriticalPath(path) {
		sev = events.SeverityHigh
	}
	f.emitFIMEvent("file.modified", "modified", sev, rec, old)
}

func (f *FIMCollector) onFileAttrsChanged(path string) {
	rec, err := f.buildFileRecord(path)
	if err != nil {
		return
	}
	old, _ := f.loadRecord(path)
	_ = f.storeRecord(rec)
	f.emitFIMEvent("file.attrs_changed", "attributes_modified", events.SeverityLow, rec, old)
}

func (f *FIMCollector) onFileDeleted(path string) {
	old, _ := f.loadRecord(path)
	_ = f.deleteRecord(path)

	rec := &fileRecord{Path: path, FileType: "file"}
	if old != nil {
		rec = old
	}

	sev := events.SeverityMedium
	if isCriticalPath(path) {
		sev = events.SeverityHigh
	}
	f.emitFIMEvent("file.deleted", "deleted", sev, rec, nil)
}

// ── ECS-compatible event emission ─────────────────────────────────────────────

// emitFIMEvent builds and publishes an ECS-compatible FIM event.
//
// ECS fields emitted:
//   - file.path, file.name, file.directory, file.type
//   - file.size, file.mode, file.uid, file.gid, file.owner, file.group
//   - file.hash.sha256, file.mtime, file.ctime
//   - fim.action, fim.previous.{hash.sha256, size, mode, uid, gid}
func (f *FIMCollector) emitFIMEvent(
	eventType, action string,
	severity events.Severity,
	current *fileRecord,
	previous *fileRecord,
) {
	filePayload := map[string]interface{}{
		"path":      current.Path,
		"name":      filepath.Base(current.Path),
		"directory": filepath.Dir(current.Path),
		"type":      current.FileType,
		"uid":       current.UID,
		"gid":       current.GID,
		"mode":      current.Mode,
	}
	if current.Size > 0 {
		filePayload["size"] = current.Size
	}
	if current.SHA256 != "" {
		filePayload["hash"] = map[string]interface{}{"sha256": current.SHA256}
	}
	if current.MtimeSec > 0 {
		filePayload["mtime"] = time.Unix(current.MtimeSec, 0).UTC().Format(time.RFC3339)
	}
	if current.CtimeSec > 0 {
		filePayload["ctime"] = time.Unix(current.CtimeSec, 0).UTC().Format(time.RFC3339)
	}
	// Resolve human-readable names — best-effort, failures are silently ignored.
	if u, err := user.LookupId(strconv.Itoa(int(current.UID))); err == nil {
		filePayload["owner"] = u.Username
	}
	if g, err := user.LookupGroupId(strconv.Itoa(int(current.GID))); err == nil {
		filePayload["group"] = g.Name
	}

	fimPayload := map[string]interface{}{"action": action}

	if previous != nil {
		prev := map[string]interface{}{}
		if previous.SHA256 != "" && previous.SHA256 != current.SHA256 {
			prev["hash"] = map[string]interface{}{"sha256": previous.SHA256}
		}
		if previous.Size != current.Size {
			prev["size"] = previous.Size
		}
		if previous.Mode != current.Mode {
			prev["mode"] = previous.Mode
		}
		if previous.UID != current.UID {
			prev["uid"] = previous.UID
		}
		if previous.GID != current.GID {
			prev["gid"] = previous.GID
		}
		if len(prev) > 0 {
			fimPayload["previous"] = prev
		}
	}

	ev := events.Event{
		ID:        fmt.Sprintf("fim-%s-%d", action, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		Category:  "file",
		Kind:      "event",
		Severity:  severity,
		Module:    "telemetry.file",
		AgentID:   f.agentID,
		Hostname:  f.hostname,
		Payload: map[string]interface{}{
			"file": filePayload,
			"fim":  fimPayload,
		},
		Tags: []string{"fim", "file", "telemetry"},
	}
	f.pipeline.Emit(ev)
}

// ── BoltDB helpers ────────────────────────────────────────────────────────────

func (f *FIMCollector) storeRecord(rec *fileRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return f.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(fimBucket))
		if b == nil {
			return fmt.Errorf("fim bucket not found")
		}
		return b.Put([]byte(rec.Path), data)
	})
}

func (f *FIMCollector) loadRecord(path string) (*fileRecord, error) {
	var rec fileRecord
	err := f.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(fimBucket))
		if b == nil {
			return fmt.Errorf("fim bucket not found")
		}
		data := b.Get([]byte(path))
		if data == nil {
			return fmt.Errorf("not found: %s", path)
		}
		return json.Unmarshal(data, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (f *FIMCollector) deleteRecord(path string) error {
	return f.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(fimBucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(path))
	})
}

// ── File metadata helpers ─────────────────────────────────────────────────────

// buildFileRecord stats path and computes SHA-256 for regular files ≤ 256 MiB.
func (f *FIMCollector) buildFileRecord(path string) (*fileRecord, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}

	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("fim: unexpected Stat_t type for %s", path)
	}

	rec := &fileRecord{
		Path:     path,
		Size:     info.Size(),
		Mode:     fmt.Sprintf("%04o", info.Mode().Perm()),
		UID:      sys.Uid,
		GID:      sys.Gid,
		MtimeSec: info.ModTime().Unix(),
		CtimeSec: sys.Ctim.Sec,
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		rec.FileType = "symlink"
	case info.IsDir():
		rec.FileType = "dir"
	default:
		rec.FileType = "file"
		// Limit hashing to 256 MiB to avoid latency spikes on large files.
		if info.Size() <= 256<<20 {
			if hash, hErr := hashFile(path); hErr == nil {
				rec.SHA256 = hash
			}
		}
	}

	return rec, nil
}

// hashFile computes the SHA-256 digest of a file's content.
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

// isCriticalPath returns true for paths that deserve elevated severity when
// modified or deleted: authentication files, PAM, SSH, system binaries, boot.
func isCriticalPath(path string) bool {
	criticals := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
		"/etc/sudoers", "/etc/pam.d/", "/etc/security/",
		"/etc/ssh/sshd_config",
		"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
		"/usr/local/bin/", "/usr/local/sbin/",
		"/boot/", "/etc/ld.so",
	}
	for _, prefix := range criticals {
		if path == prefix || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
