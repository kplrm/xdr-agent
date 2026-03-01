package process

// Enrichment adds contextual metadata to process events by reading
// additional /proc/[pid] files beyond the core stat/status/cmdline/exe.
//
// All functions in this file are pure/stateless with respect to the collector
// and degrade gracefully: if any /proc file is missing or unreadable the
// corresponding field is left at its zero value, never returning an error.
//
// ECS field coverage added here:
//   process.working_directory    → /proc/[pid]/cwd
//   process.args                 → /proc/[pid]/cmdline (NUL-separated)
//   process.fd_count             → count of entries in /proc/[pid]/fd/
//   process.io.read_bytes        → /proc/[pid]/io (read_bytes)
//   process.io.write_bytes       → /proc/[pid]/io (write_bytes)
//   container.id                 → /proc/[pid]/cgroup (Docker/containerd/k8s)
//   process.entity_id            → SHA-256(hostname+pid+starttime)[:16]
//   process.hash.sha256          → SHA-256 of executable image (new procs only)
//   process.user.name            → /etc/passwd lookup for process.user.id
//   process.group.name           → /etc/group  lookup for process.group.id

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ── Username / Group resolution ───────────────────────────────────────────────

// uidCache provides a thread-safe, lazily-populated UID → username map.
// It reads /etc/passwd directly, avoiding CGO and NSS network lookups.
type uidCache struct {
	mu    sync.RWMutex
	names map[int]string
}

func newUIDCache() *uidCache { return &uidCache{names: make(map[int]string)} }

func (c *uidCache) lookup(uid int) string {
	c.mu.RLock()
	name, ok := c.names[uid]
	c.mu.RUnlock()
	if ok {
		return name
	}
	name = scanColonFile("/etc/passwd", uid, 2, 0)
	c.mu.Lock()
	c.names[uid] = name
	c.mu.Unlock()
	return name
}

// gidCache provides a thread-safe, lazily-populated GID → group name map.
type gidCache struct {
	mu    sync.RWMutex
	names map[int]string
}

func newGIDCache() *gidCache { return &gidCache{names: make(map[int]string)} }

func (c *gidCache) lookup(gid int) string {
	c.mu.RLock()
	name, ok := c.names[gid]
	c.mu.RUnlock()
	if ok {
		return name
	}
	name = scanColonFile("/etc/group", gid, 2, 0)
	c.mu.Lock()
	c.names[gid] = name
	c.mu.Unlock()
	return name
}

// scanColonFile scans a colon-delimited file (passwd/group style) looking for
// a line where field[keyCol] matches the numeric id, then returns field[valCol].
func scanColonFile(path string, id, keyCol, valCol int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	target := strconv.Itoa(id)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) > keyCol && fields[keyCol] == target {
			if len(fields) > valCol {
				return fields[valCol]
			}
		}
	}
	return ""
}

// ── Working directory ─────────────────────────────────────────────────────────

// readCWD resolves the /proc/[pid]/cwd symlink.
// ECS: process.working_directory
func readCWD(pidDir string) string {
	target, err := os.Readlink(filepath.Join(pidDir, "cwd"))
	if err != nil {
		return ""
	}
	return target
}

// ── Command-line args ─────────────────────────────────────────────────────────

// parseCmdlineArgs reads /proc/[pid]/cmdline and splits on NUL bytes.
// ECS: process.args  (array of strings)
func parseCmdlineArgs(pidDir string) []string {
	data, err := os.ReadFile(filepath.Join(pidDir, "cmdline"))
	if err != nil || len(data) == 0 {
		return nil
	}
	// Trim trailing NUL bytes.
	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	raw := strings.Split(string(data), "\x00")
	out := raw[:0]
	for _, s := range raw {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ── Open file descriptors ─────────────────────────────────────────────────────

// countFDs counts the entries in /proc/[pid]/fd.
// Returns 0 if the directory is unreadable (expected for non-root agents).
// ECS: process.fd_count
func countFDs(pidDir string) int {
	entries, err := os.ReadDir(filepath.Join(pidDir, "fd"))
	if err != nil {
		return 0
	}
	return len(entries)
}

// ── I/O statistics ────────────────────────────────────────────────────────────

// readIO parses /proc/[pid]/io for cumulative read/write byte counts.
// ECS: process.io.read_bytes, process.io.write_bytes
func readIO(pidDir string) (readBytes, writeBytes uint64) {
	f, err := os.Open(filepath.Join(pidDir, "io"))
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "read_bytes:"):
			parts := strings.Fields(line)
			if len(parts) == 2 {
				readBytes, _ = strconv.ParseUint(parts[1], 10, 64)
			}
		case strings.HasPrefix(line, "write_bytes:"):
			parts := strings.Fields(line)
			if len(parts) == 2 {
				writeBytes, _ = strconv.ParseUint(parts[1], 10, 64)
			}
		}
	}
	return
}

// ── Container detection ───────────────────────────────────────────────────────

// detectContainerID reads /proc/[pid]/cgroup and attempts to extract a
// container ID from Docker, containerd, or Kubernetes cgroup paths.
// Returns an empty string for bare-metal / non-container processes.
// ECS: container.id
func detectContainerID(pidDir string) string {
	f, err := os.Open(filepath.Join(pidDir, "cgroup"))
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()

		// Docker: ...:/docker/<64-hex>
		if idx := strings.LastIndex(line, "/docker/"); idx >= 0 {
			id := strings.TrimSpace(line[idx+len("/docker/"):])
			if len(id) >= 12 {
				return id[:12]
			}
		}

		// containerd / k8s: ...:/kubepods/.../cri-containerd-<id>.scope
		if strings.Contains(line, "kubepods") || strings.Contains(line, "containerd") {
			parts := strings.Split(line, "/")
			for i := len(parts) - 1; i >= 0; i-- {
				seg := parts[i]
				seg = strings.TrimPrefix(seg, "cri-containerd-")
				seg = strings.TrimSuffix(seg, ".scope")
				if len(seg) >= 12 && isHex(seg) {
					return seg[:12]
				}
			}
		}

		// Podman: /libpod-<id>
		if idx := strings.LastIndex(line, "/libpod-"); idx >= 0 {
			id := strings.TrimSpace(line[idx+len("/libpod-"):])
			id = strings.TrimSuffix(id, ".scope")
			if len(id) >= 12 {
				return id[:12]
			}
		}
	}
	return ""
}

// isHex reports whether every character in s is a hexadecimal digit.
func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ── Entity ID ─────────────────────────────────────────────────────────────────

// buildEntityID creates a stable, host-scoped identifier for a process instance.
// Uses SHA-256(hostname + pid + starttime) truncated to 16 hex chars, matching
// Elastic's agent convention for ECS process.entity_id.
func buildEntityID(hostname string, pid int, startTime uint64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", hostname, pid, startTime)))
	return hex.EncodeToString(h[:])[:16]
}

// ── Executable hash ───────────────────────────────────────────────────────────

// hashFile computes the SHA-256 digest of the file at path.
// Returns an empty string on any error (missing, permission denied, etc.).
// ECS: process.hash.sha256
func hashFile(path string) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ── enrichProcessInfo ─────────────────────────────────────────────────────────

// enrichProcessInfo fills in optional "fast" enrichment fields on a ProcessInfo.
// Called for every process on every scan interval; must remain cheap.
// Hostname is omitted here — entity_id is finalised at emit time.
func enrichProcessInfo(procRoot string, info *ProcessInfo) {
	pidDir := filepath.Join(procRoot, strconv.Itoa(info.PID))
	info.CWD = readCWD(pidDir)
	info.Args = parseCmdlineArgs(pidDir)
	info.FDCount = countFDs(pidDir)
	info.IOReadBytes, info.IOWriteBytes = readIO(pidDir)
	info.ContainerID = detectContainerID(pidDir)
}

// enrichNewProcess adds expensive, one-shot enrichment for newly discovered
// processes. Only called when a process is first seen (process.start event).
func enrichNewProcess(info *ProcessInfo, uids *uidCache, gids *gidCache) {
	if info.Executable != "" {
		info.ExeSHA256 = hashFile(info.Executable)
	}
	info.Username = uids.lookup(info.UID)
	info.GroupName = gids.lookup(info.GID)
}
