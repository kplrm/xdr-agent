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
//   process.entity_id            → SHA-256(agent ID + PID + start ticks)
//   process.user.name            → /etc/passwd lookup for process.user.id
//   process.group.name           → /etc/group  lookup for process.group.id

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

		// Docker cgroupfs: ...:/docker/<id>[/child]
		if idx := strings.LastIndex(line, "/docker/"); idx >= 0 {
			id := strings.SplitN(strings.TrimSpace(line[idx+len("/docker/"):]), "/", 2)[0]
			if len(id) >= 12 && isHex(id) {
				return id
			}
		}

		// Runtime systemd scopes and containerd/Kubernetes cgroupfs paths.
		if strings.Contains(line, "kubepods") || strings.Contains(line, "containerd") ||
			strings.Contains(line, "docker-") || strings.Contains(line, "libpod-") {
			parts := strings.Split(line, "/")
			for i := len(parts) - 1; i >= 0; i-- {
				seg := strings.TrimSuffix(parts[i], ".scope")
				seg = strings.TrimPrefix(seg, "cri-containerd-")
				seg = strings.TrimPrefix(seg, "docker-")
				seg = strings.TrimPrefix(seg, "libpod-")
				if len(seg) >= 12 && isHex(seg) {
					return seg
				}
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

// buildEntityID identifies a process instance within an Agent using the full SHA-256 digest.
func buildEntityID(agentID string, pid int, startTime uint64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", agentID, pid, startTime)))
	return hex.EncodeToString(h[:])
}

// ── enrichProcessInfo ─────────────────────────────────────────────────────────

// enrichProcessInfo fills in optional "fast" enrichment fields on a ProcessInfo.
// Called for every process on every scan interval; must remain cheap.
// Entity IDs are finalised at emit time.
func enrichProcessInfo(procRoot string, info *ProcessInfo) {
	pidDir := filepath.Join(procRoot, strconv.Itoa(info.PID))
	info.CWD = readCWD(pidDir)
	info.Args = parseCmdlineArgs(pidDir)
	info.FDCount = countFDs(pidDir)
	info.IOReadBytes, info.IOWriteBytes = readIO(pidDir)
	info.ContainerID = detectContainerID(pidDir)
}

// enrichNewProcess adds user context for newly discovered
// processes. Only called when a process is first seen (process.start event).
func enrichNewProcess(info *ProcessInfo, uids *uidCache, gids *gidCache) {
	info.Username = uids.lookup(info.UID)
	info.GroupName = gids.lookup(info.GID)
}
