package network

// pid.go resolves the owning process of a network socket identified by its
// inode number.  It does this by scanning /proc/<pid>/fd/ for symbolic links
// of the form "socket:[<inode>]".
//
// Cost: O(number of open file-descriptors across all running processes).
// To keep overhead low this is called only for newly-OPENED connections.

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"xdr-agent/internal/telemetry/process"
)

// ProcessInfo holds process metadata resolved from a socket inode.
type ProcessInfo struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Executable string `json:"executable"`
	EntityID   string `json:"entity_id,omitempty"`
}

// ResolveSocketInode walks /proc/<pid>/fd/ entries to find which process owns
// the socket with the given inode number.  Returns nil when:
//   - inode is 0 (not known)
//   - no process owns the socket (already exited, or insufficient permission)
//
// procRoot is normally "/proc"; can be overridden in tests.
func ResolveSocketInode(procRoot string, inode uint64) *ProcessInfo {
	if inode == 0 {
		return nil
	}

	want := fmt.Sprintf("socket:[%d]", inode)

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Only numeric directory names are PIDs.
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join(procRoot, entry.Name(), "fd")

		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// EPERM when scanning another user's process — skip silently.
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == want {
				return readProcessInfo(procRoot, pid)
			}
		}
	}

	return nil
}

// readProcessInfo reads the name and executable path for a PID from procfs.
func readProcessInfo(procRoot string, pid int) *ProcessInfo {
	info := &ProcessInfo{PID: pid}

	pidStr := strconv.Itoa(pid)

	// /proc/<pid>/comm — short process name (max 15 chars, no path)
	if comm, err := os.ReadFile(filepath.Join(procRoot, pidStr, "comm")); err == nil {
		info.Name = strings.TrimSpace(string(comm))
	}

	// /proc/<pid>/exe — symlink to the actual binary
	if exe, err := os.Readlink(filepath.Join(procRoot, pidStr, "exe")); err == nil {
		info.Executable = exe
	}

	return info
}

// buildSocketOwnerSnapshot batches attribution for every consumer of a socket
// generation. Shared descriptors use the first visible holder, as before.
func buildSocketOwnerSnapshot(procRoot, agentID string) map[uint64]*ProcessInfo {
	owners := make(map[uint64]*ProcessInfo)
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return owners
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		before, stable := processStartTicks(procRoot, pid)
		if !stable {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(procRoot, entry.Name(), "fd"))
		if err != nil {
			continue
		}
		var inodes []uint64
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(procRoot, entry.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := parseSocketInodeLink(link)
			if !ok || owners[inode] != nil {
				continue
			}
			inodes = append(inodes, inode)
		}
		if len(inodes) == 0 {
			continue
		}
		info := readProcessInfo(procRoot, pid)
		after, stable := processStartTicks(procRoot, pid)
		if !stable || before != after {
			continue
		}
		info.EntityID = process.EntityID(agentID, pid, after)
		for _, inode := range inodes {
			owners[inode] = info
		}
	}
	return owners
}

func processStartTicks(procRoot string, pid int) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return 0, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	return ticks, err == nil
}

func parseSocketInodeLink(link string) (uint64, bool) {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return 0, false
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
	inode, err := strconv.ParseUint(raw, 10, 64)
	return inode, err == nil && inode != 0
}

// usernameForUID resolves a UID to a login name by reading /etc/passwd.
// Falls back to the numeric UID string on any error.
//
// etcPasswd is normally "/etc/passwd"; can be overridden in tests.
func usernameForUID(etcPasswd string, uid int) string {
	// Prefer the standard library NSS-aware lookup which respects NSS
	// configuration (LDAP/SSSD/etc). Fall back to parsing /etc/passwd when
	// LookupId fails (e.g., static builds without cgo or restricted envs).
	uidStr := strconv.Itoa(uid)
	if u, err := user.LookupId(uidStr); err == nil {
		return u.Username
	}

	data, err := os.ReadFile(etcPasswd)
	if err != nil {
		return uidStr
	}

	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 3 {
			continue
		}
		if parts[2] == uidStr {
			return parts[0] // login name
		}
	}

	return uidStr
}
