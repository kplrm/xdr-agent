package linux

// Procfs provides utilities for reading data from the /proc filesystem.
// This is the primary interface for process and system information on Linux.

// TODO: Implement procfs utilities
// - ReadProcessInfo(pid) → exe, cmdline, cwd, uid, gid, ppid, stat
// - ListProcesses() → iterate /proc/[0-9]+/
// - ReadProcessMaps(pid) → parsed memory map entries
// - ReadProcessEnviron(pid) → environment variables (for LD_PRELOAD check)
// - ReadProcessFDs(pid) → open file descriptors
// - ReadSystemInfo() → kernel version, uptime, load average
