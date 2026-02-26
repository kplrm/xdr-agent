package linux

// Fanotify provides file access notification using the Linux fanotify API.
// fanotify allows monitoring file system events at the mount level and
// can respond with allow/deny decisions (for malware prevention).
//
// Requires: root or CAP_SYS_ADMIN
// Kernel requirement: >= 2.6.37 (basic), >= 5.1 (FAN_OPEN_EXEC_PERM)

// TODO: Implement fanotify wrapper
// - fanotify_init() with appropriate flags
// - fanotify_mark() to watch filesystem mounts
// - Event types:
//   * FAN_OPEN_PERM — file open with permission check (for blocking)
//   * FAN_OPEN_EXEC_PERM — file exec with permission check (for malware prevention)
//   * FAN_CLOSE_WRITE — file close after write (for scanning new files)
//   * FAN_ACCESS — file read access
// - Response: FAN_ALLOW or FAN_DENY
// - File descriptor → path resolution via /proc/self/fd/
