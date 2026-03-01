// Package file provides file system event monitoring and file integrity monitoring (FIM).
//
// Two operational modes are provided:
//
//  1. File Integrity Monitoring (implemented in fim.go):
//     - Real-time change detection via Linux inotify (IN_CLOSE_WRITE, IN_CREATE,
//     IN_DELETE, IN_MOVED_*, IN_ATTRIB)
//     - Periodic SHA-256 full tree rescan (default: every 1 hour) as ground truth
//     - Persistent baseline in BoltDB (/var/lib/xdr-agent/fim_baseline.db)
//     - ECS-compatible events: file.*, fim.* fields
//
//  2. Real-time File Access Monitoring (future — this file):
//     - fanotify: intercept file open/exec/write events at the kernel level
//     - Requires: root, CAP_SYS_ADMIN + CAP_SYS_PTRACE
//     - Emits: "file.open", "file.exec", "file.write" events with process context
//     - Enables: on-access malware scanning (deny mode via FAN_DENY)
//     - Integration: feeds into prevention/malware/blocker.go (Phase 4)
//
// Architecture notes:
//   - inotify (current): user-space, no process attribution, widely available,
//     works without root on accessible paths.
//   - fanotify (future): kernel-space, full process attribution (PID, exe),
//     supports block/deny, requires CAP_SYS_ADMIN.
//
// Phase 2 (current): inotify-based FIM — see FIMCollector in fim.go.
// Phase 4 (planned): fanotify-based real-time monitor + malware scanning.
package file

// TODO (Phase 4): Implement FileMonitor using fanotify
//
// type FileMonitor struct {
//     pipeline *events.Pipeline
//     ...
//     fanotifyFd int
// }
//
// func (m *FileMonitor) Name() string { return "telemetry.file.monitor" }
//
// Setup:
//   fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF | unix.FAN_REPORT_DFID_NAME | unix.FAN_CLOEXEC, unix.O_RDONLY)
//   unix.FanotifyMark(fd, unix.FAN_MARK_ADD | unix.FAN_MARK_MOUNT,
//       unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN_EXEC,
//       unix.AT_FDCWD, "/")
//
// Event loop reads fanotify_event_metadata from fd.
// For each event, read /proc/[pid]/exe for process attribution.
// Emit "file.open", "file.exec", "file.write" into pipeline.
//
// For malware scanning (Phase 4):
//   Use FAN_ACCESS_PERM / FAN_OPEN_PERM to intercept before allowing access.
//   Feed event into detection/malware scanner.
//   Send FAN_ALLOW or FAN_DENY back to kernel.
