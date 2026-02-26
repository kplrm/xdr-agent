// Package file provides file system event monitoring and file integrity monitoring (FIM).
//
// Two operational modes:
//  1. Real-time monitoring — fanotify (for access/exec events) and inotify (for modifications)
//  2. File integrity monitoring — Periodic checksum verification of critical files
package file

// Monitor tracks file system events in real-time.

// TODO: Implement file monitor
// - Use fanotify for file open/exec/write events (requires root, CAP_SYS_ADMIN)
// - Use inotify for create/delete/modify/rename in watched directories
// - Emit "file.create", "file.modify", "file.delete", "file.rename" events
// - Configurable watch paths (default: /etc, /usr/bin, /usr/sbin, /tmp, /var/tmp)
