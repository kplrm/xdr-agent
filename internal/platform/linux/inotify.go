package linux

// Inotify provides file change notification using the Linux inotify API.
// Unlike fanotify, inotify watches specific files/directories and cannot
// respond with allow/deny. Used for FIM and scheduled task monitoring.

// TODO: Implement inotify wrapper
// - inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
// - inotify_add_watch() for each monitored path
// - Event types: IN_CREATE, IN_DELETE, IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO
// - Path resolution from watch descriptor
// - Support recursive directory watching
// - Handle watch limit (/proc/sys/fs/inotify/max_user_watches)
