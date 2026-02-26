// Package process provides real-time process monitoring for the XDR agent.
//
// It detects process creation and termination events, builds process trees,
// and enriches process data with metadata (user, cwd, command-line, hashes).
//
// Linux implementation options (in order of preference):
//  1. eBPF tracepoints (sched_process_exec, sched_process_exit) - lowest overhead
//  2. Netlink process connector (PROC_EVENT_EXEC, PROC_EVENT_EXIT)
//  3. /proc filesystem polling - fallback for older kernels
package process

// Monitor tracks process creation and termination in real-time.
//
// TODO: Implement process monitor
// - Subscribe to process exec/exit events
// - Emit "process.start" and "process.end" events to pipeline
// - Collect: PID, PPID, UID, GID, executable path, command-line args, cwd
// - Calculate file hash of executable on first exec
