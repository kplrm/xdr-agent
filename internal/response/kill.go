package response

// Kill provides remote process termination capabilities.

// TODO: Implement process kill
// - Kill by PID: syscall.Kill(pid, SIGKILL)
// - Kill by process name: find matching PIDs → kill all
// - Kill process tree: find all descendants → kill bottom-up
// - Support SIGTERM (graceful) and SIGKILL (forced)
// - Emit "response.process_kill" event with details
// - Safety: refuse to kill critical system processes (PID 1, agent itself)
