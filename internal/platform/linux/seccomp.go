package linux

// Seccomp provides seccomp-BPF filter management for system call restriction.
//
// Used by prevention/exploit to restrict dangerous syscalls (ptrace, init_module, etc.)

// TODO: Implement seccomp wrapper
// - Build seccomp-BPF filters for specific syscall restrictions
// - Apply filters to child processes
// - Support: kill, errno, trace, log actions
// - Pre-built profiles: restrict-ptrace, restrict-module-loading
