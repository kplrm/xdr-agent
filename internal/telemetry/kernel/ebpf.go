package kernel

// eBPF provides kernel-level telemetry using eBPF programs.
// eBPF is the preferred method for process, file, and network monitoring
// on modern Linux kernels (4.15+) due to its low overhead and safety guarantees.

// TODO: Implement eBPF telemetry manager
// - Load eBPF programs for key tracepoints/kprobes
// - Read events from eBPF ring buffers / perf buffers
// - Programs to implement:
//   * tracepoint/sched/sched_process_exec — process execution
//   * tracepoint/sched/sched_process_exit — process termination
//   * kprobe/tcp_connect — outbound TCP connections
//   * kprobe/inet_csk_accept — inbound TCP connections
//   * kprobe/do_init_module — kernel module loading
//   * tracepoint/syscalls/sys_enter_openat — file open (selective)
// - Use cilium/ebpf or libbpfgo Go library
// - Graceful fallback if kernel version < 4.15 or CAP_BPF unavailable
