package linux

// eBPF provides eBPF program loading and management for kernel-level telemetry.
//
// eBPF is the preferred method for deep system monitoring on modern Linux kernels.
// It provides kernel-level visibility with minimal performance overhead and
// strong safety guarantees (programs are verified before loading).
//
// Recommended Go library: cilium/ebpf or aquasecurity/libbpfgo

// TODO: Implement eBPF manager
// - Detect kernel eBPF support (kernel version, CONFIG_BPF, CAP_BPF)
// - Load pre-compiled eBPF programs (.o files)
// - Attach programs to tracepoints/kprobes
// - Read events from ring buffers
// - Graceful fallback if eBPF is unavailable
