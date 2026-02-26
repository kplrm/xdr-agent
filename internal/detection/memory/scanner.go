// Package memory provides memory scanning and exploit detection capabilities.
//
// Key protection areas:
//   - Code injection (shellcode, SO injection via ptrace/LD_PRELOAD)
//   - Process hollowing (process memory replacement)
//   - Fileless malware (memfd_create, /dev/shm, anonymous memory execution)
//   - Exploit technique detection (ROP chains, heap spray, stack pivots)
package memory

// Scanner orchestrates all memory and exploit detection methods.

// TODO: Implement memory scanner
// - Periodic scan of process memory maps (/proc/[pid]/maps)
// - Detect anonymous executable memory regions
// - Detect memory regions with both write and execute permissions (W^X violation)
// - Scan suspicious memory regions for known shellcode patterns
// - Integrate with process monitor for real-time triggering
