package memory

// Fileless detects fileless malware execution techniques.
//
// Linux fileless techniques:
//  - memfd_create() — create anonymous file in memory, execute with fexecve()
//  - Execution from /dev/shm (shared memory filesystem, not persisted)
//  - Execution from /proc/self/fd/ pointing to deleted files
//  - Python/Perl inline execution of downloaded payloads (never touches disk)
//  - Execution from anonymous memory via ELF loading tricks
//
// MITRE ATT&CK: T1620 (Reflective Code Loading)

// TODO: Implement fileless malware detection
// - Monitor memfd_create syscall via auditd/eBPF
// - Detect execution from /dev/shm, /run/shm
// - Detect execution from /proc/self/fd where target is "(deleted)"
// - Alert on processes with no on-disk executable
// - Score based on: no disk file + network activity + suspicious behavior
