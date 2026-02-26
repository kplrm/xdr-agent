package memory

// Injection detects code injection techniques.
//
// Linux injection vectors:
//  - ptrace(PTRACE_POKETEXT) — write shellcode into process memory
//  - ptrace(PTRACE_SETREGS) — hijack instruction pointer
//  - /proc/[pid]/mem writes — direct memory write
//  - LD_PRELOAD — force-load malicious shared library
//  - dlopen() from /dev/shm or /tmp — load SO from world-writable locations
//
// MITRE ATT&CK: T1055 (Process Injection)

// TODO: Implement injection detection
// - Monitor ptrace syscalls via auditd/eBPF
// - Check LD_PRELOAD environment variable for all processes
// - Monitor /proc/[pid]/maps for new anonymous executable regions
// - Alert on writes to /proc/[pid]/mem by other processes
// - Detect dlopen from suspicious paths (/dev/shm, /tmp, /var/tmp)
