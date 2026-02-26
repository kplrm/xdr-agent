package memory

// Hollowing detects process hollowing / process replacement attacks.
//
// In process hollowing, an attacker:
//  1. Creates a legitimate process in suspended state
//  2. Unmaps the original code
//  3. Maps malicious code in its place
//  4. Resumes execution
//
// Detection approach on Linux:
//  - Compare /proc/[pid]/exe symlink target with actual memory-mapped executable
//  - Detect processes where /proc/[pid]/exe is "(deleted)" but process is running
//  - Monitor for suspicious ptrace sequences: ATTACH → POKETEXT → SETREGS → DETACH
//
// MITRE ATT&CK: T1055.012 (Process Hollowing)

// TODO: Implement process hollowing detection
// - Periodic scan comparing exe link vs memory maps
// - Alert on deleted-exe processes (running from deleted binary)
// - Correlate with ptrace activity
