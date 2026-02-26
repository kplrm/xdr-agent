package behavioral

// Credential detects credential access and theft attempts.
//
// Monitored activities:
//  - Reading /etc/shadow, /etc/passwd (by non-standard processes)
//  - Access to SSH private keys (~/.ssh/id_*)
//  - Access to browser credential stores
//  - Brute force detection (rapid failed auth attempts)
//  - Mimikatz-like tools (less relevant on Linux, but patterns exist)
//  - Credential harvesting from process memory
//  - Access to AWS/GCP/Azure credential files
//
// MITRE ATT&CK: T1003, T1552, T1110

// TODO: Implement credential access detection
// - Monitor file read events for sensitive credential files
// - Alert when non-standard processes read credential files
// - Track failed authentication attempts (from auth.log)
// - Detect credential file exfiltration (read + network connection)
