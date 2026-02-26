// Package prevention provides active threat blocking capabilities.
// Unlike detection (which only alerts), prevention actively blocks malicious
// activity in real-time — stopping malware execution, ransomware encryption,
// and exploit techniques before damage occurs.
//
// Sub-packages:
//   - malware/     — Block malware execution and quarantine malicious files
//   - ransomware/  — Ransomware-specific prevention (canaries, rollback)
//   - exploit/     — Memory and exploit protection enforcement
//   - allowlist/   — Allow/block list management for exception handling
package prevention

// Manager orchestrates all prevention sub-modules.

// TODO: Implement prevention manager
// - Subscribe to detection alerts
// - Apply blocking actions based on policy (detect vs. prevent mode)
// - Coordinate with response module for remediation
// - Log all prevention actions for audit trail
