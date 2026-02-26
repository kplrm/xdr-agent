package container

// Drift detects runtime file changes in containers compared to their original image.
// In immutable infrastructure, any file modification at runtime is suspicious.

// TODO: Implement container drift detection
// - Capture filesystem snapshot from container image layers
// - Monitor runtime file modifications inside containers
// - Alert on new executables, modified system files, added users
// - Support allowlist for expected runtime changes (logs, temp files)
// - MITRE ATT&CK: T1610 (Deploy Container), T1611 (Escape to Host)
