package file

// FIM (File Integrity Monitoring) periodically computes checksums of critical
// system files and alerts on unauthorized changes.
//
// Inspired by: Wazuh syscheck, OSSEC FIM, AIDE, Tripwire

// TODO: Implement FIM
// - Baseline scan: compute SHA256 of all files in watched paths
// - Store baseline in local database (BoltDB or SQLite)
// - Periodic rescan at configurable interval
// - Compare checksums; emit "fim.changed", "fim.added", "fim.deleted" alerts
// - Track: path, size, permissions, owner, mtime, SHA256
// - Default watched paths: /etc/passwd, /etc/shadow, /etc/sudoers,
//   /etc/ssh/sshd_config, /usr/bin/*, /usr/sbin/*
