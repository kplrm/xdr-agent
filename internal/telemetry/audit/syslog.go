package audit

// Syslog collects and parses system log messages from syslog/journald.

// TODO: Implement syslog collector
// - Read from journald via sd_journal API or journalctl --follow
// - Alternative: tail /var/log/syslog, /var/log/messages
// - Filter for security-relevant messages (auth, kernel, firewall)
// - Emit structured "audit.syslog" events
