// Package session — privilege escalation events (sudo, su) are captured via
// auth log tailing in monitor.go (SessionCollector.parseAuthLine).
//
// Future work:
//   - Detect setuid/setgid calls via auditd or eBPF (kernel-level, no log dependency)
//   - Monitor Linux capabilities changes (setcap / capset syscall)
//   - Alert on unexpected privilege escalation patterns using rule engine
package session
