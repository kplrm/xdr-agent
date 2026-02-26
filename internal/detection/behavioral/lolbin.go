package behavioral

// LOLBin (Living Off The Land Binary) detection identifies abuse of legitimate
// system tools for malicious purposes.
//
// Common Linux LOLBins:
//  - curl/wget — Download payloads
//  - python/python3/perl/ruby — Execute inline scripts
//  - bash -c, sh -c — Execute encoded/obfuscated commands
//  - nc/ncat/socat — Reverse shells, data exfiltration
//  - openssl — Encrypted C2
//  - base64 — Decode obfuscated payloads
//  - chmod +x — Make downloaded files executable
//  - crontab — Install persistence
//  - ssh — Tunneling, lateral movement
//  - dd — Disk/MBR modification
//  - nsenter/unshare — Container escape
//
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter)

// TODO: Implement LOLBin detection
// - Match process exec events against LOLBin database
// - Evaluate context: parent process, command-line args, network after exec
// - Examples:
//   * "httpd spawns curl downloading to /tmp" — suspicious
//   * "cron runs python with -c inline script" — suspicious
//   * "user runs curl to install software" — likely benign (configurable)
// - Risk scoring based on combination of indicators
