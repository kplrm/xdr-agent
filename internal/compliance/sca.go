package compliance

// SCA (Security Configuration Assessment) checks endpoint security settings.
//
// Checks include:
//  - SSH configuration: disable root login, enforce key-based auth, strong ciphers
//  - Firewall: iptables/nftables/ufw active with default deny
//  - User management: no empty passwords, proper password policy
//  - File permissions: /etc/shadow, /etc/passwd, /etc/gshadow, sudoers
//  - Service management: disable unnecessary services
//  - Logging: auditd active, syslog configured, log rotation

// TODO: Implement SCA
// - Load check definitions from rules/compliance/*.yml
// - Check categories: network, authentication, filesystem, services, logging
// - Support: file content checks, command output checks, file permission checks
// - Report findings with severity and remediation guidance
