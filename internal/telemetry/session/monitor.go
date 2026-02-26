// Package session monitors user sessions, authentication events, and privilege changes.
package session

// Monitor tracks user logon/logoff events and session activity.

// TODO: Implement session monitor
// - Parse utmp/wtmp for login/logout events
// - Monitor /var/log/auth.log (Debian) or /var/log/secure (RHEL) for auth events
// - Detect su/sudo usage and privilege escalation
// - Emit "session.login", "session.logout", "session.su" events
