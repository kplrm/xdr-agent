// Package scheduled monitors scheduled tasks (cron, at, systemd timers)
// for persistence detection.
package scheduled

// Tasks monitors creation and modification of scheduled tasks.

// TODO: Implement scheduled task monitor
// - Watch cron directories: /etc/cron.d/, /etc/cron.daily/, /var/spool/cron/
// - Watch systemd timer units: /etc/systemd/system/*.timer
// - Watch at jobs: /var/spool/at/
// - Use inotify for real-time change detection
// - Emit "scheduled.cron_modified", "scheduled.timer_created" events
// - MITRE ATT&CK: T1053 (Scheduled Task/Job)
