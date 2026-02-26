package behavioral

// Persistence detects installation of persistence mechanisms.
//
// Monitored persistence vectors (Linux):
//  - Cron jobs: /etc/cron*, /var/spool/cron/
//  - Systemd services: /etc/systemd/system/, /usr/lib/systemd/system/
//  - Shell profiles: ~/.bashrc, ~/.profile, /etc/profile.d/
//  - SSH authorized_keys: ~/.ssh/authorized_keys
//  - Init scripts: /etc/init.d/
//  - LD_PRELOAD: /etc/ld.so.preload
//  - Kernel modules: /lib/modules/
//
// MITRE ATT&CK: T1053, T1543, T1546, T1547

// TODO: Implement persistence detection
// - Subscribe to file modification events for persistence paths
// - Alert when new cron job, systemd service, or authorized_key is added
// - Detect LD_PRELOAD injection
// - Detect modification of shell init files
// - Cross-reference with process tree (who created the persistence?)
