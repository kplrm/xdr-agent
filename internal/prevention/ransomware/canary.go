package ransomware

// Canary deploys and monitors honeypot files designed to detect ransomware activity.
//
// Strategy:
//  - Place decoy files in directories commonly targeted by ransomware
//  - File names are designed to be processed early in directory enumeration
//    (e.g., prefixed with "." or "0" to appear first in sorted listings)
//  - Any modification, rename, or deletion of a canary file is a strong
//    ransomware indicator and triggers immediate response
//
// Inspiration: CrowdStrike's canary file approach, Cybereason's RansomFree

// TODO: Implement canary file system
// - Deploy canary files with known content and checksums
// - Monitor canaries with inotify (IN_MODIFY, IN_DELETE, IN_MOVED_FROM)
// - On canary trigger: immediately alert + invoke ransomware response
// - Default deployment paths: /home/*/, /tmp/, /var/www/, /srv/
// - Canary file types: .docx, .xlsx, .pdf, .txt (common ransomware targets)
// - Verify canary integrity periodically
