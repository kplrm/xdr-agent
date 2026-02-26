package response

// Remediate provides file-level response actions: delete, quarantine, and restore.

// TODO: Implement file remediation
// - Delete: securely remove file (overwrite + unlink)
// - Quarantine: move to encrypted quarantine vault (reuse prevention/malware/quarantine)
// - Restore: restore file from quarantine vault (for false positives)
// - Collect: copy file to staging area for forensic upload
// - Emit "response.file_remediate" events
