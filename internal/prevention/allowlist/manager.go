// Package allowlist manages allow/block lists for exception handling across
// all prevention capabilities.
package allowlist

// Manager provides centralized allowlist/blocklist management.
//
// Exception types:
//  - Hash-based: Allow specific file SHA256 hashes (known false positives)
//  - Path-based: Exclude specific directories from scanning (e.g., build outputs)
//  - Process-based: Allow specific processes to perform otherwise-suspicious actions
//  - Signer-based: Trust files signed by specific certificates (future)
//
// Lists are managed via:
//  - Local configuration (config.json)
//  - Control plane policy push
//  - Manual CLI commands

// TODO: Implement allowlist manager
// - Support hash, path, and process-based exceptions
// - Load from config and policy
// - Provide IsAllowed(indicator) bool API for prevention modules
// - Support both allow (whitelist) and block (blacklist) modes
// - Audit log all exception evaluations
