package ruleformat

// SIGMA provides parsing for SIGMA rule format — the industry standard for
// sharing detection rules across SIEM/EDR platforms.
//
// SIGMA format: https://github.com/SigmaHQ/sigma-specification
//
// This allows importing the extensive SIGMA rule collection (~3000+ rules)
// into the XDR agent for immediate detection coverage.

// TODO: Implement SIGMA parser
// - Parse SIGMA YAML format
// - Convert SIGMA conditions to internal RuleCondition format
// - Support: process_creation, file_event, network_connection log sources
// - Handle SIGMA modifiers: contains, startswith, endswith, re, all, base64
// - Import from SigmaHQ repository
