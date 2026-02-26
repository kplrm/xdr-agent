// Package behavioral provides rule-based behavioral detection.
// It watches sequences and patterns of system events to detect attack techniques
// that may not involve known malware, such as living-off-the-land attacks,
// credential theft, lateral movement, and persistence installation.
//
// Inspired by: Elastic EQL, SIGMA rules, CrowdStrike IOA
package behavioral

// Engine evaluates behavioral rules against incoming telemetry events.

// TODO: Implement behavioral engine
// - Load rules from rules/behavioral/*.yml
// - Support rule conditions: process name, command-line regex, parent process,
//   file path, network destination, user, sequence of events
// - Evaluate rules against each incoming telemetry event
// - Support stateful rules (correlate events over time windows)
// - Support SIGMA rule format (industry standard)
// - Emit alerts with MITRE ATT&CK mapping
