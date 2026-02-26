package behavioral

// Rule defines the format for behavioral detection rules.

// TODO: Implement rule types and loader
// - Rule schema:
//   * id: unique identifier
//   * name: human-readable name
//   * description: what the rule detects
//   * severity: info/low/medium/high/critical
//   * mitre_attack: tactic + technique IDs
//   * condition: matching criteria (process, file, network, sequence)
//   * action: alert | block | quarantine
//   * enabled: true/false
// - Load from YAML files in rules/behavioral/
// - Support hot-reload without restart
// - Validate rules at load time
