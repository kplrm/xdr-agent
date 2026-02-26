package eventschema

// AlertEvent contains alert/detection-specific event fields.
type AlertEvent struct {
	RuleName        string `json:"rule.name"`
	RuleID          string `json:"rule.id"`
	RuleDescription string `json:"rule.description"`
	Severity        string `json:"event.severity_label"` // info, low, medium, high, critical
	Action          string `json:"event.action"`         // alert, block, quarantine, kill
	RiskScore       int    `json:"event.risk_score"`     // 0-100

	// MITRE ATT&CK mapping
	MitreTactic        string `json:"threat.tactic.name,omitempty"`
	MitreTechniqueID   string `json:"threat.technique.id,omitempty"`
	MitreTechniqueName string `json:"threat.technique.name,omitempty"`
}
