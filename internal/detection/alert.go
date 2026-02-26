package detection

import "xdr-agent/internal/events"

// AlertBuilder helps construct well-formed alert events with consistent fields.

// NewAlert creates a new alert event with standard fields populated.
func NewAlert(module, ruleName, ruleID, description string, severity events.Severity) events.Alert {
	return events.Alert{
		Event: events.Event{
			Type:     "alert",
			Kind:     "alert",
			Module:   module,
			Severity: severity,
		},
		RuleName:        ruleName,
		RuleID:          ruleID,
		RuleDescription: description,
	}
}
