// Package memory provides memory scanning and exploit detection capabilities.
//
// Key protection areas:
//   - Code injection (shellcode, SO injection via ptrace/LD_PRELOAD)
//   - Process hollowing (process memory replacement)
//   - Fileless malware (memfd_create, /dev/shm, anonymous memory execution)
//   - Exploit technique detection (ROP chains, heap spray, stack pivots)
package memory

import (
	"strings"

	"xdr-agent/internal/events"
)

type Finding struct {
	Matched     bool
	RuleID      string
	Name        string
	Description string
	Severity    events.Severity
}

type Scanner struct{}

func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Evaluate(event events.Event, enableInjection, enableHollowing, enableFileless bool) []Finding {
	findings := make([]Finding, 0, 3)
	payload := event.Payload
	if payload == nil {
		return findings
	}

	if enableInjection {
		if v, ok := payload["tracer_pid"]; ok {
			if n, ok := v.(float64); ok && n > 0 {
				findings = append(findings, Finding{
					Matched:     true,
					RuleID:      "memory.injection.ptrace",
					Name:        "Ptrace injection indicator",
					Description: "process has non-zero tracer pid",
					Severity:    events.SeverityHigh,
				})
			}
		}
	}

	cmd := payloadString(payload, "command_line", "process.command_line")
	path := payloadString(payload, "file_path", "process.executable")

	if enableFileless {
		lc := strings.ToLower(cmd + " " + path)
		if strings.Contains(lc, "/dev/shm") || strings.Contains(lc, "memfd:") || strings.Contains(lc, "/proc/self/fd/") {
			findings = append(findings, Finding{
				Matched:     true,
				RuleID:      "memory.fileless.execution",
				Name:        "Fileless execution indicator",
				Description: "command/executable suggests in-memory or shm execution",
				Severity:    events.SeverityHigh,
			})
		}
	}

	if enableHollowing {
		exe := payloadString(payload, "process.executable", "exe")
		if strings.Contains(strings.ToLower(exe), "(deleted)") {
			findings = append(findings, Finding{
				Matched:     true,
				RuleID:      "memory.hollowing.deleted_exe",
				Name:        "Process running from deleted executable",
				Description: "possible process replacement/hollowing",
				Severity:    events.SeverityMedium,
			})
		}
	}

	return findings
}

func payloadString(payload map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := payload[k]; ok {
			s, _ := v.(string)
			if s != "" {
				return s
			}
		}
	}
	return ""
}
