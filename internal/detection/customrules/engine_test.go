package customrules

import (
	"os"
	"path/filepath"
	"testing"

	"xdr-agent/internal/events"
)

func TestLoadRulesFromDirAndMatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "memory.yml")
	content := []byte(`rules:
  - id: memory_memfd_exec
    name: memfd execution pattern
    description: command line indicates memfd usage
    severity: high
    condition:
      event_type: process.start
      command_line: ".*memfd:.*"
    action: alert
    enabled: true
    tags: [memory]
  - id: disabled_rule
    name: disabled
    description: should not load
    severity: low
    condition:
      event_type: process.start
    action: alert
    enabled: false
`)
	if err := os.WriteFile(rulesPath, content, 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine error = %v", err)
	}

	event := events.Event{
		Type: "process.start",
		Payload: map[string]interface{}{
			"command_line": "python -c 'exec memfd:payload'",
		},
	}

	matches := engine.Match(event)
	if len(matches) != 1 {
		t.Fatalf("unexpected match count: got=%d want=1", len(matches))
	}
	if matches[0].ID != "memory_memfd_exec" {
		t.Fatalf("unexpected rule id: got=%q", matches[0].ID)
	}
	if matches[0].SeverityValue() != events.SeverityHigh {
		t.Fatalf("unexpected severity value: got=%s", matches[0].SeverityValue().String())
	}
}

func TestLoadRulesFromDirAndMatchNestedPayloadPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "memory.yml")
	content := []byte(`rules:
  - id: memory_nested_cmd
    name: nested payload match
    description: match process.command_line in nested payload map
    severity: medium
    condition:
      event_type: process.start
      command_line: ".*NESTED_MARKER.*"
    action: alert
    enabled: true
    tags: [memory]
`)
	if err := os.WriteFile(rulesPath, content, 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine error = %v", err)
	}

	event := events.Event{
		Type: "process.start",
		Payload: map[string]interface{}{
			"process": map[string]interface{}{
				"name":         "bash",
				"command_line": "bash -lc 'echo NESTED_MARKER'",
			},
		},
	}

	matches := engine.Match(event)
	if len(matches) != 1 {
		t.Fatalf("unexpected match count: got=%d want=1", len(matches))
	}
	if matches[0].ID != "memory_nested_cmd" {
		t.Fatalf("unexpected rule id: got=%q", matches[0].ID)
	}
}

func TestLoadRulesFromDir_InvalidRuleIsSkipped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "ransomware.yml")
	content := []byte(`rules:
  - id: bad_regex
    name: invalid
    description: invalid regex should fail load
    severity: high
    condition:
      event_type: file.rename
      file_path: "*["
    action: alert
    enabled: true
`)
	if err := os.WriteFile(rulesPath, content, 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine error = %v", err)
	}

	event := events.Event{
		Type: "file.rename",
		Payload: map[string]interface{}{
			"file_path": "abc.locked",
		},
	}

	if matches := engine.Match(event); len(matches) != 0 {
		t.Fatalf("invalid rule should be skipped, got %d matches", len(matches))
	}
}
