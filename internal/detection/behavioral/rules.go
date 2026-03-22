package behavioral

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"xdr-agent/internal/events"

	"gopkg.in/yaml.v3"
)

type RuleAction string

const (
	ActionAlert      RuleAction = "alert"
	ActionBlock      RuleAction = "block"
	ActionQuarantine RuleAction = "quarantine"
)

type Rule struct {
	ID             string        `yaml:"id"`
	Name           string        `yaml:"name"`
	Description    string        `yaml:"description"`
	Severity       string        `yaml:"severity"`
	MitreTactic    string        `yaml:"mitre_tactic"`
	MitreTechnique string        `yaml:"mitre_technique"`
	Condition      RuleCondition `yaml:"condition"`
	Action         RuleAction    `yaml:"action"`
	Enabled        bool          `yaml:"enabled"`
	Tags           []string      `yaml:"tags"`

	compiled compiledRule `yaml:"-"`
}

type RuleCondition struct {
	EventType     string `yaml:"event_type"`
	ProcessName   string `yaml:"process_name"`
	ParentProcess string `yaml:"parent_process"`
	CommandLine   string `yaml:"command_line"`
	FilePath      string `yaml:"file_path"`
	NetworkDst    string `yaml:"network_destination"`
	User          string `yaml:"user"`
}

type rulesFile struct {
	Rules []Rule `yaml:"rules"`
}

type compiledRule struct {
	processNameRE   *regexp.Regexp
	parentProcessRE *regexp.Regexp
	commandLineRE   *regexp.Regexp
	filePathRE      *regexp.Regexp
	networkDstRE    *regexp.Regexp
	userRE          *regexp.Regexp
}

func LoadRulesFromDir(dir string) ([]Rule, error) {
	patterns := []string{"*.yml", "*.yaml"}
	collected := make([]Rule, 0, 64)

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, fmt.Errorf("glob behavioral rules: %w", err)
		}
		for _, path := range matches {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read rule file %s: %w", path, err)
			}

			var rf rulesFile
			if err := yaml.Unmarshal(content, &rf); err != nil {
				return nil, fmt.Errorf("parse rule file %s: %w", path, err)
			}

			for i := range rf.Rules {
				r := rf.Rules[i]
				if err := r.validate(); err != nil {
					return nil, fmt.Errorf("invalid rule %s in %s: %w", r.ID, path, err)
				}
				if !r.Enabled {
					continue
				}
				if err := r.compile(); err != nil {
					return nil, fmt.Errorf("compile rule %s in %s: %w", r.ID, path, err)
				}
				collected = append(collected, r)
			}
		}
	}

	return collected, nil
}

func (r Rule) SeverityValue() events.Severity {
	switch strings.ToLower(strings.TrimSpace(r.Severity)) {
	case "low":
		return events.SeverityLow
	case "medium":
		return events.SeverityMedium
	case "high":
		return events.SeverityHigh
	case "critical":
		return events.SeverityCritical
	default:
		return events.SeverityInfo
	}
}

func (r Rule) validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(r.Condition.EventType) == "" {
		return fmt.Errorf("condition.event_type is required")
	}
	if r.Action == "" {
		r.Action = ActionAlert
	}
	if r.Action != ActionAlert && r.Action != ActionBlock && r.Action != ActionQuarantine {
		return fmt.Errorf("unsupported action %q", r.Action)
	}
	return nil
}

func (r *Rule) compile() error {
	compileOpt := func(expr string) (*regexp.Regexp, error) {
		expr = strings.TrimSpace(expr)
		if expr == "" {
			return nil, nil
		}
		return regexp.Compile(expr)
	}

	var err error
	if r.compiled.processNameRE, err = compileOpt(r.Condition.ProcessName); err != nil {
		return fmt.Errorf("condition.process_name: %w", err)
	}
	if r.compiled.parentProcessRE, err = compileOpt(r.Condition.ParentProcess); err != nil {
		return fmt.Errorf("condition.parent_process: %w", err)
	}
	if r.compiled.commandLineRE, err = compileOpt(r.Condition.CommandLine); err != nil {
		return fmt.Errorf("condition.command_line: %w", err)
	}
	if r.compiled.filePathRE, err = compileOpt(r.Condition.FilePath); err != nil {
		return fmt.Errorf("condition.file_path: %w", err)
	}
	if r.compiled.networkDstRE, err = compileOpt(r.Condition.NetworkDst); err != nil {
		return fmt.Errorf("condition.network_destination: %w", err)
	}
	if r.compiled.userRE, err = compileOpt(r.Condition.User); err != nil {
		return fmt.Errorf("condition.user: %w", err)
	}

	return nil
}

func (r Rule) Match(event events.Event) bool {
	if event.Type != r.Condition.EventType {
		return false
	}

	payloadValue := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := event.Payload[k]; ok {
				s, _ := v.(string)
				if s != "" {
					return s
				}
			}
		}
		return ""
	}

	processName := payloadValue("process_name", "process.name")
	parentName := payloadValue("parent_process", "process.parent.name")
	commandLine := payloadValue("command_line", "process.command_line")
	filePath := payloadValue("file_path", "file.path")
	user := payloadValue("user", "user.name")
	networkDst := payloadValue("network_destination", "destination.ip", "destination.domain")

	if r.compiled.processNameRE != nil && !r.compiled.processNameRE.MatchString(processName) {
		return false
	}
	if r.compiled.parentProcessRE != nil && !r.compiled.parentProcessRE.MatchString(parentName) {
		return false
	}
	if r.compiled.commandLineRE != nil && !r.compiled.commandLineRE.MatchString(commandLine) {
		return false
	}
	if r.compiled.filePathRE != nil && !r.compiled.filePathRE.MatchString(filePath) {
		return false
	}
	if r.compiled.userRE != nil && !r.compiled.userRE.MatchString(user) {
		return false
	}
	if r.compiled.networkDstRE != nil && !r.compiled.networkDstRE.MatchString(networkDst) {
		return false
	}

	return true
}
