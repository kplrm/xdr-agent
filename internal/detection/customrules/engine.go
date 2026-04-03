package customrules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

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
	ID          string        `yaml:"id"`
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Severity    string        `yaml:"severity"`
	Condition   RuleCondition `yaml:"condition"`
	Action      RuleAction    `yaml:"action"`
	Enabled     bool          `yaml:"enabled"`
	Tags        []string      `yaml:"tags"`

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

type Engine struct {
	rulesDir string

	mu         sync.RWMutex
	rules      []Rule
	lastDigest string
}

func NewEngine(rulesDir string) (*Engine, error) {
	e := &Engine{rulesDir: rulesDir}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) Reload() error {
	rules, err := LoadRulesFromDir(e.rulesDir)
	if err != nil {
		return err
	}

	digest := rulesDigest(rules)
	e.mu.Lock()
	e.rules = rules
	e.lastDigest = digest
	e.mu.Unlock()
	return nil
}

func (e *Engine) Match(event events.Event) []Rule {
	e.mu.RLock()
	rules := make([]Rule, len(e.rules))
	copy(rules, e.rules)
	e.mu.RUnlock()

	matches := make([]Rule, 0, 4)
	for _, rule := range rules {
		if rule.Match(event) {
			matches = append(matches, rule)
		}
	}
	return matches
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

func (r Rule) Match(event events.Event) bool {
	if event.Type != r.Condition.EventType {
		return false
	}

	processName := payloadString(event.Payload, "process_name", "process.name")
	parentName := payloadString(event.Payload, "parent_process", "process.parent.name")
	commandLine := payloadString(event.Payload, "command_line", "process.command_line")
	filePath := payloadString(event.Payload, "file_path", "file.path", "process.executable")
	user := payloadString(event.Payload, "user", "user.name")
	networkDst := payloadString(event.Payload, "network_destination", "destination.ip", "destination.domain")

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

func LoadRulesFromDir(dir string) ([]Rule, error) {
	patterns := []string{"*.yml", "*.yaml"}
	collected := make([]Rule, 0, 64)

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, fmt.Errorf("glob custom rules: %w", err)
		}
		for _, path := range matches {
			content, err := os.ReadFile(path)
			if err != nil {
				log.Printf("warning: customrules: skipping unreadable rule file %s: %v", path, err)
				continue
			}

			var rf rulesFile
			if err := yaml.Unmarshal(content, &rf); err != nil {
				log.Printf("warning: customrules: skipping unparsable rule file %s: %v", path, err)
				continue
			}

			for i := range rf.Rules {
				r := rf.Rules[i]
				if err := r.validate(); err != nil {
					log.Printf("warning: customrules: skipping invalid rule %q in %s: %v", r.ID, path, err)
					continue
				}
				if !r.Enabled {
					continue
				}
				if err := r.compile(); err != nil {
					log.Printf("warning: customrules: skipping rule with invalid regex %q in %s: %v", r.ID, path, err)
					continue
				}
				collected = append(collected, r)
			}
		}
	}

	return collected, nil
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

func payloadString(payload map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := payload[k]; ok {
			s, _ := v.(string)
			if s != "" {
				return s
			}
		}

		if v, ok := payloadStringByPath(payload, k); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func payloadStringByPath(payload map[string]interface{}, path string) (string, bool) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "", false
	}

	var current interface{} = payload
	for _, part := range parts {
		switch node := current.(type) {
		case map[string]interface{}:
			next, ok := node[part]
			if !ok {
				return "", false
			}
			current = next
		default:
			return "", false
		}
	}

	switch value := current.(type) {
	case string:
		return value, true
	case fmt.Stringer:
		return value.String(), true
	case int:
		return strconv.Itoa(value), true
	case int64:
		return strconv.FormatInt(value, 10), true
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64), true
	case bool:
		if value {
			return "true", true
		}
		return "false", true
	default:
		return "", false
	}
}

func rulesDigest(rules []Rule) string {
	parts := make([]string, 0, len(rules))
	for _, rule := range rules {
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%t|%s",
			rule.ID,
			rule.Name,
			rule.Description,
			rule.Severity,
			rule.Condition.EventType,
			rule.Action,
			rule.Enabled,
			strings.Join(rule.Tags, ","),
		))
	}
	sort.Strings(parts)
	hash := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(hash[:])
}
