// Package behavioral provides rule-based behavioral detection.
// It watches sequences and patterns of system events to detect attack techniques
// that may not involve known malware, such as living-off-the-land attacks,
// credential theft, lateral movement, and persistence installation.
//
// Inspired by: Elastic EQL, SIGMA rules, CrowdStrike IOA
package behavioral

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/events"
)

type Engine struct {
	rulesDir string
	reload   time.Duration

	mu              sync.RWMutex
	rules           []Rule
	lastRulesDigest string
}

func NewEngine(rulesDir string) (*Engine, error) {
	e := &Engine{
		rulesDir: rulesDir,
		reload:   30 * time.Second,
	}
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

	digest := behavioralRulesDigest(rules)
	e.mu.Lock()
	unchanged := e.lastRulesDigest != "" && e.lastRulesDigest == digest
	e.rules = rules
	e.lastRulesDigest = digest
	e.mu.Unlock()

	if !unchanged {
		log.Printf("behavioral: loaded %d rules from %s", len(rules), e.rulesDir)
	}
	return nil
}

func behavioralRulesDigest(rules []Rule) string {
	parts := make([]string, 0, len(rules))
	for _, rule := range rules {
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%t|%s",
			rule.ID,
			rule.Name,
			rule.Description,
			rule.Severity,
			rule.MitreTactic,
			rule.MitreTechnique,
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

func (e *Engine) StartAutoReload(ctx context.Context) {
	ticker := time.NewTicker(e.reload)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.Reload(); err != nil {
				log.Printf("behavioral: reload failed: %v", err)
			}
		}
	}
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
