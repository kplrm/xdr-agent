// Package behavioral provides rule-based behavioral detection.
// It watches sequences and patterns of system events to detect attack techniques
// that may not involve known malware, such as living-off-the-land attacks,
// credential theft, lateral movement, and persistence installation.
//
// Inspired by: Elastic EQL, SIGMA rules, CrowdStrike IOA
package behavioral

import (
	"context"
	"log"
	"sync"
	"time"

	"xdr-agent/internal/events"
)

type Engine struct {
	rulesDir string
	reload   time.Duration

	mu    sync.RWMutex
	rules []Rule
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
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
	log.Printf("behavioral: loaded %d rules from %s", len(rules), e.rulesDir)
	return nil
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
