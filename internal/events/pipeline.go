// Package events provides the central event pipeline for the XDR agent.
// All capabilities emit structured events (telemetry, alerts, compliance findings)
// into this pipeline, which handles enrichment, filtering, buffering, and shipping
// to the control plane.
package events

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

const dropLogWindow = 5 * time.Second

// Pipeline is the central event bus for the XDR agent.
// Capabilities publish events; the shipper consumes them.
type Pipeline struct {
	ch     chan Event
	subs   []func(Event)
	mu     sync.RWMutex
	closed bool

	dropMu      sync.Mutex
	dropFrom    time.Time
	dropCount   int
	dropLastTyp string
}

// NewPipeline creates a new event pipeline with the given buffer size.
func NewPipeline(bufferSize int) *Pipeline {
	if bufferSize <= 0 {
		bufferSize = 4096
	}
	return &Pipeline{
		ch: make(chan Event, bufferSize),
	}
}

// Emit publishes an event to the pipeline. Non-blocking if buffer is not full.
func (p *Pipeline) Emit(event Event) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return
	}

	select {
	case p.ch <- event:
	default:
		if msg := p.recordDrop(event.Type, time.Now()); msg != "" {
			log.Print(msg)
		}
	}
}

func (p *Pipeline) recordDrop(eventType string, now time.Time) string {
	p.dropMu.Lock()
	defer p.dropMu.Unlock()

	if p.dropFrom.IsZero() {
		p.dropFrom = now
		p.dropCount = 1
		p.dropLastTyp = eventType
		return fmt.Sprintf("event pipeline buffer full, dropping events (suppressing repeats for %s, latest type=%s)", dropLogWindow, eventType)
	}

	if now.Sub(p.dropFrom) < dropLogWindow {
		p.dropCount++
		p.dropLastTyp = eventType
		return ""
	}

	prevCount := p.dropCount
	prevType := p.dropLastTyp
	p.dropFrom = now
	p.dropCount = 1
	p.dropLastTyp = eventType

	return fmt.Sprintf(
		"event pipeline buffer full, dropped %d events in last %s (latest type=%s); continuing to drop (latest type=%s)",
		prevCount,
		dropLogWindow,
		prevType,
		eventType,
	)
}

// Subscribe registers a handler that will receive all events.
func (p *Pipeline) Subscribe(handler func(Event)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subs = append(p.subs, handler)
}

// Run starts dispatching events to subscribers. Blocks until ctx is canceled.
func (p *Pipeline) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			p.mu.Lock()
			p.closed = true
			close(p.ch)
			p.mu.Unlock()
			return
		case event, ok := <-p.ch:
			if !ok {
				return
			}
			p.mu.RLock()
			for _, sub := range p.subs {
				sub(event)
			}
			p.mu.RUnlock()
		}
	}
}
