// Package agentlog captures runtime diagnostics for periodic log shipping.
package agentlog

import (
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/events"
)

// Writer keeps log output independent of network delivery. Shipper diagnostics
// remain in the local journal to avoid recursively generating log batches.
type Writer struct {
	mu                       sync.Mutex
	closed                   bool
	queue                    chan events.Event
	done                     chan struct{}
	agentID, hostname, level string
}

func NewWriter(level, agentID, hostname string, enqueue func(events.Event)) *Writer {
	w := &Writer{queue: make(chan events.Event, 1024), done: make(chan struct{}), agentID: agentID, hostname: hostname, level: strings.ToUpper(level)}
	go func() {
		defer close(w.done)
		for event := range w.queue {
			enqueue(event)
		}
	}()
	return w
}

func (w *Writer) Write(data []byte) (int, error) {
	message := strings.TrimSpace(string(data))
	if strings.Contains(message, "shipper") {
		return len(data), nil
	}
	level, severity := "INFO", events.SeverityInfo
	lower := strings.ToLower(message)
	if strings.Contains(lower, "error") || strings.Contains(lower, "failed") {
		level, severity = "ERROR", events.SeverityHigh
	} else if strings.Contains(lower, "warning") || strings.Contains(lower, "degraded") {
		level, severity = "WARN", events.SeverityMedium
	}
	if (w.level == "ERROR" && level != "ERROR") || (w.level == "WARN" && level == "INFO") {
		return len(data), nil
	}
	event := events.Event{
		Timestamp: time.Now().UTC(), Type: "agent.log", Category: "agent", Kind: "event",
		Module: "agent.logger", Severity: severity, AgentID: w.agentID, Hostname: w.hostname,
		Payload: map[string]interface{}{"message": message, "log.level": level},
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		select {
		case w.queue <- event:
		default:
		}
	}
	return len(data), nil
}

func (w *Writer) Close() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
	w.mu.Unlock()
	<-w.done
}
