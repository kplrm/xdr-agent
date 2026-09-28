package events

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRecordDropRateLimitWindow(t *testing.T) {
	p := &Pipeline{}
	base := time.Unix(100, 0).UTC()

	first := p.recordDrop("file.access", base)
	if first == "" || !strings.Contains(first, "suppressing repeats") {
		t.Fatalf("expected initial suppression message, got %q", first)
	}

	second := p.recordDrop("file.access", base.Add(500*time.Millisecond))
	if second != "" {
		t.Fatalf("expected empty message inside suppression window, got %q", second)
	}

	third := p.recordDrop("process", base.Add(dropLogWindow+100*time.Millisecond))
	if third == "" || !strings.Contains(third, "dropped 2 events") {
		t.Fatalf("expected summary message after window rollover, got %q", third)
	}
	if !strings.Contains(third, "latest type=process") {
		t.Fatalf("expected latest type in rollover message, got %q", third)
	}
}

func TestShutdownDrainsAcceptedEvents(t *testing.T) {
	p := NewPipeline(16)
	for i := 0; i < 10; i++ {
		p.Emit(Event{Type: "fixture"})
	}
	count := 0
	p.Subscribe(func(e Event) {
		count++
		if e.ID == "" {
			t.Error("missing stable ID")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.Run(ctx)
	if count != 10 {
		t.Fatalf("lost %d events", 10-count)
	}
}
func TestSubscriberCanEmit(t *testing.T) {
	p := NewPipeline(16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	p.Subscribe(func(e Event) {
		if e.Type == "input" {
			p.Emit(Event{Type: "output"})
		} else {
			cancel()
		}
	})
	p.Emit(Event{Type: "input"})
	go func() { p.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recursive emit deadlocked")
	}
}
