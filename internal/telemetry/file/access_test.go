//go:build linux

package file

import (
	"context"
	"fmt"
	"testing"
	"time"

	"xdr-agent/internal/events"
)

func TestShouldEmitPerPathDebounce(t *testing.T) {
	collector := NewFileAccessCollector(nil, "agent", "host", []string{"/etc/shadow"})
	base := time.Unix(1000, 0).UTC()

	if !collector.shouldEmit("/etc/shadow", base) {
		t.Fatalf("expected first event to emit")
	}
	if collector.shouldEmit("/etc/shadow", base.Add(500*time.Millisecond)) {
		t.Fatalf("expected duplicate access within debounce window to be suppressed")
	}
	if !collector.shouldEmit("/etc/shadow", base.Add(fileAccessPerPathMinInterval+100*time.Millisecond)) {
		t.Fatalf("expected event after debounce window to emit")
	}
}

func TestShouldEmitBurstWindowCap(t *testing.T) {
	collector := NewFileAccessCollector(nil, "agent", "host", []string{"/etc/ssh"})
	base := time.Unix(2000, 0).UTC()

	for i := 0; i < fileAccessBurstMaxEvents; i++ {
		path := fmt.Sprintf("/etc/ssh/file-%d", i)
		if !collector.shouldEmit(path, base.Add(100*time.Millisecond)) {
			t.Fatalf("expected event %d to be emitted before burst cap", i)
		}
	}

	if collector.shouldEmit("/etc/ssh/overflow", base.Add(200*time.Millisecond)) {
		t.Fatalf("expected event beyond burst cap to be suppressed")
	}

	if !collector.shouldEmit("/etc/ssh/new-window", base.Add(fileAccessBurstWindow+100*time.Millisecond)) {
		t.Fatalf("expected event to emit after burst window reset")
	}
}

func TestAccessEventUsesFileModuleAndAccessType(t *testing.T) {
	pipeline := events.NewPipeline(2)
	received := make(chan events.Event, 1)
	pipeline.Subscribe(func(event events.Event) { received <- event })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pipeline.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	collector := NewFileAccessCollector(pipeline, "agent", "host", []string{"/etc/shadow"})
	collector.emitAccessEvent("/etc/shadow")
	select {
	case event := <-received:
		if event.Module != "telemetry.file" || event.Type != "file.access" {
			t.Fatalf("access event module/type = %q/%q", event.Module, event.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("access event was not dispatched")
	}
}
