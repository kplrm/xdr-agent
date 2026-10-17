//go:build linux

package file

import (
	"context"
	"testing"
	"time"

	"xdr-agent/internal/events"
)

func TestShouldEmitPreservesRepeatedAccesses(t *testing.T) {
	collector := NewFileAccessCollector(nil, "agent", "host", []string{"/etc/shadow"})
	base := time.Unix(1000, 0).UTC()

	if !collector.shouldEmit(base) {
		t.Fatalf("expected first event to emit")
	}
	if !collector.shouldEmit(base.Add(time.Millisecond)) {
		t.Fatalf("a distinct access must not be suppressed by a path debounce")
	}
}

func TestShouldEmitBurstWindowCap(t *testing.T) {
	collector := NewFileAccessCollector(nil, "agent", "host", []string{"/etc/ssh"})
	base := time.Unix(2000, 0).UTC()

	for i := 0; i < fileAccessBurstMaxEvents; i++ {
		if !collector.shouldEmit(base.Add(100 * time.Millisecond)) {
			t.Fatalf("expected event %d to be emitted before burst cap", i)
		}
	}

	if collector.shouldEmit(base.Add(200 * time.Millisecond)) {
		t.Fatalf("expected event beyond burst cap to be suppressed")
	}

	if !collector.shouldEmit(base.Add(fileAccessBurstWindow + 100*time.Millisecond)) {
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
