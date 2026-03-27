//go:build linux

package file

import (
	"fmt"
	"testing"
	"time"
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
