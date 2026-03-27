package events

import (
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
