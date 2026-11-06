package authentication

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

func TestTailNewLinesRotationAndTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	write := func(path, text string, appendMode bool) {
		t.Helper()
		flag := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if appendMode {
			flag = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		file, err := os.OpenFile(path, flag, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString(text); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	line := "Mar  3 20:06:27 laptop sshd[42]: Failed password for root from 127.0.0.1 port 22 ssh2\n"
	write(path, strings.Repeat(line, 20)+"old incomplete", false)
	pipeline := events.NewPipeline(32)
	var received []events.Event
	pipeline.Subscribe(func(event events.Event) { received = append(received, event) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pipeline.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	collector := NewCollector(pipeline, "agent", "laptop")
	collector.path = path
	if err := collector.open(true); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if collector.file != nil {
			_ = collector.file.Close()
		}
	}()
	poll := func() {
		t.Helper()
		if err := collector.poll(); err != nil {
			t.Fatal(err)
		}
	}
	write(path, " completion\n"+line+line[:30], true)
	poll()
	write(path, line[30:], true)
	poll()
	// Continue reading the old descriptor during a rename and temporary missing path.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	write(path+".1", line, true)
	if err := collector.poll(); !os.IsNotExist(err) {
		t.Fatalf("expected missing replacement, got %v", err)
	}
	write(path, line+"Mar  3 20:06:27 laptop CRON[42]: ignored\n", false)
	poll()
	poll()
	// Copy-truncate starts again at byte zero without replaying the old baseline.
	write(path, line, false)
	poll()
	// An oversized record is discarded through its newline, then collection resumes.
	write(path, strings.Repeat("x", maxLine+1)+"\n"+line, true)
	poll()
	cancel()
	<-done
	if len(received) != 6 {
		t.Fatalf("received %d events, want 6", len(received))
	}
	ids := map[string]bool{}
	for _, event := range received {
		if event.Payload["event.original"] != strings.TrimSpace(line) {
			t.Fatalf("unexpected original: %#v", event.Payload["event.original"])
		}
		if event.ID == "" || ids[event.ID] {
			t.Fatalf("repeated records must have distinct queue IDs: %q", event.ID)
		}
		ids[event.ID] = true
	}
}

func TestMissingFileRecoversAndStops(t *testing.T) {
	collector := NewCollector(events.NewPipeline(4), "agent", "host")
	collector.path = filepath.Join(t.TempDir(), "auth.log")
	missingJournal := filepath.Join(t.TempDir(), "missing-journalctl")
	collector.journalCommand = func(ctx context.Context, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, missingJournal, args...)
	}
	if err := collector.Init(capability.Dependencies{}); err != nil {
		t.Fatal(err)
	}
	if err := collector.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer collector.Stop()
	if collector.Health() != capability.HealthDegraded {
		t.Fatal("missing source must report degraded health")
	}
	if err := os.WriteFile(collector.path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for collector.Health() != capability.HealthRunning && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if collector.Health() != capability.HealthRunning {
		t.Fatal("collector did not recover when auth.log appeared")
	}
	if err := collector.Stop(); err != nil {
		t.Fatal(err)
	}
	if collector.Health() != capability.HealthStopped {
		t.Fatal("collector did not stop")
	}
}
