package detection

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xdr-agent/internal/detection/malware"
	"xdr-agent/internal/events"
)

type recoveringScanner struct{ replies chan chan error }

func (s recoveringScanner) Executable() string { return "yara" }

func (s recoveringScanner) ScanFile(ctx context.Context, _ string) (malware.Result, error) {
	reply := make(chan error, 1)
	select {
	case s.replies <- reply:
	case <-ctx.Done():
		return malware.Result{}, ctx.Err()
	}
	select {
	case err := <-reply:
		return malware.Result{}, err
	case <-ctx.Done():
		return malware.Result{}, ctx.Err()
	}
}
func (s recoveringScanner) ScanOpenFile(context.Context, *os.File) (malware.Result, error) {
	return malware.Result{}, errors.New("unexpected execution scan")
}
func (s recoveringScanner) Close() error { return nil }

func TestSuccessfulScanRecoversYARAHealthWithoutClearingOtherFailures(t *testing.T) {
	scanner := recoveringScanner{replies: make(chan chan error)}
	engine := &Engine{scanner: scanner, pipeline: events.NewPipeline(8), queue: make(chan events.Event, 8),
		health: map[string]string{"yara": "running", "execution_blocking": "degraded: fixture"}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := engine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	for _, test := range []struct {
		err  error
		want string
	}{
		{errors.New("scan timeout"), "degraded: scan error"}, {nil, "running"},
	} {
		engine.queue <- events.Event{Category: "file", Payload: map[string]interface{}{"file": map[string]interface{}{"path": "fixture"}}}
		select {
		case reply := <-scanner.replies:
			reply <- test.err
		case <-ctx.Done():
			t.Fatal("scan did not start")
		}
		for engine.Health()["yara"] != test.want {
			select {
			case <-ctx.Done():
				t.Fatal("YARA health did not transition")
			case <-time.After(time.Millisecond):
			}
		}
	}
	if engine.Health()["execution_blocking"] != "degraded: fixture" {
		t.Fatal("unrelated health failure was cleared")
	}
}

func TestOwnExecutableIncludesSymlinks(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "yara")
	other := filepath.Join(dir, "other")
	alias := filepath.Join(dir, "alias")
	if err := os.WriteFile(helper, []byte("helper"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("other"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(helper, alias); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(helper)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{helperFiles: []os.FileInfo{info}}
	if !engine.isOwnExecutable(alias) || engine.isOwnExecutable(other) {
		t.Fatal("YARA helper exclusion failed")
	}
}

func TestYARAScanFilterKeepsChangesAndSkipsReads(t *testing.T) {
	for _, test := range []struct {
		typeName string
		category string
		want     bool
	}{
		{"file.access", "file", false},
		{"file.modified", "file", true},
		{"process.start", "process", true},
		{"process.end", "process", false},
	} {
		event := events.Event{Kind: "event", Category: test.category, Type: test.typeName, Module: "telemetry.file"}
		if got := shouldScanEvent(event); got != test.want {
			t.Errorf("scan %s: got %t, want %t", test.typeName, got, test.want)
		}
	}
}
