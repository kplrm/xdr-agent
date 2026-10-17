package file

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

func newTestFIM(t *testing.T) (*FIMCollector, *events.Pipeline, string) {
	t.Helper()
	root := t.TempDir()
	watch := filepath.Join(root, "watched")
	if err := os.Mkdir(watch, 0700); err != nil {
		t.Fatal(err)
	}
	pipeline := events.NewPipeline(64)
	collector := NewFIMCollector(pipeline, "agent", "host", []WatchPath{{Path: watch, Recursive: true}}, time.Hour, filepath.Join(root, "baseline.db"))
	if err := collector.Init(capability.Dependencies{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = collector.Stop() })
	return collector, pipeline, watch
}

func drainFIMEvents(pipeline *events.Pipeline) []events.Event {
	var received []events.Event
	pipeline.Subscribe(func(event events.Event) { received = append(received, event) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pipeline.Run(ctx)
	return received
}

func TestFIMInotifyAndRescanShareBaseline(t *testing.T) {
	collector, pipeline, watch := newTestFIM(t)
	path := filepath.Join(watch, "settings")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	collector.runBaselineScan(context.Background())
	collector.onFileModified(path) // Opening for write alone is not an integrity change.
	collector.onFileAttrsChanged(path)
	if err := os.WriteFile(path, []byte("updated content"), 0600); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			collector.onFileModified(path)
			collector.runRescan(context.Background())
		}()
	}
	workers.Wait()
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	collector.onFileAttrsChanged(path)
	collector.runRescan(context.Background())
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	collector.onFileDeleted(path)
	collector.onFileDeleted(path)
	collector.runRescan(context.Background())
	received := drainFIMEvents(pipeline)
	want := []string{"file.modified", "file.attrs_changed", "file.deleted"}
	if len(received) != len(want) {
		t.Fatalf("observations emitted %d events, want %d: %+v", len(received), len(want), received)
	}
	for i, event := range received {
		if event.Type != want[i] {
			t.Errorf("event %d type = %q, want %q", i, event.Type, want[i])
		}
	}
}

func TestFIMRescanDeletionAndRecreation(t *testing.T) {
	collector, pipeline, watch := newTestFIM(t)
	path := filepath.Join(watch, "settings")
	if err := os.WriteFile(path, []byte("same content"), 0600); err != nil {
		t.Fatal(err)
	}
	collector.onFileCreated(path)
	collector.onFileCreated(path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	collector.runRescan(context.Background()) // Deletion must not write under a read transaction.
	if err := os.WriteFile(path, []byte("same content"), 0600); err != nil {
		t.Fatal(err)
	}
	collector.onFileCreated(path)
	collector.runRescan(context.Background())
	received := drainFIMEvents(pipeline)
	want := []string{"file.created", "file.deleted", "file.created"}
	if len(received) != len(want) {
		t.Fatalf("creation/deletion lifecycle = %+v", received)
	}
	for i, event := range received {
		if event.Type != want[i] {
			t.Errorf("event %d type = %q, want %q", i, event.Type, want[i])
		}
	}
}
