package system

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

// testdataDir returns the absolute path to test/testdata/ relative to the repo root.
func testdataDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile = .../internal/telemetry/system/memory_test.go
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	return filepath.Join(repoRoot, "test", "testdata")
}

// ── ReadMemoryInfo / ParseMeminfo tests ─────────────────────────────────────

func TestReadMemoryInfo_Standard(t *testing.T) {
	path := filepath.Join(testdataDir(), "meminfo")
	info, err := ReadMemoryInfo(path)
	if err != nil {
		t.Fatalf("ReadMemoryInfo(%q): %v", path, err)
	}

	// Values from test/testdata/meminfo (all in kB, converted to bytes)
	expectTotal := uint64(16384000) * 1024
	expectFree := uint64(4194304) * 1024
	expectAvailable := uint64(12288000) * 1024
	expectBuffers := uint64(524288) * 1024
	expectCached := uint64(4096000) * 1024
	expectSwapTotal := uint64(8192000) * 1024
	expectSwapFree := uint64(7168000) * 1024

	assertUint64(t, "TotalBytes", info.TotalBytes, expectTotal)
	assertUint64(t, "FreeBytes", info.FreeBytes, expectFree)
	assertUint64(t, "AvailableBytes", info.AvailableBytes, expectAvailable)
	assertUint64(t, "BuffersBytes", info.BuffersBytes, expectBuffers)
	assertUint64(t, "CachedBytes", info.CachedBytes, expectCached)
	assertUint64(t, "SwapTotalBytes", info.SwapTotalBytes, expectSwapTotal)
	assertUint64(t, "SwapFreeBytes", info.SwapFreeBytes, expectSwapFree)

	// Used = Total - Free - Buffers - Cached
	expectUsed := expectTotal - expectFree - expectBuffers - expectCached
	assertUint64(t, "UsedBytes", info.UsedBytes, expectUsed)

	// SwapUsed = SwapTotal - SwapFree
	expectSwapUsed := expectSwapTotal - expectSwapFree
	assertUint64(t, "SwapUsedBytes", info.SwapUsedBytes, expectSwapUsed)

	// UsedPercent
	expectPercent := float64(expectUsed) / float64(expectTotal) * 100.0
	if math.Abs(info.UsedPercent-expectPercent) > 0.01 {
		t.Errorf("UsedPercent = %.2f, want %.2f", info.UsedPercent, expectPercent)
	}
}

func TestReadMemoryInfo_LowMemory(t *testing.T) {
	path := filepath.Join(testdataDir(), "meminfo_low")
	info, err := ReadMemoryInfo(path)
	if err != nil {
		t.Fatalf("ReadMemoryInfo(%q): %v", path, err)
	}

	expectTotal := uint64(2048000) * 1024
	expectFree := uint64(102400) * 1024
	expectBuffers := uint64(51200) * 1024
	expectCached := uint64(102400) * 1024
	expectUsed := expectTotal - expectFree - expectBuffers - expectCached

	assertUint64(t, "TotalBytes", info.TotalBytes, expectTotal)
	assertUint64(t, "UsedBytes", info.UsedBytes, expectUsed)

	// Swap should be fully used
	expectSwapTotal := uint64(1024000) * 1024
	assertUint64(t, "SwapTotalBytes", info.SwapTotalBytes, expectSwapTotal)
	assertUint64(t, "SwapFreeBytes", info.SwapFreeBytes, 0)
	assertUint64(t, "SwapUsedBytes", info.SwapUsedBytes, expectSwapTotal)

	// High memory usage
	if info.UsedPercent < 80.0 {
		t.Errorf("expected UsedPercent > 80%%, got %.2f%%", info.UsedPercent)
	}
}

func TestReadMemoryInfo_NoSwap(t *testing.T) {
	path := filepath.Join(testdataDir(), "meminfo_no_swap")
	info, err := ReadMemoryInfo(path)
	if err != nil {
		t.Fatalf("ReadMemoryInfo(%q): %v", path, err)
	}

	assertUint64(t, "SwapTotalBytes", info.SwapTotalBytes, 0)
	assertUint64(t, "SwapFreeBytes", info.SwapFreeBytes, 0)
	assertUint64(t, "SwapUsedBytes", info.SwapUsedBytes, 0)

	// Low memory usage
	if info.UsedPercent > 10.0 {
		t.Errorf("expected UsedPercent < 10%%, got %.2f%%", info.UsedPercent)
	}
}

func TestReadMemoryInfo_FileNotFound(t *testing.T) {
	_, err := ReadMemoryInfo("/nonexistent/path/meminfo")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestReadMemoryInfo_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "meminfo_empty")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := ReadMemoryInfo(path)
	if err != nil {
		t.Fatalf("unexpected error for empty file: %v", err)
	}
	// All fields should be zero
	assertUint64(t, "TotalBytes", info.TotalBytes, 0)
	assertUint64(t, "FreeBytes", info.FreeBytes, 0)
	assertUint64(t, "UsedBytes", info.UsedBytes, 0)
}

func TestReadMemoryInfo_MalformedLines(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "meminfo_bad")
	content := "MemTotal:       notanumber kB\nMemFree:        1024 kB\ngarbage line\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := ReadMemoryInfo(path)
	if err != nil {
		t.Fatalf("unexpected error for malformed file: %v", err)
	}
	assertUint64(t, "TotalBytes", info.TotalBytes, 0)
	assertUint64(t, "FreeBytes", info.FreeBytes, 1024*1024)
}

// ── MemoryCollector integration tests ───────────────────────────────────────

func TestMemoryCollector_EmitsEvent(t *testing.T) {
	pipeline := events.NewPipeline(64)
	received := make(chan events.Event, 8)
	pipeline.Subscribe(func(e events.Event) {
		received <- e
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeline.Run(ctx)

	mc := NewMemoryCollector(pipeline, "test-agent-001", "test-host", 100*time.Millisecond)
	mc.SetProcPath(filepath.Join(testdataDir(), "meminfo"))

	if err := mc.Init(capability.Dependencies{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := mc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for at least one event
	select {
	case evt := <-received:
		if evt.Type != "system.memory" {
			t.Errorf("event.Type = %q, want %q", evt.Type, "system.memory")
		}
		if evt.Kind != "metric" {
			t.Errorf("event.Kind = %q, want %q", evt.Kind, "metric")
		}
		if evt.Category != "host" {
			t.Errorf("event.Category = %q, want %q", evt.Category, "host")
		}
		if evt.AgentID != "test-agent-001" {
			t.Errorf("event.AgentID = %q, want %q", evt.AgentID, "test-agent-001")
		}
		if evt.Module != "telemetry.system.memory" {
			t.Errorf("event.Module = %q, want %q", evt.Module, "telemetry.system.memory")
		}

		// Verify payload structure
		sys, ok := evt.Payload["system"].(map[string]interface{})
		if !ok {
			t.Fatal("payload missing 'system' key")
		}
		mem, ok := sys["memory"].(map[string]interface{})
		if !ok {
			t.Fatal("payload missing 'system.memory' key")
		}
		totalBytes, ok := mem["total"].(uint64)
		if !ok {
			t.Fatal("payload missing 'system.memory.total'")
		}
		if totalBytes == 0 {
			t.Error("total should be > 0")
		}

	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for memory event")
	}

	if err := mc.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if mc.Health() != capability.HealthStopped {
		t.Errorf("health = %v, want %v", mc.Health(), capability.HealthStopped)
	}
}

func TestMemoryCollector_Name(t *testing.T) {
	mc := NewMemoryCollector(nil, "", "", 0)
	if mc.Name() != "telemetry.system.memory" {
		t.Errorf("Name() = %q, want %q", mc.Name(), "telemetry.system.memory")
	}
}

func TestMemoryCollector_HealthTransitions(t *testing.T) {
	mc := NewMemoryCollector(events.NewPipeline(8), "a", "h", time.Hour)

	if mc.Health() != capability.HealthStopped {
		t.Errorf("initial health = %v, want HealthStopped", mc.Health())
	}

	_ = mc.Init(capability.Dependencies{})
	if mc.Health() != capability.HealthStarting {
		t.Errorf("after Init health = %v, want HealthStarting", mc.Health())
	}

	ctx, cancel := context.WithCancel(context.Background())
	mc.SetProcPath(filepath.Join(testdataDir(), "meminfo"))
	_ = mc.Start(ctx)
	time.Sleep(200 * time.Millisecond) // let the goroutine start + collect once

	if mc.Health() != capability.HealthRunning {
		t.Errorf("after Start health = %v, want HealthRunning", mc.Health())
	}

	cancel()
	_ = mc.Stop()
	if mc.Health() != capability.HealthStopped {
		t.Errorf("after Stop health = %v, want HealthStopped", mc.Health())
	}
}

func TestMemoryCollector_DegradedOnBadPath(t *testing.T) {
	pipeline := events.NewPipeline(8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeline.Run(ctx)

	mc := NewMemoryCollector(pipeline, "a", "h", 100*time.Millisecond)
	mc.SetProcPath("/nonexistent/meminfo")

	_ = mc.Init(capability.Dependencies{})
	_ = mc.Start(ctx)
	time.Sleep(300 * time.Millisecond) // let it fail to read

	if mc.Health() != capability.HealthDegraded {
		t.Errorf("health = %v, want HealthDegraded", mc.Health())
	}
	_ = mc.Stop()
}

// ── helpers ─────────────────────────────────────────────────────────────────

func assertUint64(t *testing.T, name string, got, want uint64) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", name, got, want)
	}
}
