package system

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

// ── SystemCollector tests ────────────────────────────────────────────────────

func TestSystemCollector_Name(t *testing.T) {
	c := NewSystemCollector(nil, "", "", 0)
	assertStr(t, "Name", c.Name(), "telemetry.system")
}

func TestSystemCollector_HealthTransitions(t *testing.T) {
	pipeline := events.NewPipeline(4096)
	c := NewSystemCollector(pipeline, "agent-1", "host-1", 5*time.Second)
	c.SetProcRoot(cpuFixtureA())
	c.SetMemPath(filepath.Join(testdataDir(), "meminfo"))

	if c.Health() != capability.HealthStopped {
		t.Fatalf("initial health = %v, want Stopped", c.Health())
	}

	if err := c.Init(capability.Dependencies{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if c.Health() != capability.HealthStarting {
		t.Fatalf("post-Init health = %v, want Starting", c.Health())
	}

	ctx, cancel := context.WithCancel(context.Background())
	go pipeline.Run(ctx)

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	h := c.Health()
	if h != capability.HealthRunning && h != capability.HealthDegraded {
		t.Errorf("post-Start health = %v, want Running or Degraded", h)
	}

	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.Health() != capability.HealthStopped {
		t.Fatalf("post-Stop health = %v, want Stopped", c.Health())
	}
	cancel()
}

func TestSystemCollector_DegradedOnBadPath(t *testing.T) {
	pipeline := events.NewPipeline(4096)
	c := NewSystemCollector(pipeline, "agent-1", "host-1", 5*time.Second)
	c.SetProcRoot("/nonexistent/path")
	c.SetMemPath("/nonexistent/meminfo")

	c.collectBaseline()
	if c.Health() != capability.HealthDegraded {
		t.Fatalf("health = %v, want Degraded", c.Health())
	}
}

func TestSystemCollector_BaselineEmitsMemoryOnly(t *testing.T) {
	pipeline := events.NewPipeline(4096)

	var received []events.Event
	var mu sync.Mutex
	pipeline.Subscribe(func(e events.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeline.Run(ctx)

	c := NewSystemCollector(pipeline, "test-agent", "test-host", 5*time.Second)
	c.SetProcRoot(cpuFixtureA())
	c.SetMemPath(filepath.Join(testdataDir(), "meminfo"))

	// Baseline should emit one system.metrics event with memory only (no CPU delta yet)
	c.collectBaseline()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 1 {
		t.Fatalf("expected 1 event after baseline, got %d", len(received))
	}

	evt := received[0]
	assertStr(t, "Type", evt.Type, "system.metrics")
	assertStr(t, "Category", evt.Category, "host")
	assertStr(t, "Kind", evt.Kind, "metric")
	assertStr(t, "Module", evt.Module, "telemetry.system")
	assertStr(t, "AgentID", evt.AgentID, "test-agent")

	sys, ok := evt.Payload["system"].(map[string]interface{})
	if !ok {
		t.Fatal("payload missing 'system' key")
	}

	// Should have memory
	mem, ok := sys["memory"].(map[string]interface{})
	if !ok {
		t.Fatal("payload missing 'system.memory' key")
	}
	totalBytes, ok := mem["total"].(uint64)
	if !ok || totalBytes == 0 {
		t.Error("total should be > 0")
	}

	// Should NOT have cpu (no delta available)
	if _, hasCpu := sys["cpu"]; hasCpu {
		t.Error("baseline event should NOT have 'system.cpu' key")
	}
}

func TestSystemCollector_EmitsCombinedEvent(t *testing.T) {
	pipeline := events.NewPipeline(4096)

	var received []events.Event
	var mu sync.Mutex
	pipeline.Subscribe(func(e events.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeline.Run(ctx)

	c := NewSystemCollector(pipeline, "test-agent", "test-host", 5*time.Second)
	c.SetProcRoot(cpuFixtureA())
	c.SetMemPath(filepath.Join(testdataDir(), "meminfo"))

	// Baseline (snapshot A) — emits 1 event (memory only)
	c.collectBaseline()

	// Switch to snapshot B and collect — should emit combined event + process events
	c.SetProcRoot(cpuFixtureB())
	c.collectAndEmit()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Expected: 1 baseline + 1 combined system.metrics + 2 process.cpu = 4
	var sysMetrics []events.Event
	var procCpuEvents []events.Event
	for _, e := range received {
		switch e.Type {
		case "system.metrics":
			sysMetrics = append(sysMetrics, e)
		case "process.cpu":
			procCpuEvents = append(procCpuEvents, e)
		}
	}

	if len(sysMetrics) != 2 {
		t.Fatalf("expected 2 system.metrics events (baseline+full), got %d", len(sysMetrics))
	}

	// ── Validate the combined (second) system.metrics event ──────────
	combined := sysMetrics[1]
	assertStr(t, "Type", combined.Type, "system.metrics")
	assertStr(t, "Category", combined.Category, "host")
	assertStr(t, "Module", combined.Module, "telemetry.system")

	sys := combined.Payload["system"].(map[string]interface{})

	// Memory assertions
	mem := sys["memory"].(map[string]interface{})
	totalBytes := mem["total"].(uint64)
	if totalBytes == 0 {
		t.Error("total should be > 0")
	}
	usedMap := mem["used"].(map[string]interface{})
	usedPct := usedMap["pct"].(float64)
	if usedPct <= 0 || usedPct > 100 {
		t.Errorf("used.pct = %.2f, want 0 < x <= 100", usedPct)
	}

	// CPU assertions
	cpu := sys["cpu"].(map[string]interface{})
	assertFloat(t, "total.pct", cpu["total"].(map[string]interface{})["pct"].(float64), 60.1, 0.2)
	assertFloat(t, "user.pct", cpu["user"].(map[string]interface{})["pct"].(float64), 49.3, 0.2)
	assertFloat(t, "system.pct", cpu["system"].(map[string]interface{})["pct"].(float64), 9.9, 0.2)
	assertInt(t, "cores", cpu["cores"].(int), 2)

	// Tags should include both memory and cpu
	tagSet := make(map[string]bool)
	for _, tag := range combined.Tags {
		tagSet[tag] = true
	}
	if !tagSet["memory"] {
		t.Error("combined event missing 'memory' tag")
	}
	if !tagSet["cpu"] {
		t.Error("combined event missing 'cpu' tag")
	}
	if !tagSet["system"] {
		t.Error("combined event missing 'system' tag")
	}

	// ── process.cpu events (same as before: firefox + nginx) ─────────
	if len(procCpuEvents) != 2 {
		t.Fatalf("expected 2 process.cpu events, got %d", len(procCpuEvents))
	}

	// Sorted by CPU% descending: firefox first
	ff := procCpuEvents[0].Payload["process"].(map[string]interface{})
	assertInt(t, "ff.pid", ff["pid"].(int), 1234)
	assertStr(t, "ff.name", ff["name"].(string), "firefox")
	assertFloat(t, "ff.cpu.pct", ff["cpu"].(map[string]interface{})["pct"].(float64), 49.3, 0.2)
	assertStr(t, "ff.command_line", ff["command_line"].(string), "/usr/lib/firefox/firefox --no-remote --profile /home/user/.mozilla")

	ng := procCpuEvents[1].Payload["process"].(map[string]interface{})
	assertInt(t, "ng.pid", ng["pid"].(int), 5678)
	assertFloat(t, "ng.cpu_pct", ng["cpu"].(map[string]interface{})["pct"].(float64), 7.4, 0.2)
}

func TestSystemCollector_MemFailCpuOk(t *testing.T) {
	pipeline := events.NewPipeline(4096)

	var received []events.Event
	var mu sync.Mutex
	pipeline.Subscribe(func(e events.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeline.Run(ctx)

	c := NewSystemCollector(pipeline, "test-agent", "test-host", 5*time.Second)
	c.SetProcRoot(cpuFixtureA())
	c.SetMemPath(filepath.Join(testdataDir(), "meminfo"))

	// Baseline
	c.collectBaseline()

	// Break memory path but keep CPU working
	c.SetMemPath("/nonexistent/meminfo")
	c.SetProcRoot(cpuFixtureB())
	c.collectAndEmit()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Should still emit a system.metrics event with CPU only
	var sysMetrics []events.Event
	for _, e := range received {
		if e.Type == "system.metrics" {
			sysMetrics = append(sysMetrics, e)
		}
	}

	if len(sysMetrics) < 2 {
		t.Fatalf("expected at least 2 system.metrics events, got %d", len(sysMetrics))
	}

	combined := sysMetrics[1]
	sys := combined.Payload["system"].(map[string]interface{})

	// Should have CPU
	if _, hasCpu := sys["cpu"]; !hasCpu {
		t.Error("expected 'system.cpu' when memory fails but CPU works")
	}
	// Should NOT have memory
	if _, hasMem := sys["memory"]; hasMem {
		t.Error("expected no 'system.memory' when memory path is invalid")
	}
}

func TestSystemCollector_CpuFailMemOk(t *testing.T) {
	pipeline := events.NewPipeline(4096)

	var received []events.Event
	var mu sync.Mutex
	pipeline.Subscribe(func(e events.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeline.Run(ctx)

	c := NewSystemCollector(pipeline, "test-agent", "test-host", 5*time.Second)
	c.SetProcRoot(cpuFixtureA())
	c.SetMemPath(filepath.Join(testdataDir(), "meminfo"))

	// Baseline
	c.collectBaseline()

	// Break CPU path but keep memory working
	c.SetProcRoot("/nonexistent/path")
	c.collectAndEmit()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	var sysMetrics []events.Event
	for _, e := range received {
		if e.Type == "system.metrics" {
			sysMetrics = append(sysMetrics, e)
		}
	}

	if len(sysMetrics) < 2 {
		t.Fatalf("expected at least 2 system.metrics events, got %d", len(sysMetrics))
	}

	combined := sysMetrics[1]
	sys := combined.Payload["system"].(map[string]interface{})

	// Should have memory
	if _, hasMem := sys["memory"]; !hasMem {
		t.Error("expected 'system.memory' when CPU fails but memory works")
	}
	// Should NOT have cpu (read failed)
	if _, hasCpu := sys["cpu"]; hasCpu {
		t.Error("expected no 'system.cpu' when CPU path is invalid")
	}
}
