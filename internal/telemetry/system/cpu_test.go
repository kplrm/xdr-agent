package system

import (
	"context"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

func cpuFixtureA() string { return filepath.Join(testdataDir(), "proc_cpu_a") }
func cpuFixtureB() string { return filepath.Join(testdataDir(), "proc_cpu_b") }

// ── helpers ──────────────────────────────────────────────────────────────────

func assertFloat(t *testing.T, name string, got, want, delta float64) {
	t.Helper()
	if math.Abs(got-want) > delta {
		t.Errorf("%s = %.4f, want %.4f (±%.4f)", name, got, want, delta)
	}
}

func assertInt(t *testing.T, name string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", name, got, want)
	}
}

func assertStr(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}

func assertBool(t *testing.T, name string, got, want bool) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

// ── Parsing tests ────────────────────────────────────────────────────────────

func TestReadSystemCpu(t *testing.T) {
	stats, err := ReadSystemCpu(cpuFixtureA())
	if err != nil {
		t.Fatalf("ReadSystemCpu: %v", err)
	}

	assertUint64(t, "User", stats.User, 10000)
	assertUint64(t, "Nice", stats.Nice, 200)
	assertUint64(t, "System", stats.System, 3000)
	assertUint64(t, "Idle", stats.Idle, 50000)
	assertUint64(t, "IOWait", stats.IOWait, 500)
	assertUint64(t, "IRQ", stats.IRQ, 0)
	assertUint64(t, "SoftIRQ", stats.SoftIRQ, 100)
	assertUint64(t, "Steal", stats.Steal, 0)
	assertUint64(t, "Total", stats.Total, 63800)
	assertInt(t, "Cores", stats.Cores, 2)
}

func TestReadSystemCpu_SnapshotB(t *testing.T) {
	stats, err := ReadSystemCpu(cpuFixtureB())
	if err != nil {
		t.Fatalf("ReadSystemCpu: %v", err)
	}

	assertUint64(t, "User", stats.User, 11000)
	assertUint64(t, "System", stats.System, 3200)
	assertUint64(t, "Total", stats.Total, 65830)
	assertInt(t, "Cores", stats.Cores, 2)
}

func TestReadSystemCpu_InvalidPath(t *testing.T) {
	_, err := ReadSystemCpu("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestReadProcessCpuTimes(t *testing.T) {
	procs, err := ReadProcessCpuTimes(cpuFixtureA())
	if err != nil {
		t.Fatalf("ReadProcessCpuTimes: %v", err)
	}
	if len(procs) != 3 {
		t.Fatalf("expected 3 processes, got %d", len(procs))
	}

	firefox := procs[1234]
	assertStr(t, "firefox.Name", firefox.Name, "firefox")
	assertUint64(t, "firefox.UTime", firefox.UTime, 5000)
	assertUint64(t, "firefox.STime", firefox.STime, 2000)

	nginx := procs[5678]
	assertStr(t, "nginx.Name", nginx.Name, "nginx")
	assertUint64(t, "nginx.UTime", nginx.UTime, 1000)
	assertUint64(t, "nginx.STime", nginx.STime, 500)

	python := procs[9999]
	assertStr(t, "python3.Name", python.Name, "python3")
	assertUint64(t, "python3.UTime", python.UTime, 3000)
	assertUint64(t, "python3.STime", python.STime, 1500)
}

func TestReadProcessCpuTimes_SnapshotB(t *testing.T) {
	procs, err := ReadProcessCpuTimes(cpuFixtureB())
	if err != nil {
		t.Fatalf("ReadProcessCpuTimes: %v", err)
	}
	if len(procs) != 2 {
		t.Fatalf("expected 2 processes, got %d", len(procs))
	}

	firefox := procs[1234]
	assertUint64(t, "firefox.UTime", firefox.UTime, 5800)
	assertUint64(t, "firefox.STime", firefox.STime, 2200)
}

func TestReadProcessCpuTimes_InvalidPath(t *testing.T) {
	_, err := ReadProcessCpuTimes("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestParseProcessStatCpu(t *testing.T) {
	snap, err := ParseProcessStatCpu(cpuFixtureA(), 1234)
	if err != nil {
		t.Fatalf("ParseProcessStatCpu: %v", err)
	}

	assertInt(t, "PID", snap.PID, 1234)
	assertStr(t, "Name", snap.Name, "firefox")
	assertUint64(t, "UTime", snap.UTime, 5000)
	assertUint64(t, "STime", snap.STime, 2000)
	// Executable falls back to name since there is no exe symlink in test data
	assertStr(t, "Executable", snap.Executable, "firefox")
	assertStr(t, "CommandLine", snap.CommandLine, "/usr/lib/firefox/firefox --no-remote --profile /home/user/.mozilla")
}

func TestParseProcessStatCpu_NonexistentPID(t *testing.T) {
	_, err := ParseProcessStatCpu(cpuFixtureA(), 42)
	if err == nil {
		t.Fatal("expected error for nonexistent PID")
	}
}

// ── Delta calculation tests ──────────────────────────────────────────────────

func TestCpuDelta(t *testing.T) {
	sysA, err := ReadSystemCpu(cpuFixtureA())
	if err != nil {
		t.Fatalf("ReadSystemCpu A: %v", err)
	}
	sysB, err := ReadSystemCpu(cpuFixtureB())
	if err != nil {
		t.Fatalf("ReadSystemCpu B: %v", err)
	}

	totalDelta := sysB.Total - sysA.Total
	assertUint64(t, "totalDelta", totalDelta, 2030)

	fd := float64(totalDelta)
	idlePct := float64(sysB.Idle-sysA.Idle) / fd * 100
	iowaitPct := float64(sysB.IOWait-sysA.IOWait) / fd * 100
	totalPct := 100.0 - idlePct - iowaitPct
	assertFloat(t, "totalPct", totalPct, 60.1, 0.1)

	userPct := float64(sysB.User-sysA.User) / fd * 100
	assertFloat(t, "userPct", userPct, 49.3, 0.1)

	systemPct := float64(sysB.System-sysA.System) / fd * 100
	assertFloat(t, "systemPct", systemPct, 9.9, 0.1)
}

func TestCpuDelta_PerProcess(t *testing.T) {
	sysA, err := ReadSystemCpu(cpuFixtureA())
	if err != nil {
		t.Fatalf("ReadSystemCpu A: %v", err)
	}
	sysB, err := ReadSystemCpu(cpuFixtureB())
	if err != nil {
		t.Fatalf("ReadSystemCpu B: %v", err)
	}
	procA, err := ReadProcessCpuTimes(cpuFixtureA())
	if err != nil {
		t.Fatalf("ReadProcessCpuTimes A: %v", err)
	}
	procB, err := ReadProcessCpuTimes(cpuFixtureB())
	if err != nil {
		t.Fatalf("ReadProcessCpuTimes B: %v", err)
	}

	totalDelta := float64(sysB.Total - sysA.Total)

	// firefox: utime 5000→5800 (+800), stime 2000→2200 (+200), total +1000
	ff := procB[1234]
	ffPrev := procA[1234]
	ffPct := float64((ff.UTime-ffPrev.UTime)+(ff.STime-ffPrev.STime)) / totalDelta * 100
	assertFloat(t, "firefox cpu_pct", ffPct, 49.3, 0.1)

	// nginx: utime 1000→1100 (+100), stime 500→550 (+50), total +150
	ng := procB[5678]
	ngPrev := procA[5678]
	ngPct := float64((ng.UTime-ngPrev.UTime)+(ng.STime-ngPrev.STime)) / totalDelta * 100
	assertFloat(t, "nginx cpu_pct", ngPct, 7.4, 0.1)

	// python3 disappeared — not in procB
	_, found := procB[9999]
	assertBool(t, "python3 in procB", found, false)
}

// ── Collector integration tests ──────────────────────────────────────────────

func TestCpuCollector_Name(t *testing.T) {
	c := NewCpuCollector(nil, "", "", 0)
	assertStr(t, "Name", c.Name(), "telemetry.system.cpu")
}

func TestCpuCollector_HealthTransitions(t *testing.T) {
	pipeline := events.NewPipeline(4096)
	c := NewCpuCollector(pipeline, "test-agent", "test-host", 5*time.Second)
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
	time.Sleep(50 * time.Millisecond)
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

func TestCpuCollector_DegradedOnBadPath(t *testing.T) {
	pipeline := events.NewPipeline(4096)
	c := NewCpuCollector(pipeline, "test-agent", "test-host", 5*time.Second)
	c.SetProcRoot("/nonexistent/path")

	c.collectBaseline()
	if c.Health() != capability.HealthDegraded {
		t.Fatalf("health = %v, want Degraded", c.Health())
	}
}

func TestCpuCollector_SkipsFirstCollection(t *testing.T) {
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

	c := NewCpuCollector(pipeline, "test-agent", "test-host", 5*time.Second)
	c.SetProcRoot(cpuFixtureA())

	// First collection only stores baseline — no events emitted.
	c.collectBaseline()
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 0 {
		t.Errorf("expected 0 events after baseline, got %d", len(received))
	}
}

func TestCpuCollector_EmitsEvents(t *testing.T) {
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

	c := NewCpuCollector(pipeline, "test-agent", "test-host", 5*time.Second)
	c.SetProcRoot(cpuFixtureA())

	// Baseline — no events
	c.collectBaseline()

	// Switch to snapshot B and collect — should emit events
	c.SetProcRoot(cpuFixtureB())
	c.collectAndEmit()

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Expect: 1 system.cpu event + 2 process.cpu events (firefox, nginx).
	// python3 (9999) was in A but not in B — skipped (no delta).
	if len(received) < 3 {
		t.Fatalf("expected >= 3 events, got %d", len(received))
	}

	var sysCpu *events.Event
	var procCpuEvents []events.Event
	for i := range received {
		switch received[i].Type {
		case "system.cpu":
			e := received[i]
			sysCpu = &e
		case "process.cpu":
			procCpuEvents = append(procCpuEvents, received[i])
		}
	}

	// ── system.cpu event assertions ──────────────────────────────────
	if sysCpu == nil {
		t.Fatal("no system.cpu event received")
	}
	assertStr(t, "Category", sysCpu.Category, "host")
	assertStr(t, "Kind", sysCpu.Kind, "metric")
	assertStr(t, "Module", sysCpu.Module, "telemetry.system.cpu")
	assertStr(t, "AgentID", sysCpu.AgentID, "test-agent")
	assertStr(t, "Hostname", sysCpu.Hostname, "test-host")

	cpuPayload := sysCpu.Payload["system"].(map[string]interface{})["cpu"].(map[string]interface{})
	assertFloat(t, "total.pct", cpuPayload["total"].(map[string]interface{})["pct"].(float64), 60.1, 0.2)
	assertFloat(t, "user.pct", cpuPayload["user"].(map[string]interface{})["pct"].(float64), 49.3, 0.2)
	assertFloat(t, "system.pct", cpuPayload["system"].(map[string]interface{})["pct"].(float64), 9.9, 0.2)
	assertInt(t, "cores", cpuPayload["cores"].(int), 2)

	// ── process.cpu event assertions ─────────────────────────────────
	if len(procCpuEvents) != 2 {
		t.Fatalf("expected 2 process.cpu events, got %d", len(procCpuEvents))
	}

	// Events are sorted by CPU% descending: firefox first, nginx second.
	ff := procCpuEvents[0]
	assertStr(t, "ff.Category", ff.Category, "process")
	assertStr(t, "ff.Kind", ff.Kind, "metric")
	ffProc := ff.Payload["process"].(map[string]interface{})
	assertInt(t, "ff.pid", ffProc["pid"].(int), 1234)
	assertStr(t, "ff.name", ffProc["name"].(string), "firefox")
	assertFloat(t, "ff.cpu.pct", ffProc["cpu"].(map[string]interface{})["pct"].(float64), 49.3, 0.2)
	assertStr(t, "ff.command_line", ffProc["command_line"].(string), "/usr/lib/firefox/firefox --no-remote --profile /home/user/.mozilla")

	ng := procCpuEvents[1]
	ngProc := ng.Payload["process"].(map[string]interface{})
	assertInt(t, "ng.pid", ngProc["pid"].(int), 5678)
	assertStr(t, "ng.name", ngProc["name"].(string), "nginx")
	assertFloat(t, "ng.cpu.pct", ngProc["cpu"].(map[string]interface{})["pct"].(float64), 7.4, 0.2)
	assertStr(t, "ng.command_line", ngProc["command_line"].(string), "/usr/sbin/nginx -g daemon off;")
}
