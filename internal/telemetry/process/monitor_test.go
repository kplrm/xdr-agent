package process

import (
	"context"
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
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	return filepath.Join(repoRoot, "test", "testdata")
}

// ── ScanProcesses / ReadProcessInfo tests ───────────────────────────────────

func TestScanProcesses_Standard(t *testing.T) {
	root := filepath.Join(testdataDir(), "proc_snapshot_a")
	procs, err := ScanProcesses(root)
	if err != nil {
		t.Fatalf("ScanProcesses(%q): %v", root, err)
	}

	if len(procs) != 3 {
		t.Fatalf("expected 3 processes, got %d", len(procs))
	}

	// PID 1 — systemd
	p1, ok := procs[1]
	if !ok {
		t.Fatal("PID 1 not found")
	}
	assertEqual(t, "PID 1 Name", p1.Name, "systemd")
	assertIntEqual(t, "PID 1 PPID", p1.PPID, 0)
	assertEqual(t, "PID 1 State", p1.State, "S")
	assertIntEqual(t, "PID 1 UID", p1.UID, 0)
	assertIntEqual(t, "PID 1 Threads", p1.Threads, 1)
	assertUint64Equal(t, "PID 1 StartTime", p1.StartTime, 100)

	// PID 42 — sshd
	p42, ok := procs[42]
	if !ok {
		t.Fatal("PID 42 not found")
	}
	assertEqual(t, "PID 42 Name", p42.Name, "sshd")
	assertIntEqual(t, "PID 42 PPID", p42.PPID, 1)
	assertUint64Equal(t, "PID 42 StartTime", p42.StartTime, 500)

	// PID 200 — nginx
	p200, ok := procs[200]
	if !ok {
		t.Fatal("PID 200 not found")
	}
	assertEqual(t, "PID 200 Name", p200.Name, "nginx")
	assertIntEqual(t, "PID 200 UID", p200.UID, 33)
	assertIntEqual(t, "PID 200 GID", p200.GID, 33)
	assertIntEqual(t, "PID 200 Threads", p200.Threads, 4)
}

func TestScanProcesses_SnapshotB(t *testing.T) {
	root := filepath.Join(testdataDir(), "proc_snapshot_b")
	procs, err := ScanProcesses(root)
	if err != nil {
		t.Fatalf("ScanProcesses(%q): %v", root, err)
	}

	if len(procs) != 3 {
		t.Fatalf("expected 3 processes, got %d", len(procs))
	}

	// PID 42 should be absent, PID 300 should be present
	if _, ok := procs[42]; ok {
		t.Error("PID 42 should not exist in snapshot b")
	}

	p300, ok := procs[300]
	if !ok {
		t.Fatal("PID 300 not found")
	}
	assertEqual(t, "PID 300 Name", p300.Name, "bash")
	assertIntEqual(t, "PID 300 PPID", p300.PPID, 42)
	assertIntEqual(t, "PID 300 UID", p300.UID, 1000)
	assertIntEqual(t, "PID 300 GID", p300.GID, 1000)
	assertUint64Equal(t, "PID 300 StartTime", p300.StartTime, 1500)
}

func TestReadProcessInfo_CmdLine(t *testing.T) {
	root := filepath.Join(testdataDir(), "proc_snapshot_a")
	info, err := ReadProcessInfo(root, 42)
	if err != nil {
		t.Fatalf("ReadProcessInfo: %v", err)
	}

	if info.CmdLine == "" {
		t.Error("expected non-empty CmdLine")
	}
	if info.CmdLine != "/usr/sbin/sshd -D" {
		t.Errorf("CmdLine = %q, want %q", info.CmdLine, "/usr/sbin/sshd -D")
	}
}

func TestScanProcesses_NonexistentPath(t *testing.T) {
	_, err := ScanProcesses("/nonexistent/proc")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestReadProcessInfo_MissingPID(t *testing.T) {
	root := filepath.Join(testdataDir(), "proc_snapshot_a")
	_, err := ReadProcessInfo(root, 9999)
	if err == nil {
		t.Fatal("expected error for nonexistent PID")
	}
}

// ── Diff detection tests ────────────────────────────────────────────────────

func TestProcessDiff_DetectsNewAndGone(t *testing.T) {
	rootA := filepath.Join(testdataDir(), "proc_snapshot_a")
	rootB := filepath.Join(testdataDir(), "proc_snapshot_b")

	snapA, err := ScanProcesses(rootA)
	if err != nil {
		t.Fatalf("scan A: %v", err)
	}
	snapB, err := ScanProcesses(rootB)
	if err != nil {
		t.Fatalf("scan B: %v", err)
	}

	// New PIDs: present in B but not A
	var newPIDs []int
	for pid := range snapB {
		if _, existed := snapA[pid]; !existed {
			newPIDs = append(newPIDs, pid)
		}
	}

	// Gone PIDs: present in A but not B
	var gonePIDs []int
	for pid := range snapA {
		if _, exists := snapB[pid]; !exists {
			gonePIDs = append(gonePIDs, pid)
		}
	}

	if len(newPIDs) != 1 || newPIDs[0] != 300 {
		t.Errorf("expected new PID [300], got %v", newPIDs)
	}
	if len(gonePIDs) != 1 || gonePIDs[0] != 42 {
		t.Errorf("expected gone PID [42], got %v", gonePIDs)
	}
}

// ── ProcessCollector integration tests ──────────────────────────────────────

func TestProcessCollector_EmitsEvents(t *testing.T) {
	pipeline := events.NewPipeline(64)
	received := make(chan events.Event, 32)
	pipeline.Subscribe(func(e events.Event) {
		received <- e
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeline.Run(ctx)

	pc := NewProcessCollector(pipeline, "test-agent-001", "test-host", 100*time.Millisecond)
	// First scan establishes baseline with snapshot_a
	pc.SetProcRoot(filepath.Join(testdataDir(), "proc_snapshot_a"))

	if err := pc.Init(capability.Dependencies{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := pc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for baseline to establish
	time.Sleep(150 * time.Millisecond)

	// Switch to snapshot_b: PID 42 gone, PID 300 new
	pc.SetProcRoot(filepath.Join(testdataDir(), "proc_snapshot_b"))

	// Collect events from next scan
	var startEvents, endEvents []events.Event
	deadline := time.After(3 * time.Second)

	for {
		select {
		case evt := <-received:
			switch evt.Type {
			case "process.start":
				startEvents = append(startEvents, evt)
			case "process.end":
				endEvents = append(endEvents, evt)
			}
			if len(startEvents) >= 1 && len(endEvents) >= 1 {
				goto verify
			}
		case <-deadline:
			goto verify
		}
	}

verify:
	if len(startEvents) == 0 {
		t.Fatal("expected at least one process.start event")
	}
	if len(endEvents) == 0 {
		t.Fatal("expected at least one process.end event")
	}

	// Verify the start event is for PID 300
	found300 := false
	for _, evt := range startEvents {
		proc := evt.Payload["process"].(map[string]interface{})
		if proc["pid"].(int) == 300 {
			found300 = true
			assertEqual(t, "start event name", proc["name"].(string), "bash")
			assertIntEqual(t, "start event ppid", proc["ppid"].(int), 42)
		}
	}
	if !found300 {
		t.Error("no process.start event for PID 300")
	}

	// Verify the end event is for PID 42
	found42 := false
	for _, evt := range endEvents {
		proc := evt.Payload["process"].(map[string]interface{})
		if proc["pid"].(int) == 42 {
			found42 = true
			assertEqual(t, "end event name", proc["name"].(string), "sshd")
		}
	}
	if !found42 {
		t.Error("no process.end event for PID 42")
	}

	if err := pc.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestProcessCollector_Name(t *testing.T) {
	pc := NewProcessCollector(nil, "", "", 0)
	if pc.Name() != "telemetry.process" {
		t.Errorf("Name() = %q, want %q", pc.Name(), "telemetry.process")
	}
}

func TestProcessCollector_HealthTransitions(t *testing.T) {
	pc := NewProcessCollector(events.NewPipeline(8), "a", "h", time.Hour)

	if pc.Health() != capability.HealthStopped {
		t.Errorf("initial health = %v, want HealthStopped", pc.Health())
	}

	_ = pc.Init(capability.Dependencies{})
	if pc.Health() != capability.HealthStarting {
		t.Errorf("after Init health = %v, want HealthStarting", pc.Health())
	}

	ctx, cancel := context.WithCancel(context.Background())
	pc.SetProcRoot(filepath.Join(testdataDir(), "proc_snapshot_a"))
	_ = pc.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	if pc.Health() != capability.HealthRunning {
		t.Errorf("after Start health = %v, want HealthRunning", pc.Health())
	}

	cancel()
	_ = pc.Stop()
	if pc.Health() != capability.HealthStopped {
		t.Errorf("after Stop health = %v, want HealthStopped", pc.Health())
	}
}

func TestProcessCollector_DegradedOnBadPath(t *testing.T) {
	pipeline := events.NewPipeline(8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeline.Run(ctx)

	pc := NewProcessCollector(pipeline, "a", "h", 100*time.Millisecond)
	pc.SetProcRoot("/nonexistent/proc")

	_ = pc.Init(capability.Dependencies{})
	_ = pc.Start(ctx)
	time.Sleep(300 * time.Millisecond)

	if pc.Health() != capability.HealthDegraded {
		t.Errorf("health = %v, want HealthDegraded", pc.Health())
	}
	_ = pc.Stop()
}

// ── helpers ─────────────────────────────────────────────────────────────────

func assertEqual(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}

func assertIntEqual(t *testing.T, name string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", name, got, want)
	}
}

func assertUint64Equal(t *testing.T, name string, got, want uint64) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", name, got, want)
	}
}
