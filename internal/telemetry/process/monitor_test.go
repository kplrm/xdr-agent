package process

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestProcessEntityIDsUseAgentIdentity(t *testing.T) {
	const processID = "0875e38fab7155a1a57e77d53c73dcdfae2ab48989e9933d721981717666d372"
	const parentID = "1d93c001a6edbf2eb09b6fde4ea9408c276e5cb5eae1aa81de7deb1a7e6250c6"
	for _, test := range []struct {
		agentID, hostname string
		wantID            string
	}{
		{"test-agent-001", "host-a", processID},
		{"test-agent-001", "host-b", processID},
		{"different-agent", "host-a", ""},
	} {
		pipeline := events.NewPipeline(8)
		collector := NewProcessCollector(pipeline, test.agentID, test.hostname, 0)
		parent := ProcessInfo{PID: 1, StartTime: 100}
		info := ProcessInfo{PID: 42, PPID: 1, SessionID: 1, StartTime: 500}
		collector.tree.Update(parent)
		collector.tree.Update(info)
		collector.emitEvent("process.start", info, 0)
		event := queuedEvents(pipeline)[0]
		process := event.Payload["process"].(map[string]interface{})
		if test.wantID == "" {
			if got := process["entity_id"].(string); len(got) != 64 || got == processID {
				t.Fatalf("Agent ID did not scope full entity ID: %q", got)
			}
			continue
		}
		assertEqual(t, "process entity ID", process["entity_id"].(string), processID)
		assertEqual(t, "parent entity ID", process["parent"].(map[string]interface{})["entity_id"].(string), parentID)
		assertEqual(t, "ancestor entity ID", process["ancestors"].([]map[string]interface{})[0]["entity_id"].(string), parentID)
		assertEqual(t, "session leader entity ID", process["group_leader"].(map[string]interface{})["entity_id"].(string), parentID)
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var encoded map[string]interface{}
		if err := json.Unmarshal(body, &encoded); err != nil {
			t.Fatal(err)
		}
		if severity, ok := encoded["event.severity"]; !ok || severity != float64(0) {
			t.Fatalf("informational severity was not retained: %s", body)
		}
	}
	if buildEntityID("test-agent-001", 43, 500) == processID || buildEntityID("test-agent-001", 42, 501) == processID {
		t.Fatal("process identity ignored PID or start ticks")
	}
}

func TestKernelThreadsKeepLineageWithoutEnrichmentOrEvents(t *testing.T) {
	root := t.TempDir()
	writeProcessStat(t, root, 2, 0, "kthreadd", pfKernelThread)
	pidDir := filepath.Join(root, "2")
	for name, value := range map[string]string{
		"status":  "Uid:\t123 123 123 123\nThreads:\t9\nVmRSS:\t42 kB\n",
		"cmdline": "/should/not/be/read\x00",
		"io":      "read_bytes: 42\nwrite_bytes: 42\n",
		"cgroup":  "0::/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
	} {
		if err := os.WriteFile(filepath.Join(pidDir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/should/not/be/resolved", filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	pipeline := events.NewPipeline(16)
	collector := NewProcessCollector(pipeline, "agent", "host", 0)
	collector.SetProcRoot(root)
	collector.scan()
	info := collector.known[2]
	if !info.KernelThread || info.Name != "kthreadd" || info.UID != 0 || info.Threads != 0 || info.CmdLine != "" || info.Executable != "" ||
		info.Args != nil || info.IOReadBytes != 0 || info.ContainerID != "" {
		t.Fatalf("kernel task was not kept stat-only: %+v", info)
	}
	if len(collector.uids.names) != 0 || len(collector.prevCPU) != 0 {
		t.Fatal("kernel task received user or CPU enrichment")
	}
	// A flagged task need not have a kernel-looking name. Conversely a user
	// process named kworker with no executable must still be reported.
	writeProcessStat(t, root, 3, 2, "worker", pfKernelThread)
	writeProcessStat(t, root, 42, 2, "kworker/fake", 0)
	collector.scan()
	if err := os.RemoveAll(filepath.Join(root, "3")); err != nil {
		t.Fatal(err)
	}
	collector.scan()
	if collector.tree.Size() != 2 {
		t.Fatal("exited kernel task was retained in the tree")
	}
	if err := os.RemoveAll(filepath.Join(root, "42")); err != nil {
		t.Fatal(err)
	}
	collector.scan()
	received := queuedEvents(pipeline)
	if len(received) != 2 || received[0].Type != "process.start" || received[1].Type != "process.end" {
		t.Fatalf("unexpected lifecycle events: %+v", received)
	}
	for _, event := range received {
		process := event.Payload["process"].(map[string]interface{})
		assertIntEqual(t, "user process PID", process["pid"].(int), 42)
		parent := process["parent"].(map[string]interface{})
		assertEqual(t, "kernel parent name", parent["name"].(string), "kthreadd")
		assertEqual(t, "kernel parent entity ID", parent["entity_id"].(string), buildEntityID("agent", 2, 102))
	}
}

func TestKernelThreadExecBecomesUserProcess(t *testing.T) {
	root := t.TempDir()
	writeProcessStat(t, root, 42, 2, "worker", pfKernelThread)
	pipeline := events.NewPipeline(8)
	collector := NewProcessCollector(pipeline, "agent", "host", 0)
	collector.SetProcRoot(root)
	collector.scan()
	writeProcessStat(t, root, 42, 2, "sh", 0)
	collector.scan()
	received := queuedEvents(pipeline)
	if len(received) != 1 || received[0].Type != "process.start" {
		t.Fatalf("kernel-to-user transition did not produce a process start: %+v", received)
	}
}

func writeProcessStat(t *testing.T, root string, pid, ppid int, name string, flags uint64) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (%s) S %d 0 0 0 -1 %d 0 0 0 0 0 0 0 0 20 0 1 0 %d\n", pid, name, ppid, flags, 100+pid)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0600); err != nil {
		t.Fatal(err)
	}
}

func queuedEvents(pipeline *events.Pipeline) []events.Event {
	var received []events.Event
	pipeline.Subscribe(func(event events.Event) { received = append(received, event) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pipeline.Run(ctx)
	return received
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
