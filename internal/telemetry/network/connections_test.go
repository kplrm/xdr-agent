package network

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

// ── IP parsing tests ────────────────────────────────────────────────────────

func TestParseIPv4Hex_Loopback(t *testing.T) {
	ip, err := ParseIPv4Hex("0100007F")
	if err != nil {
		t.Fatalf("ParseIPv4Hex: %v", err)
	}
	if ip != "127.0.0.1" {
		t.Errorf("got %q, want %q", ip, "127.0.0.1")
	}
}

func TestParseIPv4Hex_AllZeroes(t *testing.T) {
	ip, err := ParseIPv4Hex("00000000")
	if err != nil {
		t.Fatalf("ParseIPv4Hex: %v", err)
	}
	if ip != "0.0.0.0" {
		t.Errorf("got %q, want %q", ip, "0.0.0.0")
	}
}

func TestParseIPv4Hex_PrivateIP(t *testing.T) {
	// 10.0.0.104 → network byte order 0x0A000068 →
	// x86 reads as 0x6800000A → hex "6800000A"
	ip, err := ParseIPv4Hex("6800000A")
	if err != nil {
		t.Fatalf("ParseIPv4Hex: %v", err)
	}
	if ip != "10.0.0.104" {
		t.Errorf("got %q, want %q", ip, "10.0.0.104")
	}
}

func TestParseIPv4Hex_InvalidLength(t *testing.T) {
	_, err := ParseIPv4Hex("01007F")
	if err == nil {
		t.Error("expected error for invalid length")
	}
}

func TestParseIPv6Hex_Loopback(t *testing.T) {
	// ::1 stored as four 32-bit words in host (little-endian) order:
	// 00000000 00000000 00000000 01000000
	ip, err := ParseIPv6Hex("00000000000000000000000001000000")
	if err != nil {
		t.Fatalf("ParseIPv6Hex: %v", err)
	}
	if ip != "::1" {
		t.Errorf("got %q, want %q", ip, "::1")
	}
}

func TestParseIPv6Hex_AllZeroes(t *testing.T) {
	ip, err := ParseIPv6Hex("00000000000000000000000000000000")
	if err != nil {
		t.Fatalf("ParseIPv6Hex: %v", err)
	}
	if ip != "::" {
		t.Errorf("got %q, want %q", ip, "::")
	}
}

func TestParseIPv6Hex_InvalidLength(t *testing.T) {
	_, err := ParseIPv6Hex("0000000000000000")
	if err == nil {
		t.Error("expected error for invalid length")
	}
}

// ── ParseProcNet tests ──────────────────────────────────────────────────────

func TestParseProcNet_TCP(t *testing.T) {
	path := filepath.Join(testdataDir(), "proc_net_baseline", "net", "tcp")
	conns, err := ParseProcNet(path, "tcp")
	if err != nil {
		t.Fatalf("ParseProcNet(%q): %v", path, err)
	}

	if len(conns) != 3 {
		t.Fatalf("expected 3 connections, got %d", len(conns))
	}

	// Connection 0: 127.0.0.1:53 → 0.0.0.0:0 LISTEN
	assertConn(t, conns[0], "tcp", "127.0.0.1", 53, "0.0.0.0", 0, "LISTEN")

	// Connection 1: 0.0.0.0:22 → 0.0.0.0:0 LISTEN
	assertConn(t, conns[1], "tcp", "0.0.0.0", 22, "0.0.0.0", 0, "LISTEN")

	// Connection 2: 127.0.0.1:49156 → 127.0.0.1:5555 ESTABLISHED
	assertConn(t, conns[2], "tcp", "127.0.0.1", 49156, "127.0.0.1", 5555, "ESTABLISHED")

	// Verify UID and inode on connection 2
	if conns[2].UID != 1000 {
		t.Errorf("conn[2].UID = %d, want 1000", conns[2].UID)
	}
	if conns[2].Inode != 45678 {
		t.Errorf("conn[2].Inode = %d, want 45678", conns[2].Inode)
	}
}

func TestParseProcNet_TCP6(t *testing.T) {
	path := filepath.Join(testdataDir(), "proc_net_baseline", "net", "tcp6")
	conns, err := ParseProcNet(path, "tcp6")
	if err != nil {
		t.Fatalf("ParseProcNet(%q): %v", path, err)
	}

	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}

	// :::80 → :::0 LISTEN
	assertConn(t, conns[0], "tcp6", "::", 80, "::", 0, "LISTEN")
}

func TestParseProcNet_UDP(t *testing.T) {
	path := filepath.Join(testdataDir(), "proc_net_baseline", "net", "udp")
	conns, err := ParseProcNet(path, "udp")
	if err != nil {
		t.Fatalf("ParseProcNet(%q): %v", path, err)
	}

	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}

	// 127.0.0.1:53 UDP
	assertConn(t, conns[0], "udp", "127.0.0.1", 53, "0.0.0.0", 0, "CLOSE")
}

func TestParseProcNet_Nonexistent(t *testing.T) {
	_, err := ParseProcNet("/nonexistent/tcp", "tcp")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

// ── Diff detection tests ────────────────────────────────────────────────────

func TestNetworkDiff_DetectsChanges(t *testing.T) {
	baselinePath := filepath.Join(testdataDir(), "proc_net_baseline", "net", "tcp")
	updatedPath := filepath.Join(testdataDir(), "proc_net_updated", "net", "tcp")

	baseline, err := ParseProcNet(baselinePath, "tcp")
	if err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	updated, err := ParseProcNet(updatedPath, "tcp")
	if err != nil {
		t.Fatalf("parse updated: %v", err)
	}

	baselineMap := make(map[string]ConnectionInfo)
	for _, c := range baseline {
		baselineMap[c.key()] = c
	}
	updatedMap := make(map[string]ConnectionInfo)
	for _, c := range updated {
		updatedMap[c.key()] = c
	}

	// New connections
	var newConns []ConnectionInfo
	for key, c := range updatedMap {
		if _, existed := baselineMap[key]; !existed {
			newConns = append(newConns, c)
		}
	}

	// Closed connections
	var closedConns []ConnectionInfo
	for key, c := range baselineMap {
		if _, exists := updatedMap[key]; !exists {
			closedConns = append(closedConns, c)
		}
	}

	// Connection #2 (127.0.0.1:49156→127.0.0.1:5555) should be closed
	if len(closedConns) != 1 {
		t.Fatalf("expected 1 closed connection, got %d", len(closedConns))
	}
	if closedConns[0].LocalPort != 49156 {
		t.Errorf("closed conn local port = %d, want 49156", closedConns[0].LocalPort)
	}

	// Connection #3 (10.0.0.104:49157→216.58.206.71:443) should be new
	if len(newConns) != 1 {
		t.Fatalf("expected 1 new connection, got %d", len(newConns))
	}
	if newConns[0].LocalAddr != "10.0.0.104" {
		t.Errorf("new conn local addr = %q, want %q", newConns[0].LocalAddr, "10.0.0.104")
	}
	if newConns[0].RemoteAddr != "216.58.206.71" {
		t.Errorf("new conn remote addr = %q, want %q", newConns[0].RemoteAddr, "216.58.206.71")
	}
	if newConns[0].RemotePort != 443 {
		t.Errorf("new conn remote port = %d, want 443", newConns[0].RemotePort)
	}
}

// ── NetworkCollector integration tests ──────────────────────────────────────

func TestNetworkCollector_EmitsEvents(t *testing.T) {
	pipeline := events.NewPipeline(64)
	received := make(chan events.Event, 32)
	pipeline.Subscribe(func(e events.Event) {
		received <- e
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeline.Run(ctx)

	nc := NewNetworkCollector(pipeline, "test-agent-001", "test-host", 100*time.Millisecond)
	// Start with baseline
	nc.SetProcRoot(filepath.Join(testdataDir(), "proc_net_baseline"))

	if err := nc.Init(capability.Dependencies{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := nc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for baseline
	time.Sleep(150 * time.Millisecond)

	// Switch to updated: conn #2 gone, conn #3 new
	nc.SetProcRoot(filepath.Join(testdataDir(), "proc_net_updated"))

	var openEvents, closeEvents []events.Event
	deadline := time.After(3 * time.Second)

	for {
		select {
		case evt := <-received:
			switch evt.Type {
			case "network.connection_opened":
				openEvents = append(openEvents, evt)
			case "network.connection_closed":
				closeEvents = append(closeEvents, evt)
			}
			if len(openEvents) >= 1 && len(closeEvents) >= 1 {
				goto verify
			}
		case <-deadline:
			goto verify
		}
	}

verify:
	if len(openEvents) == 0 {
		t.Fatal("expected at least one connection_opened event")
	}
	if len(closeEvents) == 0 {
		t.Fatal("expected at least one connection_closed event")
	}

	// Check the opened event has outbound direction
	net0 := openEvents[0].Payload["network"].(map[string]interface{})
	if net0["direction"] != "outbound" {
		t.Errorf("opened event direction = %q, want %q", net0["direction"], "outbound")
	}
	if net0["state"] != "ESTABLISHED" {
		t.Errorf("opened event state = %q, want %q", net0["state"], "ESTABLISHED")
	}

	if err := nc.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestNetworkCollector_Name(t *testing.T) {
	nc := NewNetworkCollector(nil, "", "", 0)
	if nc.Name() != "telemetry.network" {
		t.Errorf("Name() = %q, want %q", nc.Name(), "telemetry.network")
	}
}

func TestNetworkCollector_HealthTransitions(t *testing.T) {
	nc := NewNetworkCollector(events.NewPipeline(8), "a", "h", time.Hour)

	if nc.Health() != capability.HealthStopped {
		t.Errorf("initial health = %v, want HealthStopped", nc.Health())
	}

	_ = nc.Init(capability.Dependencies{})
	if nc.Health() != capability.HealthStarting {
		t.Errorf("after Init health = %v, want HealthStarting", nc.Health())
	}

	ctx, cancel := context.WithCancel(context.Background())
	nc.SetProcRoot(filepath.Join(testdataDir(), "proc_net_baseline"))
	_ = nc.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	if nc.Health() != capability.HealthRunning {
		t.Errorf("after Start health = %v, want HealthRunning", nc.Health())
	}

	cancel()
	_ = nc.Stop()
	if nc.Health() != capability.HealthStopped {
		t.Errorf("after Stop health = %v, want HealthStopped", nc.Health())
	}
}

// ── Direction helper test ───────────────────────────────────────────────────

func TestDirection(t *testing.T) {
	tests := []struct {
		conn ConnectionInfo
		want string
	}{
		{ConnectionInfo{State: "LISTEN"}, "listening"},
		{ConnectionInfo{State: "ESTABLISHED", RemoteAddr: "0.0.0.0"}, "listening"},
		{ConnectionInfo{State: "ESTABLISHED", RemoteAddr: "::"}, "listening"},
		{ConnectionInfo{State: "ESTABLISHED", RemoteAddr: "8.8.8.8"}, "outbound"},
	}

	for _, tt := range tests {
		got := direction(tt.conn)
		if got != tt.want {
			t.Errorf("direction(%+v) = %q, want %q", tt.conn, got, tt.want)
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func assertConn(t *testing.T, c ConnectionInfo, proto, localAddr string, localPort int, remoteAddr string, remotePort int, state string) {
	t.Helper()
	if c.Protocol != proto {
		t.Errorf("Protocol = %q, want %q", c.Protocol, proto)
	}
	if c.LocalAddr != localAddr {
		t.Errorf("LocalAddr = %q, want %q", c.LocalAddr, localAddr)
	}
	if c.LocalPort != localPort {
		t.Errorf("LocalPort = %d, want %d", c.LocalPort, localPort)
	}
	if c.RemoteAddr != remoteAddr {
		t.Errorf("RemoteAddr = %q, want %q", c.RemoteAddr, remoteAddr)
	}
	if c.RemotePort != remotePort {
		t.Errorf("RemotePort = %d, want %d", c.RemotePort, remotePort)
	}
	if c.State != state {
		t.Errorf("State = %q, want %q", c.State, state)
	}
}
