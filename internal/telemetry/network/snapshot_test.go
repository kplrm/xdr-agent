package network

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xdr-agent/internal/events"
	"xdr-agent/internal/telemetry/process"
)

func TestNetworkIntervalUpdatePreservesBaseline(t *testing.T) {
	pipeline := events.NewPipeline(16)
	collector := NewNetworkCollector(pipeline, "agent", "host", time.Hour)
	provider := NewSocketSnapshotProvider(t.TempDir(), "agent")
	var cycles atomic.Int32
	provider.read = func(_, proto string) ([]ConnectionInfo, error) {
		if proto == "tcp" {
			cycles.Add(1)
			return []ConnectionInfo{{Protocol: "tcp", LocalAddr: "10.0.0.1", LocalPort: 80, RemoteAddr: "0.0.0.0", State: "LISTEN", Inode: 42}}, nil
		}
		return nil, nil
	}
	provider.owners = func(_, _ string) map[uint64]*ProcessInfo { return nil }
	collector.SetSocketSnapshotProvider(provider)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collector.Start(ctx)
	defer collector.Stop()
	collector.SetInterval(20 * time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for cycles.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	collector.Stop()
	if cycles.Load() < 2 {
		t.Fatal("new network interval did not take effect")
	}
	if got := dnsDrainEvents(pipeline); len(got) != 0 {
		t.Fatalf("interval update must preserve unchanged socket baseline: %+v", got)
	}
}

func TestPerimeterUpdateDiscardsRetainedDirection(t *testing.T) {
	pipeline := events.NewPipeline(16)
	collector := NewNetworkCollector(pipeline, "agent", "host", time.Second)
	provider := NewSocketSnapshotProvider(t.TempDir(), "agent")
	var sockets []ConnectionInfo
	provider.read = func(_, proto string) ([]ConnectionInfo, error) {
		if proto == "tcp" {
			return sockets, nil
		}
		return nil, nil
	}
	provider.owners = func(_, _ string) map[uint64]*ProcessInfo { return nil }
	collector.SetSocketSnapshotProvider(provider)
	collector.scan()
	sockets = []ConnectionInfo{{Protocol: "tcp", LocalAddr: "10.0.0.2", LocalPort: 50000, RemoteAddr: "8.8.8.8", RemotePort: 443, State: "SYN_SENT", Inode: 123}}
	collector.scan()
	sockets[0].State = "ESTABLISHED"
	collector.scan()
	perimeter, _ := NewPerimeter([]string{"8.8.8.8/32"})
	collector.SetPerimeter(perimeter)
	sockets[0].State = "TIME_WAIT"
	collector.scan()
	// A close immediately after a second policy update must also carry a value.
	collector.SetPerimeter(perimeter)
	sockets = nil
	collector.scan()
	got := dnsDrainEvents(pipeline)
	if len(got) != 4 || got[1].Payload["network"].(map[string]interface{})["direction"] != "outbound" || got[2].Payload["network"].(map[string]interface{})["direction"] != "unknown" || got[3].Payload["network"].(map[string]interface{})["direction"] != "unknown" {
		t.Fatalf("old perimeter direction survived updated policy: %+v", got)
	}
}

func TestHostAddressChangesReclassifyOnlyAffectedConnections(t *testing.T) {
	pipeline := events.NewPipeline(32)
	collector := NewNetworkCollector(pipeline, "agent", "host", time.Second)
	var addresses []net.Addr
	hosts := &HostAddresses{read: func() ([]net.Addr, error) { return addresses, nil }}
	hosts.refresh()
	perimeter, _ := NewPerimeter(nil, hosts)
	collector.SetPerimeter(perimeter)
	provider := NewSocketSnapshotProvider(t.TempDir(), "agent")
	var sockets []ConnectionInfo
	provider.read = func(_, proto string) ([]ConnectionInfo, error) {
		if proto == "tcp" {
			return sockets, nil
		}
		return nil, nil
	}
	provider.owners = func(_, _ string) map[uint64]*ProcessInfo { return nil }
	collector.SetSocketSnapshotProvider(provider)
	collector.scan()
	public := "2003:e5:bf04:d325:2949:ef93:1438:d7f5"
	sockets = []ConnectionInfo{
		{Protocol: "tcp", LocalAddr: public, LocalPort: 50000, RemoteAddr: "2606:4700:3034::6815:427e", RemotePort: 443, State: "SYN_SENT", Inode: 123},
		{Protocol: "tcp", LocalAddr: "10.0.0.2", LocalPort: 50001, RemoteAddr: "8.8.8.8", RemotePort: 443, State: "SYN_SENT", Inode: 124},
	}
	collector.scan()
	for i := range sockets {
		sockets[i].State = "ESTABLISHED"
	}
	collector.scan()
	addresses = []net.Addr{&net.IPAddr{IP: net.ParseIP(public)}}
	hosts.refresh()
	collector.scan()
	for i := range sockets {
		sockets[i].State = "TIME_WAIT"
	}
	collector.scan()
	addresses = nil
	hosts.refresh()
	sockets = nil
	collector.scan()
	got := dnsDrainEvents(pipeline)
	if len(got) != 8 {
		t.Fatalf("got %d events, want eight socket transitions without refresh duplicates", len(got))
	}
	for i, event := range got {
		want := "outbound"
		if event.Payload["source"].(map[string]interface{})["ip"] == public {
			want = "external"
			if i >= 4 && event.Type != "network.connection_closed" {
				want = "unknown" // No handshake observed with this IP recognized as local.
			}
		}
		if direction := event.Payload["network"].(map[string]interface{})["direction"]; direction != want {
			t.Errorf("event %d direction=%v, want %s", i, direction, want)
		}
	}
}

func TestSocketLifecycleTracksStateAndRetainsOwner(t *testing.T) {
	pipeline := events.NewPipeline(32)
	collector := NewNetworkCollector(pipeline, "agent", "host", time.Second)
	provider := NewSocketSnapshotProvider(t.TempDir(), "agent")
	collector.SetSocketSnapshotProvider(provider)
	conn := ConnectionInfo{Protocol: "tcp", LocalAddr: "10.0.0.2", LocalPort: 50000,
		RemoteAddr: "8.8.8.8", RemotePort: 443, State: "SYN_SENT", Inode: 123}
	var sockets []ConnectionInfo
	reads, walks := 0, 0
	provider.read = func(_, proto string) ([]ConnectionInfo, error) {
		reads++
		if proto == "tcp" {
			return sockets, nil
		}
		return nil, nil
	}
	provider.owners = func(_, _ string) map[uint64]*ProcessInfo {
		walks++
		return map[uint64]*ProcessInfo{123: {PID: 42, Name: "client", EntityID: "instance"}}
	}
	collector.scan() // silent baseline
	sockets = []ConnectionInfo{conn}
	collector.scan()
	// DNS and connections consume the same ownership walk.
	if owner := provider.Current().ResolveInode(123); owner == nil || owner.PID != 42 {
		t.Fatal("missing shared owner")
	}
	collector.scan() // unchanged, no event
	sockets[0].State = "ESTABLISHED"
	collector.scan()
	sockets[0].State, sockets[0].Inode = "TIME_WAIT", 0
	collector.scan()
	sockets = nil
	collector.scan()
	got := dnsDrainEvents(pipeline)
	want := []string{"network.connection_opened", "network.connection_state_changed", "network.connection_state_changed", "network.connection_closed"}
	if len(got) != len(want) {
		t.Fatalf("events=%d, want %d: %+v", len(got), len(want), got)
	}
	for i, event := range got {
		if event.Type != want[i] {
			t.Errorf("event %d=%s, want %s", i, event.Type, want[i])
		}
		if event.Payload["network"].(map[string]interface{})["direction"] != "outbound" {
			t.Errorf("lost initiator at event %d", i)
		}
		if event.Payload["process"].(map[string]interface{})["entity_id"] != "instance" {
			t.Errorf("lost owner at event %d", i)
		}
	}
	if reads != 6*4 || walks != 1 {
		t.Fatalf("reads=%d walks=%d, want 24 and 1", reads, walks)
	}
}

func TestSocketReadFailureAndReusedTuple(t *testing.T) {
	pipeline := events.NewPipeline(16)
	collector := NewNetworkCollector(pipeline, "agent", "host", time.Second)
	provider := NewSocketSnapshotProvider(t.TempDir(), "agent")
	collector.SetSocketSnapshotProvider(provider)
	conn := ConnectionInfo{Protocol: "tcp", LocalAddr: "10.0.0.1", RemoteAddr: "10.0.0.2", LocalPort: 1000, RemotePort: 2000, Inode: 1, State: "ESTABLISHED"}
	var sockets []ConnectionInfo
	failed := false
	provider.read = func(_, proto string) ([]ConnectionInfo, error) {
		if proto == "tcp" {
			if failed {
				return nil, errors.New("unreadable table")
			}
			return sockets, nil
		}
		return nil, nil
	}
	provider.owners = func(_, _ string) map[uint64]*ProcessInfo { return nil }
	collector.scan()
	sockets = []ConnectionInfo{conn}
	collector.scan()
	failed = true
	collector.scan() // cannot infer closure from a failed read
	failed = false
	sockets[0].Inode = 2 // new socket, same endpoints
	collector.scan()
	got := dnsDrainEvents(pipeline)
	counts := map[string]int{}
	for _, event := range got {
		counts[event.Type]++
	}
	if len(got) != 3 || counts["network.connection_opened"] != 2 || counts["network.connection_closed"] != 1 {
		t.Fatalf("events=%+v", counts)
	}
}

func TestSocketHandshakeInodePromotionAndTupleReuse(t *testing.T) {
	for _, test := range []struct{ state, direction string }{
		{"SYN_RECV", "inbound"},
		{"SYN_SENT", "outbound"},
	} {
		t.Run(test.state, func(t *testing.T) {
			pipeline := events.NewPipeline(32)
			collector := NewNetworkCollector(pipeline, "agent", "host", time.Second)
			provider := NewSocketSnapshotProvider(t.TempDir(), "agent")
			collector.SetSocketSnapshotProvider(provider)
			var sockets []ConnectionInfo
			provider.read = func(_, proto string) ([]ConnectionInfo, error) {
				if proto == "tcp" {
					return sockets, nil
				}
				return nil, nil
			}
			provider.owners = func(_, _ string) map[uint64]*ProcessInfo {
				return map[uint64]*ProcessInfo{
					123: {PID: 42, EntityID: "first-process"},
					456: {PID: 43, EntityID: "next-process"},
				}
			}
			collector.scan() // empty baseline
			sockets = []ConnectionInfo{{Protocol: "tcp", LocalAddr: "10.0.0.2", LocalPort: 8443,
				RemoteAddr: "8.8.8.8", RemotePort: 50000, State: test.state}}
			collector.scan() // handshake has no inode or owner yet
			sockets[0].State, sockets[0].Inode = "ESTABLISHED", 123
			collector.scan() // inode assignment must preserve the handshake instance
			collector.scan() // the promoted instance must keep its stable key
			sockets[0].State, sockets[0].Inode = "TIME_WAIT", 0
			collector.scan()
			// Reusing the tuple after TIME_WAIT must not inherit the earlier
			// handshake or owner, even though the earlier instance's key had inode 0.
			sockets[0].State, sockets[0].Inode = "ESTABLISHED", 456
			collector.scan()
			got := dnsDrainEvents(pipeline)
			want := []string{"network.connection_opened", "network.connection_state_changed", "network.connection_state_changed", "network.connection_opened", "network.connection_closed"}
			if len(got) != len(want) {
				t.Fatalf("promotion events=%+v, want %v", got, want)
			}
			for i, event := range got[:3] {
				if event.Type != want[i] || event.Payload["network"].(map[string]interface{})["direction"] != test.direction {
					t.Errorf("event %d lost lifecycle/direction: %+v", i, event)
				}
				if i > 0 && event.Payload["process"].(map[string]interface{})["entity_id"] != "first-process" {
					t.Errorf("event %d lost promoted owner: %+v", i, event)
				}
			}

			if got[3].Type != want[3] || got[4].Type != want[4] {
				t.Fatalf("tuple reuse events=%+v", got)
			}
			if got[3].Payload["network"].(map[string]interface{})["direction"] != "unknown" ||
				got[3].Payload["process"].(map[string]interface{})["entity_id"] != "next-process" {
				t.Fatalf("new socket inherited old context: %+v", got[3])
			}
			if got[4].Payload["network"].(map[string]interface{})["direction"] != test.direction ||
				got[4].Payload["process"].(map[string]interface{})["entity_id"] != "first-process" {
				t.Fatalf("closed socket lost prior context: %+v", got[4])
			}
		})
	}
}

func TestUDPOwnershipRequiresUnambiguousSocket(t *testing.T) {
	provider := NewSocketSnapshotProvider(t.TempDir(), "agent")
	provider.read = func(_, proto string) ([]ConnectionInfo, error) {
		if proto != "udp" {
			return nil, nil
		}
		return []ConnectionInfo{
			{LocalAddr: "10.0.0.1", LocalPort: 50000, RemoteAddr: "10.0.0.53", RemotePort: 53, Inode: 1},
			{LocalAddr: "10.0.0.1", LocalPort: 50000, RemoteAddr: "10.0.0.54", RemotePort: 53, Inode: 2},
		}, nil
	}
	provider.owners = func(_, _ string) map[uint64]*ProcessInfo { return map[uint64]*ProcessInfo{1: {PID: 1}, 2: {PID: 2}} }
	snapshot := provider.Refresh()
	if snapshot.ResolveUDP("10.0.0.1", 50000) != nil {
		t.Fatal("ambiguous endpoint must not choose an arbitrary owner")
	}
	if owner := snapshot.ResolveUDPFlow("10.0.0.1", 50000, "10.0.0.54", 53); owner == nil || owner.PID != 2 {
		t.Fatalf("full tuple owner=%+v", owner)
	}
	if owner := snapshot.ResolveUDPFlow("10.0.0.1", 50000, "10.0.0.55", 53); owner != nil {
		t.Fatalf("unmatched peer owner=%+v", owner)
	}
}

func TestSocketSnapshotConcurrentConsumers(t *testing.T) {
	provider := NewSocketSnapshotProvider(t.TempDir(), "agent")
	var walks atomic.Int32
	provider.read = func(_, proto string) ([]ConnectionInfo, error) {
		if proto == "udp" {
			return []ConnectionInfo{{LocalAddr: "10.0.0.1", LocalPort: 50000, Inode: 1}}, nil
		}
		return nil, nil
	}
	provider.owners = func(_, _ string) map[uint64]*ProcessInfo {
		walks.Add(1)
		return map[uint64]*ProcessInfo{1: {PID: 42}}
	}
	for generation := 0; generation < 2; generation++ {
		snapshot := provider.Refresh()
		var consumers sync.WaitGroup
		for i := 0; i < 32; i++ {
			consumers.Add(1)
			go func() {
				defer consumers.Done()
				if owner := snapshot.ResolveInode(1); owner == nil || owner.PID != 42 {
					t.Error("connection owner missing")
				}
				if owner := provider.Current().ResolveUDP("10.0.0.1", 50000); owner == nil || owner.PID != 42 {
					t.Error("DNS owner missing")
				}
			}()
		}
		consumers.Wait()
	}
	if walks.Load() != 2 {
		t.Fatalf("ownership walks=%d, want one per generation", walks.Load())
	}
}

func TestSocketOwnerEntityIDMatchesProcessInstance(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "42")
	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0700); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = "S", "100"
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte("42 (client) "+strings.Join(fields, " ")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("client\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[123]", filepath.Join(pidDir, "fd", "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/client", filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	owner := buildSocketOwnerSnapshot(root, "agent")[123]
	if owner == nil || owner.EntityID != process.EntityID("agent", 42, 100) || owner.Executable != "/usr/bin/client" {
		t.Fatalf("owner=%+v", owner)
	}
}
