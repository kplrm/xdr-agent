//go:build linux

package network

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"

	"xdr-agent/internal/events"
)

func TestDNSLoopbackCaptureCopies(t *testing.T) {
	for _, response := range []bool{false, true} {
		t.Run(map[bool]string{false: "query", true: "response"}[response], func(t *testing.T) {
			d, pipeline := dnsTestCollector(t)
			frame := dnsTestFrame(response, 1)
			outgoing := &syscall.SockaddrLinklayer{Ifindex: 1, Hatype: syscall.ARPHRD_LOOPBACK, Pkttype: syscall.PACKET_OUTGOING}
			host := &syscall.SockaddrLinklayer{Ifindex: 1, Hatype: syscall.ARPHRD_LOOPBACK, Pkttype: syscall.PACKET_HOST}
			// A genuine identical repeated datagram still has its own host copy.
			for i := 0; i < 2; i++ {
				d.handleCapturedFrame(frame, outgoing)
				d.handleCapturedFrame(frame, host)
			}
			got := dnsDrainEvents(pipeline)
			if len(got) != 2 {
				t.Fatalf("emitted %d events, want one per datagram (2)", len(got))
			}
			if got[0].ID == got[1].ID {
				t.Fatal("repeated datagrams must retain distinct event IDs")
			}
		})
	}
}

func TestDNSCaptureRetainsUnprovenDuplicates(t *testing.T) {
	d, pipeline := dnsTestCollector(t)
	query := dnsTestFrame(false, 1)
	// Identical bytes on physical or different interfaces do not prove that the
	// same datagram was captured twice; never suppress an actual retry this way.
	for _, addr := range []*syscall.SockaddrLinklayer{
		{Ifindex: 2, Hatype: syscall.ARPHRD_ETHER, Pkttype: syscall.PACKET_OUTGOING},
		{Ifindex: 2, Hatype: syscall.ARPHRD_ETHER, Pkttype: syscall.PACKET_OUTGOING},
		{Ifindex: 3, Hatype: syscall.ARPHRD_ETHER, Pkttype: syscall.PACKET_HOST},
		nil,
	} {
		d.handleCapturedFrame(query, addr)
	}
	d.handleCapturedFrame(dnsTestFrame(false, 28), &syscall.SockaddrLinklayer{Ifindex: 2, Hatype: syscall.ARPHRD_ETHER})
	d.handleCapturedFrame(dnsTestFrame(true, 1), &syscall.SockaddrLinklayer{Ifindex: 2, Hatype: syscall.ARPHRD_ETHER})
	got := dnsDrainEvents(pipeline)
	if len(got) != 6 {
		t.Fatalf("emitted %d events, want 6 distinct observations", len(got))
	}
	if got[4].Payload["dns"].(map[string]interface{})["question"].(map[string]interface{})["type"] != "AAAA" || got[5].Type != "dns.answer" {
		t.Fatal("A/AAAA questions and query/answer observations must remain distinct")
	}
}

func TestDNSResponseMatchesFullTransaction(t *testing.T) {
	d, pipeline := dnsTestCollector(t)
	makeMessage := func(qtype uint16) *parsedDNS {
		return &parsedDNS{ID: 42, Questions: []dnsQuestion{{Name: "example.com", Type: qtype, Class: 1}}}
	}
	// Same client and transaction ID, with separate resolver/question contexts.
	d.emitDNSEvent(makeMessage(1), "10.0.0.2", "10.0.0.53", 50000, 53, &ProcessInfo{PID: 100, EntityID: "process-100"})
	d.emitDNSEvent(makeMessage(1), "10.0.0.2", "10.0.0.54", 50000, 53, &ProcessInfo{PID: 200})
	d.emitDNSEvent(makeMessage(28), "10.0.0.2", "10.0.0.53", 50000, 53, &ProcessInfo{PID: 300})
	for _, test := range []struct {
		resolver string
		qtype    uint16
	}{
		{"10.0.0.53", 1}, {"10.0.0.54", 1}, {"10.0.0.53", 28},
	} {
		answer := makeMessage(test.qtype)
		answer.IsResponse = true
		d.emitDNSEvent(answer, test.resolver, "10.0.0.2", 53, 50000, nil)
	}
	got := dnsDrainEvents(pipeline)
	for i, pid := range []int{100, 200, 300} {
		proc, ok := got[3+i].Payload["process"].(map[string]interface{})
		if !ok || proc["pid"] != pid {
			t.Errorf("response %d process = %v, want PID %d", i, proc, pid)
		}
	}
	if got[3].Payload["process"].(map[string]interface{})["entity_id"] != "process-100" {
		t.Fatal("response must inherit the query's process entity ID")
	}
}

func TestDNSUsesPublishedSocketSnapshot(t *testing.T) {
	d, _ := dnsTestCollector(t)
	provider := NewSocketSnapshotProvider(t.TempDir(), "test-agent")
	reads, walks := 0, 0
	provider.read = func(_ string, protocol string) ([]ConnectionInfo, error) {
		reads++
		if protocol == "udp" {
			return []ConnectionInfo{{LocalAddr: "10.0.0.2", LocalPort: 50000, Inode: 123}}, nil
		}
		return nil, nil
	}
	provider.owners = func(_, _ string) map[uint64]*ProcessInfo {
		walks++
		return map[uint64]*ProcessInfo{123: {PID: 100, EntityID: "process-100"}}
	}
	d.SetSocketSnapshotProvider(provider)
	if proc := d.resolveUDPSocket("10.0.0.2", 50000, "10.0.0.53", 53); proc != nil || reads != 0 || walks != 0 {
		t.Fatal("DNS must not refresh an unpublished socket snapshot")
	}
	for generation := 1; generation <= 2; generation++ {
		provider.Refresh()
		for i := 0; i < 10; i++ {
			proc := d.resolveUDPSocket("10.0.0.2", 50000, "10.0.0.53", 53)
			if proc == nil || proc.EntityID != "process-100" {
				t.Fatalf("process = %+v, want shared socket owner", proc)
			}
		}
		if reads != generation*4 || walks != generation {
			t.Fatalf("generation %d: table reads = %d, owner walks = %d; want %d and %d", generation, reads, walks, generation*4, generation)
		}
	}
}

func TestDNSDirectionFollowsPacketEndpoints(t *testing.T) {
	d, pipeline := dnsTestCollector(t)
	query := &parsedDNS{ID: 42, Questions: []dnsQuestion{{Name: "example.com", Type: 1, Class: 1}}}
	d.emitDNSEvent(query, "10.0.0.2", "8.8.8.8", 50000, 53, nil)
	query.IsResponse = true
	d.emitDNSEvent(query, "8.8.8.8", "10.0.0.2", 53, 50000, nil)
	got := dnsDrainEvents(pipeline)
	for i, direction := range []string{"outbound", "inbound"} {
		network := got[i].Payload["network"].(map[string]interface{})
		if network["direction"] != direction {
			t.Errorf("event %d direction = %v, want %s", i, network["direction"], direction)
		}
	}
}

func TestDNSDirectionUsesUpdatedHostAddresses(t *testing.T) {
	d, pipeline := dnsTestCollector(t)
	local, remote := "2003:e5:bf04:d325:2949:ef93:1438:d7f5", "2606:4700:3034::6815:427e"
	addresses := []net.Addr{&net.IPAddr{IP: net.ParseIP(local)}}
	hosts := &HostAddresses{read: func() ([]net.Addr, error) { return addresses, nil }}
	hosts.refresh()
	perimeter, _ := NewPerimeter([]string{}, hosts)
	d.SetPerimeter(perimeter)
	query := &parsedDNS{ID: 42, Questions: []dnsQuestion{{Name: "example.com", Type: 1, Class: 1}}}
	d.emitDNSEvent(query, local, remote, 50000, 53, nil)
	d.emitDNSEvent(query, remote, local, 53, 50000, nil)
	addresses = nil
	hosts.refresh()
	d.emitDNSEvent(query, local, remote, 50000, 53, nil)
	got := dnsDrainEvents(pipeline)
	if len(got) != 3 {
		t.Fatalf("got %d DNS events, want three", len(got))
	}
	for i, event := range got {
		if got, want := event.Payload["network"].(map[string]interface{})["direction"], []string{"outbound", "inbound", "external"}[i]; got != want {
			t.Errorf("event %d direction=%v, want %s", i, got, want)
		}
	}
}

func TestDNSObservationTimestampPrecedesOwnershipEnrichment(t *testing.T) {
	d, pipeline := dnsTestCollector(t)
	provider := NewSocketSnapshotProvider(t.TempDir(), "test-agent")
	provider.read = func(_ string, protocol string) ([]ConnectionInfo, error) {
		if protocol == "udp" {
			return []ConnectionInfo{{LocalAddr: "127.0.0.1", LocalPort: 50000, Inode: 123}}, nil
		}
		return nil, nil
	}
	var ownershipAt time.Time
	provider.owners = func(_, _ string) map[uint64]*ProcessInfo {
		ownershipAt = time.Now().UTC()
		return map[uint64]*ProcessInfo{123: {PID: 100}}
	}
	provider.Refresh()
	d.SetSocketSnapshotProvider(provider)
	d.handleFrame(dnsTestFrame(false, 1))
	got := dnsDrainEvents(pipeline)
	if len(got) != 1 || ownershipAt.IsZero() || got[0].Timestamp.After(ownershipAt) {
		t.Fatalf("observation timestamp must precede ownership enrichment: events=%v ownership=%v", got, ownershipAt)
	}
}

func TestDNSExpiredQueryDoesNotAttributeResponse(t *testing.T) {
	d, pipeline := dnsTestCollector(t)
	msg := &parsedDNS{ID: 42, Questions: []dnsQuestion{{Name: "example.com", Type: 1, Class: 1}}}
	d.emitDNSEvent(msg, "10.0.0.2", "10.0.0.53", 50000, 53, &ProcessInfo{PID: 100})
	for _, pending := range d.pending {
		pending.ts = time.Now().Add(-dnsPendingTTL - time.Second)
	}
	msg.IsResponse = true
	d.emitDNSEvent(msg, "10.0.0.53", "10.0.0.2", 53, 50000, nil)
	got := dnsDrainEvents(pipeline)
	if _, ok := got[1].Payload["process"]; ok {
		t.Fatal("expired transaction must not supply a process to a response")
	}
}

func dnsTestCollector(t *testing.T) (*DNSCollector, *events.Pipeline) {
	t.Helper()
	pipeline := events.NewPipeline(64)
	d := NewDNSCollector(pipeline, "test-agent", "test-host")
	return d, pipeline
}

func dnsDrainEvents(pipeline *events.Pipeline) []events.Event {
	var got []events.Event
	pipeline.Subscribe(func(event events.Event) { got = append(got, event) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pipeline.Run(ctx)
	return got
}

func dnsTestFrame(response bool, qtype uint16) []byte {
	question := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 0, 0, 1}
	binary.BigEndian.PutUint16(question[len(question)-4:], qtype)
	frame := make([]byte, 14+20+8+12+len(question))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(frame)-14))
	client, resolver := net.ParseIP("127.0.0.1").To4(), net.ParseIP("127.0.0.53").To4()
	srcPort, dstPort := uint16(50000), uint16(53)
	if response {
		client, resolver = resolver, client
		srcPort, dstPort = dstPort, srcPort
	}
	copy(ip[12:16], client)
	copy(ip[16:20], resolver)
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(frame)-34))
	dns := frame[42:]
	binary.BigEndian.PutUint16(dns[0:2], 42)
	binary.BigEndian.PutUint16(dns[4:6], 1)
	if response {
		binary.BigEndian.PutUint16(dns[2:4], 0x8000)
	}
	copy(dns[12:], question)
	return frame
}
