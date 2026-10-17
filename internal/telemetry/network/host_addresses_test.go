package network

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHostAddressesClassifyExactIPsAndFollowChanges(t *testing.T) {
	var addresses []net.Addr
	var readErr error
	hosts := &HostAddresses{read: func() ([]net.Addr, error) { return addresses, readErr }}
	p, _ := NewPerimeter([]string{}, hosts)
	local := "2003:e5:bf04:d325:2949:ef93:1438:d7f5"
	remote := "2606:4700:3034::6815:427e"
	addresses = []net.Addr{
		&net.IPNet{IP: net.ParseIP(local), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("203.0.113.9"), Mask: net.CIDRMask(24, 32)},
	}
	hosts.refresh()
	for _, test := range []struct{ source, destination, want string }{
		{local, remote, "outbound"},
		{remote, local, "inbound"},
		{"203.0.113.9", "8.8.8.8", "outbound"},
		{"::ffff:203.0.113.9", "8.8.8.8", "outbound"},
		{"2003:e5:bf04:d325::2", remote, "external"},
		{"203.0.113.10", "8.8.8.8", "external"},
		{local, "::", "unknown"},
	} {
		if got := p.Direction(test.source, test.destination); got != test.want {
			t.Errorf("Direction(%s, %s)=%s, want %s", test.source, test.destination, got, test.want)
		}
	}
	before := hosts.current.Load()
	hosts.refresh()
	if before != hosts.current.Load() {
		t.Fatal("unchanged addresses invalidated the shared snapshot")
	}
	readErr = errors.New("temporary kernel query failure")
	hosts.refresh()
	if p.Direction(local, remote) != "outbound" {
		t.Fatal("failed refresh discarded known local IPs")
	}
	readErr = nil
	addresses = []net.Addr{&net.IPNet{IP: net.ParseIP("2003:e5:bf04:d325::99"), Mask: net.CIDRMask(64, 128)}}
	hosts.refresh()
	if p.Direction(local, remote) != "external" || p.Direction("2003:e5:bf04:d325::99", remote) != "outbound" {
		t.Fatal("address replacement did not remove the old IP and include the new one")
	}
	// CIDR policy changes retain access to the same dynamic host cache.
	replacement, _ := NewPerimeter([]string{"10.0.0.0/8"}, hosts)
	if replacement.Direction("2003:e5:bf04:d325::99", remote) != "outbound" {
		t.Fatal("policy replacement lost host addresses")
	}
}

func TestHostAddressWatcherCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{}, 1)
	hosts := &HostAddresses{read: func() ([]net.Addr, error) {
		select {
		case ready <- struct{}{}:
		default:
		}
		return nil, nil
	}}
	done := make(chan error, 1)
	go func() { done <- hosts.watch(ctx) }()
	select {
	case err := <-done:
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EAFNOSUPPORT) {
			t.Skipf("netlink unavailable: %v", err)
		}
		t.Fatalf("watcher stopped before address discovery: %v", err)
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("watcher did not discover addresses")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock the address watcher")
	}
}
