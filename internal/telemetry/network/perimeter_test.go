package network

import "testing"

func TestPerimeterDirection(t *testing.T) {
	p, err := NewPerimeter(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, source, destination, want string
	}{
		{"RFC1918 private", "10.244.3.205", "172.16.5.1", "internal"},
		{"private upper boundary", "172.31.255.255", "192.168.2.52", "internal"},
		{"outside private range", "172.32.0.1", "8.8.8.8", "external"},
		{"outbound", "192.168.2.52", "8.8.8.8", "outbound"},
		{"inbound", "8.8.8.8", "192.168.2.52", "inbound"},
		{"IPv6 ULA", "fc00::1", "fd12:3456::2", "internal"},
		{"IPv6 outbound", "fd12::1", "2606:4700:4700::1111", "outbound"},
		{"loopback IPv4", "127.0.0.1", "127.0.0.53", "internal"},
		{"loopback IPv6", "::1", "::1", "internal"},
		{"mapped IPv4", "::ffff:192.168.2.52", "::ffff:8.8.8.8", "outbound"},
		{"unspecified remote", "192.168.2.52", "0.0.0.0", "unknown"},
		{"unspecified IPv6", "::", "fd12::1", "unknown"},
		{"missing remote", "192.168.2.52", "", "unknown"},
		{"invalid source", "invalid", "8.8.8.8", "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := p.Direction(test.source, test.destination); got != test.want {
				t.Errorf("Direction(%q, %q) = %q, want %q", test.source, test.destination, got, test.want)
			}
		})
	}
}

func TestPerimeterConfiguration(t *testing.T) {
	custom, err := NewPerimeter([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if got := custom.Direction("203.0.113.10", "192.168.1.1"); got != "outbound" {
		t.Fatalf("custom CIDRs must replace defaults: %s", got)
	}
	empty, err := NewPerimeter([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if got := empty.Direction("10.0.0.1", "192.168.1.1"); got != "external" {
		t.Fatalf("explicit empty CIDRs must stay empty: %s", got)
	}
	if got := empty.Direction("127.0.0.1", "127.0.0.53"); got != "internal" {
		t.Fatalf("loopback must remain internal: %s", got)
	}
	if _, err := NewPerimeter([]string{"192.168.1.1"}); err == nil {
		t.Fatal("non-CIDR internal network accepted")
	}
	if got := (*Perimeter)(nil).Direction("10.0.0.1", "8.8.8.8"); got != "unknown" {
		t.Fatalf("nil perimeter = %s", got)
	}
}

func TestConnectionDirectionRequiresEvidenceForPerimeterCrossing(t *testing.T) {
	p, err := NewPerimeter(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		state string
		port  int
		want  string
	}{
		{"ESTABLISHED", 443, "unknown"},
		{"ESTABLISHED", 8443, "unknown"},
		{"SYN_SENT", 55000, "outbound"},
		{"SYN_RECV", 8443, "inbound"},
	} {
		conn := ConnectionInfo{Protocol: "tcp", LocalAddr: "192.168.2.52", LocalPort: test.port, RemoteAddr: "8.8.8.8", RemotePort: 55001, State: test.state}
		if got := p.ConnectionDirection(conn); got != test.want {
			t.Errorf("state %s local port %d: direction = %s, want %s", test.state, test.port, got, test.want)
		}
	}
	if got := p.ConnectionDirection(ConnectionInfo{LocalAddr: "192.168.2.52", RemoteAddr: "10.0.0.1", State: "ESTABLISHED"}); got != "internal" {
		t.Fatalf("same-side established connection = %s, want internal", got)
	}
	if got := p.ConnectionDirection(ConnectionInfo{LocalAddr: "192.168.2.52", RemoteAddr: "0.0.0.0", State: "LISTEN"}); got != "unknown" {
		t.Fatalf("listener direction = %s, want unknown", got)
	}
}
