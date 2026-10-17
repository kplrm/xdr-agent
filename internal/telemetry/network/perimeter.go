package network

import (
	"fmt"
	"net"
	"net/netip"

	"xdr-agent/internal/config"
)

// Perimeter combines configured CIDRs with exact assigned host addresses.
// Its configuration is immutable; the optional host cache is shared safely.
type Perimeter struct {
	internal []*net.IPNet
	hosts    *HostAddresses
	local    *hostIPSet
}

func NewPerimeter(cidrs []string, hosts ...*HostAddresses) (*Perimeter, error) {
	if cidrs == nil {
		cidrs = config.DefaultInternalNetworks()
	}
	p := &Perimeter{}
	if len(hosts) > 0 {
		p.hosts = hosts[0]
	}
	for _, cidr := range cidrs {
		_, prefix, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid internal network %q: %w", cidr, err)
		}
		p.internal = append(p.internal, prefix)
	}
	return p, nil
}

// snapshot keeps both endpoints and retained connection context on one address set.
func (p *Perimeter) snapshot() *Perimeter {
	if p == nil || p.hosts == nil {
		return p
	}
	return &Perimeter{internal: p.internal, local: p.hosts.current.Load()}
}

func (p *Perimeter) contains(ip net.IP) bool {
	// Loopback communication never crosses the network perimeter.
	if ip.IsLoopback() {
		return true
	}
	if p.local != nil {
		addr, _ := netip.AddrFromSlice(ip)
		if _, assigned := (*p.local)[addr.Unmap()]; assigned {
			return true
		}
	}
	for _, prefix := range p.internal {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// Direction follows the observed packet's source and destination, rather than ports.
func (p *Perimeter) Direction(sourceIP, destinationIP string) string {
	p = p.snapshot()
	source, destination := net.ParseIP(sourceIP), net.ParseIP(destinationIP)
	if p == nil || source == nil || destination == nil || source.IsUnspecified() || destination.IsUnspecified() {
		return "unknown"
	}
	sourceInternal, destinationInternal := p.contains(source), p.contains(destination)
	switch {
	case sourceInternal && destinationInternal:
		return "internal"
	case !sourceInternal && !destinationInternal:
		return "external"
	case sourceInternal:
		return "outbound"
	default:
		return "inbound"
	}
}

// ConnectionDirection uses handshake state only when a perimeter crossing needs
// an initiator. Established socket snapshots alone cannot prove who initiated.
func (p *Perimeter) ConnectionDirection(conn ConnectionInfo) string {
	p = p.snapshot()
	direction := p.Direction(conn.LocalAddr, conn.RemoteAddr)
	if direction != "inbound" && direction != "outbound" {
		return direction
	}
	switch conn.State {
	case "SYN_SENT":
		return direction
	case "SYN_RECV":
		return p.Direction(conn.RemoteAddr, conn.LocalAddr)
	default:
		return "unknown"
	}
}
