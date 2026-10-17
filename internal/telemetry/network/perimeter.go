package network

import (
	"fmt"
	"net"

	"xdr-agent/internal/config"
)

// Perimeter classifies endpoints against explicitly configured internal CIDRs.
// It is immutable after construction and safe to share between collectors.
type Perimeter struct {
	internal []*net.IPNet
}

func NewPerimeter(cidrs []string) (*Perimeter, error) {
	if cidrs == nil {
		cidrs = config.DefaultInternalNetworks()
	}
	p := &Perimeter{}
	for _, cidr := range cidrs {
		_, prefix, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid internal network %q: %w", cidr, err)
		}
		p.internal = append(p.internal, prefix)
	}
	return p, nil
}

func (p *Perimeter) contains(ip net.IP) bool {
	// Loopback communication never crosses the network perimeter.
	if ip.IsLoopback() {
		return true
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
