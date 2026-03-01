package network

// communityID computes the Community ID v1 hash for a network 5-tuple.
//
// Specification: https://github.com/corelight/community-id-spec
//
// The hash provides a deterministic, flow-level identifier that remains the
// same across all tools/sensors capturing the same network connection.
// Format: "1:<base64(sha1(seed + ordered_src_ip + ordered_dst_ip + proto + pad + src_port + dst_port))>"

import (
	"crypto/sha1"  //nolint:gosec // Community ID spec mandates SHA-1
	"encoding/base64"
	"encoding/binary"
	"net"
)

// ipProtoTCP and ipProtoUDP are the IANA protocol numbers used by Community ID.
const (
	ipProtoTCP uint8 = 6
	ipProtoUDP uint8 = 17
)

// CommunityID returns the Community ID v1 string for a connection 5-tuple.
// Returns an empty string if the IP addresses cannot be parsed.
//
// Parameters:
//   - srcIP, dstIP: dotted-decimal or IPv6 string
//   - srcPort, dstPort: transport layer ports
//   - transport: "tcp" or "udp"
func CommunityID(srcIPStr, dstIPStr string, srcPort, dstPort int, transport string) string {
	srcIP := net.ParseIP(srcIPStr)
	dstIP := net.ParseIP(dstIPStr)
	if srcIP == nil || dstIP == nil {
		return ""
	}

	var proto uint8
	switch transport {
	case "tcp":
		proto = ipProtoTCP
	case "udp":
		proto = ipProtoUDP
	default:
		proto = ipProtoTCP
	}

	return communityIDFromIPs(srcIP, dstIP, srcPort, dstPort, proto)
}

// communityIDFromIPs computes the hash from parsed net.IP values.
func communityIDFromIPs(srcIP, dstIP net.IP, srcPort, dstPort int, proto uint8) string {
	// Normalise to 4-byte or 16-byte representations consistently.
	src4, dst4 := srcIP.To4(), dstIP.To4()

	var src, dst []byte
	if src4 != nil && dst4 != nil {
		src, dst = src4, dst4
	} else {
		src, dst = srcIP.To16(), dstIP.To16()
	}

	// Order the tuple so the smaller endpoint is always "source"
	// (gives the same ID regardless of which side of the flow generated this event).
	if !flowIsOrdered(src, srcPort, dst, dstPort) {
		src, dst = dst, src
		srcPort, dstPort = dstPort, srcPort
	}

	h := sha1.New() //nolint:gosec // mandated by spec

	// 2-byte seed — default 0 per spec
	h.Write([]byte{0, 0})

	h.Write(src)
	h.Write(dst)

	// Protocol byte + 1 padding byte
	h.Write([]byte{proto, 0})

	// Source and destination ports in network (big-endian) byte order
	var portBuf [2]byte

	binary.BigEndian.PutUint16(portBuf[:], uint16(srcPort))
	h.Write(portBuf[:])

	binary.BigEndian.PutUint16(portBuf[:], uint16(dstPort))
	h.Write(portBuf[:])

	return "1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// flowIsOrdered returns true when (srcIP, srcPort) ≤ (dstIP, dstPort) in the
// byte-comparison ordering required by the Community ID spec.
func flowIsOrdered(srcIP []byte, srcPort int, dstIP []byte, dstPort int) bool {
	for i := 0; i < len(srcIP) && i < len(dstIP); i++ {
		if srcIP[i] < dstIP[i] {
			return true
		}
		if srcIP[i] > dstIP[i] {
			return false
		}
	}
	return srcPort <= dstPort
}
