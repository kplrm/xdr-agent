// Package network - dns.go implements DNS query monitoring via a raw AF_PACKET socket.
//
// DNSCollector captures UDP DNS traffic (port 53) from all network interfaces by
// sniffing raw Ethernet frames. It emits ECS-compatible events for both DNS queries
// (QR=0) and DNS responses (QR=1), and attempts best-effort PID resolution by
// correlating the local socket with the shared /proc/net/udp snapshot.
//
// ECS event fields emitted:
//   - dns.question.name       — queried domain (FQDN)
//   - dns.question.type       — query type (A, AAAA, MX, CNAME, …)
//   - dns.question.class      — query class (IN)
//   - dns.response_code       — NOERROR, NXDOMAIN, SERVFAIL, … (responses only)
//   - dns.type                — "query" or "answer"
//   - dns.id                  — DNS transaction ID
//   - dns.answers[].name/type/ttl/data — resource records (responses only)
//   - dns.resolved_ips        — convenience list of A/AAAA resolved addresses
//   - dns.header_flags        — active DNS header flags (qr, aa, tc, rd, ra)
//   - network.transport       — "udp"
//   - network.type            — "ipv4" or "ipv6"
//   - network.community_id    — Community ID v1 for flow correlation
//   - local.ip / local.port — host endpoint
//   - remote.ip / remote.port — peer endpoint
//   - dns.client.ip/port, dns.server.ip/port — forwarded traffic without a host endpoint
//   - process.pid / process.name / process.executable (best-effort, may be absent)
//
// Limitations:
//   - DNS over TCP is not yet captured (uncommon for regular queries, needed for
//     zone transfers and large EDNS0 responses > 512 bytes).
//   - DNS over HTTPS (DoH) and DNS over TLS (DoT) require TLS inspection.
//   - PID resolution is subject to a race condition on short-lived UDP sockets.
//
//go:build linux

package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

// ── constants ─────────────────────────────────────────────────────────────────

const (
	// ethPAll captures all Ethernet frame types (ETH_P_ALL = 0x0003).
	ethPAll uint16 = 0x0003

	// dnsPort is the standard DNS port.
	dnsPort = 53

	// dnsMaxRead is the maximum raw frame size we will allocate.
	dnsMaxRead = 65536

	// dnsPendingTTL is how long we keep an unmatched query in the pending map.
	dnsPendingTTL = 5 * time.Second

	// dnsPendingClean is how often we purge expired pending entries.
	dnsPendingClean = 30 * time.Second

	// dnsMaxAnswers caps the number of RRs we parse in a single response (DoS guard).
	dnsMaxAnswers = 64
)

// ── internal types ────────────────────────────────────────────────────────────

// dnsPendingKey separates transactions that reuse a client socket or DNS ID.
type dnsPendingKey struct {
	txID    uint16
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
	qname   string
	qtype   uint16
	qclass  uint16
}

// dnsPendingEntry stores context for an in-flight DNS query waiting for its response.
type dnsPendingEntry struct {
	ts      time.Time
	qname   string
	qtype   string
	proc    *ProcessInfo
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
}

// dnsQuestion holds parsed question section fields.
type dnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// dnsRR holds a parsed resource record from the answer section.
type dnsRR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string // human-readable RDATA
}

// parsedDNS holds the decoded DNS message.
type parsedDNS struct {
	ID         uint16
	IsResponse bool // QR bit: false=query, true=response
	Opcode     uint8
	AA         bool  // Authoritative Answer
	TC         bool  // TrunCated
	RD         bool  // Recursion Desired
	RA         bool  // Recursion Available
	Rcode      uint8 // Response code
	Questions  []dnsQuestion
	Answers    []dnsRR
}

// ── DNSCollector ──────────────────────────────────────────────────────────────

// DNSCollector captures DNS queries and responses from the network using a raw
// AF_PACKET socket. It implements capability.Capability.
//
// DNS monitoring is kept as a separate collector from NetworkCollector because
// the two use fundamentally different mechanisms: NetworkCollector polls /proc/net/*
// for connection state, whereas DNSCollector sniffs packets from the NIC.
// Both live in the same network package and share helper functions.
type DNSCollector struct {
	workers   sync.WaitGroup
	pipeline  *events.Pipeline
	agentID   string
	hostname  string
	sockets   *SocketSnapshotProvider
	perimeter *Perimeter

	mu     sync.Mutex
	health capability.HealthStatus
	cancel context.CancelFunc
	sockfd int

	pendingMu sync.Mutex
	pending   map[dnsPendingKey]*dnsPendingEntry
}

// NewDNSCollector creates a new DNS traffic collector.
func NewDNSCollector(pipeline *events.Pipeline, agentID, hostname string) *DNSCollector {
	perimeter, _ := NewPerimeter(nil) // Built-in CIDRs are valid.
	return &DNSCollector{
		pipeline:  pipeline,
		agentID:   agentID,
		hostname:  hostname,
		perimeter: perimeter,
		sockfd:    -1,
		pending:   make(map[dnsPendingKey]*dnsPendingEntry),
	}
}

// SetSocketSnapshotProvider shares the connection collector's procfs observations.
// DNS never refreshes the provider or reads network tables on a packet arrival.
func (d *DNSCollector) SetSocketSnapshotProvider(provider *SocketSnapshotProvider) {
	d.sockets = provider
}

func (d *DNSCollector) SetPerimeter(perimeter *Perimeter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.perimeter = perimeter
}

// ── capability.Capability interface ──────────────────────────────────────────

func (d *DNSCollector) Name() string { return "telemetry.dns" }

func (d *DNSCollector) Init(_ capability.Dependencies) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.health = capability.HealthStarting
	return nil
}

// Start opens a raw AF_PACKET socket (requires CAP_NET_RAW) and launches the
// packet capture loop in a goroutine.
func (d *DNSCollector) Start(ctx context.Context) error {
	// AF_PACKET, SOCK_RAW — captures outgoing and incoming frames.
	// Protocol ETH_P_ALL (0x0003) in network byte order.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons16(ethPAll)))
	if err != nil {
		d.mu.Lock()
		d.health = capability.HealthDegraded
		d.mu.Unlock()
		return fmt.Errorf("dns collector: open raw socket (requires CAP_NET_RAW): %w", err)
	}

	// Set a 1-second receive timeout so the loop can honour ctx cancellation.
	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("dns collector: set recv timeout: %w", err)
	}

	childCtx, cancel := context.WithCancel(ctx)

	d.mu.Lock()
	d.cancel = cancel
	d.sockfd = fd
	d.health = capability.HealthRunning
	d.mu.Unlock()

	d.workers.Add(2)
	go func() { defer d.workers.Done(); d.captureLoop(childCtx, fd) }()
	go func() { defer d.workers.Done(); d.pendingCleaner(childCtx) }()

	log.Printf("dns collector: started raw socket capture on all interfaces")
	return nil
}

func (d *DNSCollector) Stop() error {
	d.mu.Lock()
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()
	// Receive timeout lets capture exit before its descriptor is closed and reused.
	d.workers.Wait()
	d.mu.Lock()
	if d.sockfd >= 0 {
		_ = syscall.Close(d.sockfd)
		d.sockfd = -1
	}
	d.health = capability.HealthStopped
	d.mu.Unlock()
	return nil
}

func (d *DNSCollector) Health() capability.HealthStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.health
}

// ── packet capture loop ───────────────────────────────────────────────────────

func (d *DNSCollector) captureLoop(ctx context.Context, fd int) {
	buf := make([]byte, dnsMaxRead)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR || err == syscall.EWOULDBLOCK {
				continue // timeout → check ctx
			}
			return // socket closed by Stop()
		}
		if n > 0 {
			addr, _ := from.(*syscall.SockaddrLinklayer)
			d.handleCapturedFrame(buf[:n], addr)
		}
	}
}

// pendingCleaner periodically removes stale pending query entries.
func (d *DNSCollector) pendingCleaner(ctx context.Context) {
	ticker := time.NewTicker(dnsPendingClean)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			d.pendingMu.Lock()
			for k, v := range d.pending {
				if now.Sub(v.ts) > dnsPendingTTL {
					delete(d.pending, k)
				}
			}
			d.pendingMu.Unlock()
		}
	}
}

// ── frame/packet parsing ─────────────────────────────────────────────────────

// handleCapturedFrame retains the received loopback copy of each datagram.
// AF_PACKET also delivers a PACKET_OUTGOING copy on loopback; emitting both
// would duplicate every local query/response. Outgoing packets on other devices
// and observations on different interfaces remain distinct: matching content
// alone cannot distinguish capture copies from real retransmissions.
func (d *DNSCollector) handleCapturedFrame(frame []byte, addr *syscall.SockaddrLinklayer) {
	if addr != nil && addr.Hatype == syscall.ARPHRD_LOOPBACK && addr.Pkttype == syscall.PACKET_OUTGOING {
		return
	}
	d.handleFrame(frame)
}

// handleFrame parses a raw Ethernet frame and dispatches DNS packets.
func (d *DNSCollector) handleFrame(frame []byte) {
	observedAt := time.Now().UTC()
	if len(frame) < 14 {
		return
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	l3Offset := 14

	// Handle 802.1Q / 802.1ad VLAN tags (4 extra bytes each).
	for etherType == 0x8100 || etherType == 0x88A8 {
		if len(frame) < l3Offset+4 {
			return
		}
		etherType = binary.BigEndian.Uint16(frame[l3Offset+2 : l3Offset+4])
		l3Offset += 4
	}

	var srcIP, dstIP string
	var protocol uint8
	var l4Offset int

	switch etherType {
	case 0x0800: // IPv4
		if len(frame) < l3Offset+20 {
			return
		}
		ihl := int(frame[l3Offset]&0x0F) * 4
		if ihl < 20 || l3Offset+ihl > len(frame) {
			return
		}
		// Drop fragments (IP flags fragment-offset field).
		if binary.BigEndian.Uint16(frame[l3Offset+6:l3Offset+8])&0x1FFF != 0 {
			return
		}
		protocol = frame[l3Offset+9]
		srcIP = net.IP(frame[l3Offset+12 : l3Offset+16]).String()
		dstIP = net.IP(frame[l3Offset+16 : l3Offset+20]).String()
		l4Offset = l3Offset + ihl

	case 0x86DD: // IPv6 (simplified: no extension headers)
		if len(frame) < l3Offset+40 {
			return
		}
		protocol = frame[l3Offset+6] // Next Header
		srcIP = net.IP(frame[l3Offset+8 : l3Offset+24]).String()
		dstIP = net.IP(frame[l3Offset+24 : l3Offset+40]).String()
		l4Offset = l3Offset + 40

	default:
		return
	}

	if protocol != 17 { // UDP only
		return
	}
	if len(frame) < l4Offset+8 {
		return
	}

	srcPort := binary.BigEndian.Uint16(frame[l4Offset : l4Offset+2])
	dstPort := binary.BigEndian.Uint16(frame[l4Offset+2 : l4Offset+4])

	if srcPort != dnsPort && dstPort != dnsPort {
		return // not DNS
	}

	udpPayloadLen := int(binary.BigEndian.Uint16(frame[l4Offset+4:l4Offset+6])) - 8
	dnsStart := l4Offset + 8
	if udpPayloadLen <= 0 || dnsStart >= len(frame) {
		return
	}
	if dnsStart+udpPayloadLen > len(frame) {
		udpPayloadLen = len(frame) - dnsStart
	}
	if udpPayloadLen < 12 {
		return // DNS header minimum
	}

	dnsPayload := frame[dnsStart : dnsStart+udpPayloadLen]

	msg, err := parseDNSMessage(dnsPayload)
	if err != nil || len(msg.Questions) == 0 {
		return
	}

	d.emitDNSEventAt(msg, srcIP, dstIP, srcPort, dstPort, nil, observedAt)
}

// resolveUDPSocket uses the most recent shared socket snapshot. A newly created
// socket may remain unattributed until the next collection cycle.
func (d *DNSCollector) resolveUDPSocket(localIP string, localPort int, remoteIP string, remotePort int) *ProcessInfo {
	if d.sockets == nil {
		return nil
	}
	snap := d.sockets.Current()
	if snap == nil {
		return nil
	}
	return snap.ResolveUDPFlow(localIP, localPort, remoteIP, remotePort)
}

// ── DNS event emission ────────────────────────────────────────────────────────

func (d *DNSCollector) emitDNSEvent(
	msg *parsedDNS,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	proc *ProcessInfo,
) {
	d.emitDNSEventAt(msg, srcIP, dstIP, srcPort, dstPort, proc, time.Now().UTC())
}

func (d *DNSCollector) emitDNSEventAt(
	msg *parsedDNS,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	proc *ProcessInfo,
	ts time.Time,
) {
	q := msg.Questions[0]
	qname := q.Name
	qtype := qtypeString(q.Type)

	dnsType := "query"
	eventType := "dns.query"
	if msg.IsResponse {
		dnsType = "answer"
		eventType = "dns.answer"
	}

	netTransport := "udp"
	netIPType := "ipv4"
	if strings.Contains(srcIP, ":") {
		netIPType = "ipv6"
	}

	questionMap := map[string]interface{}{
		"name":              qname,
		"type":              qtype,
		"class":             qclassString(q.Class),
		"registered_domain": registeredDomain(qname),
	}

	dnsMap := map[string]interface{}{
		"id":                  msg.ID,
		"type":                dnsType,
		"question":            questionMap,
		"op_code":             opcodeString(msg.Opcode),
		"recursion_desired":   msg.RD,
		"recursion_available": msg.RA,
		"authoritative":       msg.AA,
		"header_flags":        buildDNSHeaderFlags(msg),
	}

	if msg.IsResponse {
		dnsMap["response_code"] = rcodeString(msg.Rcode)
	}

	// Build answer records and collect resolved IPs (responses only).
	if msg.IsResponse && len(msg.Answers) > 0 {
		var answersSlice []map[string]interface{}
		var resolvedIPs []string

		for _, rr := range msg.Answers {
			entry := map[string]interface{}{
				"name": rr.Name,
				"type": qtypeString(rr.Type),
				"ttl":  rr.TTL,
				"data": rr.Data,
			}
			answersSlice = append(answersSlice, entry)
			if rr.Type == 1 || rr.Type == 28 { // A or AAAA
				resolvedIPs = append(resolvedIPs, rr.Data)
			}
		}

		dnsMap["answers"] = answersSlice
		dnsMap["answers_count"] = len(answersSlice)
		if len(resolvedIPs) > 0 {
			dnsMap["resolved_ips"] = resolvedIPs
		}
	}

	cid := CommunityID(srcIP, dstIP, int(srcPort), int(dstPort), netTransport)
	d.mu.Lock()
	perimeter := d.perimeter.snapshot()
	d.mu.Unlock()

	payload := map[string]interface{}{
		"dns": dnsMap,
		"network": map[string]interface{}{
			"transport":    netTransport,
			"type":         netIPType,
			"community_id": cid,
			"direction":    perimeter.Direction(srcIP, dstIP),
		},
	}

	srcLocal, dstLocal := perimeter.isLocal(net.ParseIP(srcIP)), perimeter.isLocal(net.ParseIP(dstIP))
	localIP, remoteIP, localPort, remotePort := srcIP, dstIP, srcPort, dstPort
	if srcLocal || dstLocal {
		// When both endpoints are local, keep the DNS client on the local side.
		if dstLocal && (!srcLocal || msg.IsResponse) {
			localIP, remoteIP, localPort, remotePort = dstIP, srcIP, dstPort, srcPort
		}
		payload["local"] = map[string]interface{}{"ip": localIP, "port": int(localPort)}
		payload["remote"] = map[string]interface{}{"ip": remoteIP, "port": int(remotePort)}
		if proc == nil {
			proc = d.resolveUDPSocket(localIP, int(localPort), remoteIP, int(remotePort))
		}
	} else {
		// Forwarded packets have DNS roles, but no proven host endpoint.
		if msg.IsResponse {
			localIP, remoteIP, localPort, remotePort = dstIP, srcIP, dstPort, srcPort
		}
		dnsMap["client"] = map[string]interface{}{"ip": localIP, "port": int(localPort)}
		dnsMap["server"] = map[string]interface{}{"ip": remoteIP, "port": int(remotePort)}
	}

	// For queries: store in pending map to correlate with later responses.
	if !msg.IsResponse {
		key := dnsTransactionKey(msg, srcIP, dstIP, srcPort, dstPort)
		d.pendingMu.Lock()
		d.pending[key] = &dnsPendingEntry{
			ts:      ts,
			qname:   qname,
			qtype:   qtype,
			proc:    proc,
			srcIP:   srcIP,
			dstIP:   dstIP,
			srcPort: srcPort,
			dstPort: dstPort,
		}
		d.pendingMu.Unlock()
	}

	// For responses: try to enrich with original query context if proc was not resolved.
	// The response comes from the resolver (srcPort==53); look up the matching query
	// where query srcIP == response dstIP and query srcPort == response dstPort.
	if msg.IsResponse {
		key := dnsTransactionKey(msg, dstIP, srcIP, dstPort, srcPort)
		d.pendingMu.Lock()
		if pending, ok := d.pending[key]; ok {
			if proc == nil && ts.Sub(pending.ts) <= dnsPendingTTL {
				proc = pending.proc
			}
			delete(d.pending, key)
		}
		d.pendingMu.Unlock()
	}

	if proc != nil && (srcLocal || dstLocal) {
		payload["process"] = map[string]interface{}{
			"pid":        proc.PID,
			"name":       proc.Name,
			"executable": proc.Executable,
		}
		if proc.EntityID != "" {
			payload["process"].(map[string]interface{})["entity_id"] = proc.EntityID
		}
	}

	event := events.Event{
		ID:        fmt.Sprintf("dns-%d-%d", msg.ID, rand.Int63()),
		Timestamp: ts,
		Type:      eventType,
		Category:  "network",
		Kind:      "event",
		Module:    "telemetry.dns",
		AgentID:   d.agentID,
		Hostname:  d.hostname,
		Payload:   payload,
		Tags:      []string{"dns", "network", "telemetry"},
	}

	d.pipeline.Emit(event)
}

func dnsTransactionKey(msg *parsedDNS, clientIP, resolverIP string, clientPort, resolverPort uint16) dnsPendingKey {
	q := msg.Questions[0]
	return dnsPendingKey{
		txID: msg.ID, srcIP: clientIP, srcPort: clientPort,
		dstIP: resolverIP, dstPort: resolverPort,
		qname: strings.ToLower(q.Name), qtype: q.Type, qclass: q.Class,
	}
}

// ── DNS wire format parser ────────────────────────────────────────────────────

// parseDNSMessage decodes a DNS message from the wire format (RFC 1035).
func parseDNSMessage(buf []byte) (*parsedDNS, error) {
	if len(buf) < 12 {
		return nil, fmt.Errorf("dns message too short (%d bytes)", len(buf))
	}

	flags := binary.BigEndian.Uint16(buf[2:4])
	msg := &parsedDNS{
		ID:         binary.BigEndian.Uint16(buf[0:2]),
		IsResponse: (flags & 0x8000) != 0,
		Opcode:     uint8((flags >> 11) & 0x0F),
		AA:         (flags & 0x0400) != 0,
		TC:         (flags & 0x0200) != 0,
		RD:         (flags & 0x0100) != 0,
		RA:         (flags & 0x0080) != 0,
		Rcode:      uint8(flags & 0x000F),
	}

	qdCount := int(binary.BigEndian.Uint16(buf[4:6]))
	anCount := int(binary.BigEndian.Uint16(buf[6:8]))
	offset := 12

	// Parse questions.
	for i := 0; i < qdCount && offset < len(buf); i++ {
		name, next, err := parseDNSName(buf, offset)
		if err != nil {
			break
		}
		offset = next
		if offset+4 > len(buf) {
			break
		}
		msg.Questions = append(msg.Questions, dnsQuestion{
			Name:  name,
			Type:  binary.BigEndian.Uint16(buf[offset : offset+2]),
			Class: binary.BigEndian.Uint16(buf[offset+2 : offset+4]),
		})
		offset += 4
	}

	// Parse answer RRs (capped to prevent DoS).
	cap := anCount
	if cap > dnsMaxAnswers {
		cap = dnsMaxAnswers
	}
	for i := 0; i < cap && offset < len(buf); i++ {
		name, next, err := parseDNSName(buf, offset)
		if err != nil {
			break
		}
		offset = next
		if offset+10 > len(buf) {
			break
		}
		rrType := binary.BigEndian.Uint16(buf[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(buf[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(buf[offset+4 : offset+8])
		rdLen := int(binary.BigEndian.Uint16(buf[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(buf) {
			break
		}
		rdataStart := offset
		rdata := buf[rdataStart : rdataStart+rdLen]
		offset += rdLen

		msg.Answers = append(msg.Answers, dnsRR{
			Name:  name,
			Type:  rrType,
			Class: rrClass,
			TTL:   ttl,
			Data:  parseRDATA(buf, rdataStart, rrType, rdata),
		})
	}

	return msg, nil
}

// parseDNSName decodes a DNS label sequence (with pointer compression support)
// starting at buf[offset]. Returns the resolved FQDN and the offset of the
// first byte AFTER the name in the original message (not following pointers).
func parseDNSName(buf []byte, offset int) (string, int, error) {
	var labels []string
	origEnd := -1 // records where the caller should continue after this name
	pos := offset
	seen := make(map[int]bool) // pointer loop detection

	for {
		if pos >= len(buf) {
			return "", 0, fmt.Errorf("dns name out of bounds at %d", pos)
		}
		if seen[pos] {
			return "", 0, fmt.Errorf("dns name compression loop at %d", pos)
		}
		seen[pos] = true

		lbl := int(buf[pos])

		if lbl == 0 { // root / end of name
			if origEnd < 0 {
				origEnd = pos + 1
			}
			break
		}

		if lbl&0xC0 == 0xC0 { // pointer
			if pos+1 >= len(buf) {
				return "", 0, fmt.Errorf("dns pointer out of bounds at %d", pos)
			}
			if origEnd < 0 {
				origEnd = pos + 2
			}
			ptr := int(binary.BigEndian.Uint16(buf[pos:pos+2]) & 0x3FFF)
			pos = ptr
			continue
		}

		if lbl&0xC0 != 0 {
			return "", 0, fmt.Errorf("unsupported dns label type 0x%02x at %d", lbl, pos)
		}

		// Plain label: [length][bytes]
		labelLen := lbl
		pos++
		if pos+labelLen > len(buf) {
			return "", 0, fmt.Errorf("dns label extends past buffer")
		}
		labels = append(labels, string(buf[pos:pos+labelLen]))
		pos += labelLen
	}

	if origEnd < 0 {
		origEnd = pos
	}

	name := strings.Join(labels, ".")
	if name == "" {
		name = "."
	}
	return name, origEnd, nil
}

// parseRDATA converts raw RDATA bytes into a human-readable string.
// buf is the full DNS message (needed for name compression in CNAME/MX/NS/PTR).
// rdataStart is the offset of RDATA in buf.
func parseRDATA(buf []byte, rdataStart int, rrType uint16, rdata []byte) string {
	switch rrType {
	case 1: // A
		if len(rdata) == 4 {
			return net.IPv4(rdata[0], rdata[1], rdata[2], rdata[3]).String()
		}
	case 28: // AAAA
		if len(rdata) == 16 {
			return net.IP(rdata).String()
		}
	case 5, 2, 12: // CNAME, NS, PTR — RDATA is a DNS name
		if name, _, err := parseDNSName(buf, rdataStart); err == nil {
			return name
		}
	case 15: // MX — 2-byte preference + DNS name
		if len(rdata) >= 2 {
			pref := binary.BigEndian.Uint16(rdata[0:2])
			if name, _, err := parseDNSName(buf, rdataStart+2); err == nil {
				return fmt.Sprintf("%d %s", pref, name)
			}
		}
	case 33: // SRV — priority(2) weight(2) port(2) target(name)
		if len(rdata) >= 6 {
			prio := binary.BigEndian.Uint16(rdata[0:2])
			weight := binary.BigEndian.Uint16(rdata[2:4])
			port := binary.BigEndian.Uint16(rdata[4:6])
			if name, _, err := parseDNSName(buf, rdataStart+6); err == nil {
				return fmt.Sprintf("%d %d %d %s", prio, weight, port, name)
			}
		}
	case 16: // TXT — series of [len][bytes]
		var parts []string
		i := 0
		for i < len(rdata) {
			l := int(rdata[i])
			i++
			if i+l > len(rdata) {
				break
			}
			parts = append(parts, string(rdata[i:i+l]))
			i += l
		}
		return strings.Join(parts, "")
	}
	// Fallback: hex dump.
	if len(rdata) <= 32 {
		return fmt.Sprintf("0x%x", rdata)
	}
	return fmt.Sprintf("0x%x…(%d bytes)", rdata[:16], len(rdata))
}

// ── string helpers ────────────────────────────────────────────────────────────

// qtypeString converts a DNS QTYPE code to its mnemonic (e.g. 1 → "A").
func qtypeString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 35:
		return "NAPTR"
	case 41:
		return "OPT"
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 47:
		return "NSEC"
	case 48:
		return "DNSKEY"
	case 255:
		return "ANY"
	case 257:
		return "CAA"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// qclassString converts a DNS QCLASS code to its mnemonic.
func qclassString(c uint16) string {
	switch c {
	case 1:
		return "IN"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", c)
	}
}

// rcodeString converts a DNS RCODE to its mnemonic.
func rcodeString(rc uint8) string {
	switch rc {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	case 6:
		return "YXDOMAIN"
	case 7:
		return "YXRRSET"
	case 8:
		return "NXRRSET"
	case 9:
		return "NOTAUTH"
	case 10:
		return "NOTZONE"
	default:
		return fmt.Sprintf("RCODE%d", rc)
	}
}

// opcodeString converts a DNS OPCODE to its mnemonic.
func opcodeString(op uint8) string {
	switch op {
	case 0:
		return "QUERY"
	case 1:
		return "IQUERY"
	case 2:
		return "STATUS"
	case 4:
		return "NOTIFY"
	case 5:
		return "UPDATE"
	default:
		return fmt.Sprintf("OPCODE%d", op)
	}
}

// buildDNSHeaderFlags returns the active DNS header flag names (ECS dns.header_flags).
func buildDNSHeaderFlags(msg *parsedDNS) []string {
	var flags []string
	if msg.IsResponse {
		flags = append(flags, "qr")
	}
	if msg.AA {
		flags = append(flags, "aa")
	}
	if msg.TC {
		flags = append(flags, "tc")
	}
	if msg.RD {
		flags = append(flags, "rd")
	}
	if msg.RA {
		flags = append(flags, "ra")
	}
	return flags
}

// registeredDomain extracts a best-effort registered domain from a FQDN by
// returning the last two DNS labels (e.g. "sub.example.com" → "example.com").
// A proper implementation would use the Public Suffix List (PSL).
func registeredDomain(name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return name
}

// htons16 converts a uint16 from host byte order to network (big-endian) byte order.
// Needed for the AF_PACKET protocol argument.
func htons16(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}
