// Package network provides network connection monitoring and DNS query logging.
//
// The connection tracker polls /proc/net/{tcp,tcp6,udp,udp6} to build a snapshot
// of active connections, diffs against the previous snapshot, and emits events
// for opened/closed connections.
//
// Future: upgrade to netlink SOCK_DIAG or eBPF kprobes for real-time events.
package network

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

const (
	defaultNetProcRoot = "/proc"
	defaultNetInterval = 15 * time.Second
)

// tcpStateNames maps the hex TCP state codes from /proc/net/tcp to names.
var tcpStateNames = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

// ConnectionInfo holds a parsed network connection from /proc/net/*.
type ConnectionInfo struct {
	Protocol   string `json:"protocol"` // tcp, tcp6, udp, udp6
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	UID        int    `json:"uid"`
	Inode      uint64 `json:"inode"`
}

// key returns a stable string suitable for snapshot diffing.
func (c ConnectionInfo) key() string {
	return fmt.Sprintf("%s:%s:%d->%s:%d:%s",
		c.Protocol, c.LocalAddr, c.LocalPort,
		c.RemoteAddr, c.RemotePort, c.State)
}

// NetworkCollector tracks TCP/UDP connections by periodically polling
// /proc/net/* and emitting events for changes. It implements capability.Capability.
type NetworkCollector struct {
	pipeline *events.Pipeline
	agentID  string
	hostname string
	interval time.Duration
	procRoot string // path to /proc; defaults to /proc

	mu       sync.Mutex
	health   capability.HealthStatus
	cancel   context.CancelFunc
	known    map[string]ConnectionInfo
	baseline bool
}

// NewNetworkCollector creates a new network telemetry collector.
//
// Parameters:
//   - pipeline: the central event bus to emit events into
//   - agentID:  the enrolled agent identifier
//   - hostname: the host's name (for event enrichment)
//   - interval: how often to scan /proc/net (0 → 15 s default)
func NewNetworkCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *NetworkCollector {
	if interval <= 0 {
		interval = defaultNetInterval
	}
	return &NetworkCollector{
		pipeline: pipeline,
		agentID:  agentID,
		hostname: hostname,
		interval: interval,
		procRoot: defaultNetProcRoot,
		health:   capability.HealthStopped,
		known:    make(map[string]ConnectionInfo),
	}
}

// SetProcRoot overrides the default /proc path (useful for testing).
func (n *NetworkCollector) SetProcRoot(path string) { n.procRoot = path }

// ── capability.Capability interface ──────────────────────────────────────────

func (n *NetworkCollector) Name() string { return "telemetry.network" }

func (n *NetworkCollector) Init(_ capability.Dependencies) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.health = capability.HealthStarting
	return nil
}

func (n *NetworkCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	n.mu.Lock()
	n.cancel = cancel
	n.health = capability.HealthRunning
	n.mu.Unlock()

	go n.loop(childCtx)
	return nil
}

func (n *NetworkCollector) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cancel != nil {
		n.cancel()
	}
	n.health = capability.HealthStopped
	return nil
}

func (n *NetworkCollector) Health() capability.HealthStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.health
}

// ── internal ─────────────────────────────────────────────────────────────────

// loop runs the periodic network scan cycle.
func (n *NetworkCollector) loop(ctx context.Context) {
	n.scan()

	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.scan()
		}
	}
}

// scan reads /proc/net/{tcp,tcp6,udp,udp6}, diffs with the previous snapshot,
// and emits events for new and closed connections.
func (n *NetworkCollector) scan() {
	protocols := []string{"tcp", "tcp6", "udp", "udp6"}
	snapshot := make(map[string]ConnectionInfo)

	parsed := 0
	for _, proto := range protocols {
		path := filepath.Join(n.procRoot, "net", proto)
		conns, err := ParseProcNet(path, proto)
		if err != nil {
			continue // file may not exist (e.g. no IPv6)
		}
		for _, c := range conns {
			snapshot[c.key()] = c
		}
		parsed += len(conns)
	}

	n.mu.Lock()
	prevKnown := n.known
	wasBaseline := n.baseline
	n.known = snapshot
	n.baseline = true
	n.health = capability.HealthRunning
	n.mu.Unlock()

	if !wasBaseline {
		log.Printf("network collector: baseline established with %d connections", parsed)
		return
	}

	// Opened connections (in snapshot but not in previous)
	for key, conn := range snapshot {
		if _, existed := prevKnown[key]; !existed {
			n.emitEvent("network.connection_opened", conn)
		}
	}

	// Closed connections (in previous but not in snapshot)
	for key, conn := range prevKnown {
		if _, exists := snapshot[key]; !exists {
			n.emitEvent("network.connection_closed", conn)
		}
	}
}

// emitEvent publishes a network connection event into the pipeline.
func (n *NetworkCollector) emitEvent(eventType string, conn ConnectionInfo) {
	event := events.Event{
		ID:        fmt.Sprintf("net-%s-%d", eventType, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		Category:  "network",
		Kind:      "event",
		Severity:  events.SeverityInfo,
		Module:    "telemetry.network",
		AgentID:   n.agentID,
		Hostname:  n.hostname,
		Payload: map[string]interface{}{
			"network": map[string]interface{}{
				"protocol":    conn.Protocol,
				"transport":   transport(conn.Protocol),
				"direction":   direction(conn),
				"local_addr":  conn.LocalAddr,
				"local_port":  conn.LocalPort,
				"remote_addr": conn.RemoteAddr,
				"remote_port": conn.RemotePort,
				"state":       conn.State,
				"uid":         conn.UID,
				"inode":       conn.Inode,
			},
		},
		Tags: []string{"network", "telemetry"},
	}

	n.pipeline.Emit(event)
	log.Printf("network collector: %s %s %s:%d -> %s:%d (%s)",
		eventType, conn.Protocol, conn.LocalAddr, conn.LocalPort,
		conn.RemoteAddr, conn.RemotePort, conn.State)
}

// direction infers the network direction from the connection state and addresses.
func direction(conn ConnectionInfo) string {
	if conn.State == "LISTEN" {
		return "listening"
	}
	if conn.RemoteAddr == "0.0.0.0" || conn.RemoteAddr == "::" {
		return "listening"
	}
	return "outbound"
}

// transport extracts the L4 protocol name (tcp/udp) from the full protocol
// string (which may include "6" for IPv6 variants).
func transport(protocol string) string {
	if strings.HasPrefix(protocol, "tcp") {
		return "tcp"
	}
	return "udp"
}

// ── public parsing helpers (testable) ────────────────────────────────────────

// ParseProcNet parses a /proc/net/{tcp,tcp6,udp,udp6} file and returns the
// list of connections found.
func ParseProcNet(path, protocol string) ([]ConnectionInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []ConnectionInfo
	scanner := bufio.NewScanner(f)

	// Skip the header line.
	if !scanner.Scan() {
		return conns, nil
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localAddr, localPort, err1 := parseAddr(fields[1], protocol)
		remoteAddr, remotePort, err2 := parseAddr(fields[2], protocol)
		if err1 != nil || err2 != nil {
			continue
		}

		stateHex := strings.ToUpper(fields[3])
		state := tcpStateNames[stateHex]
		if state == "" {
			state = stateHex
		}

		uid, _ := strconv.Atoi(fields[7])
		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		conns = append(conns, ConnectionInfo{
			Protocol:   protocol,
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      state,
			UID:        uid,
			Inode:      inode,
		})
	}

	return conns, scanner.Err()
}

// parseAddr splits "HEXIP:HEXPORT" from /proc/net/* into a human-readable
// IP string and integer port.
func parseAddr(s, protocol string) (string, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr: %s", s)
	}

	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse port: %w", err)
	}

	ipHex := parts[0]
	var ip string
	if strings.HasSuffix(protocol, "6") {
		ip, err = ParseIPv6Hex(ipHex)
	} else {
		ip, err = ParseIPv4Hex(ipHex)
	}
	if err != nil {
		return "", 0, err
	}

	return ip, int(port), nil
}

// ParseIPv4Hex converts an 8-character hex string from /proc/net/tcp (stored
// in host byte order on little-endian) to a dotted-quad IPv4 string.
//
// Example: "0100007F" → "127.0.0.1"
func ParseIPv4Hex(hexStr string) (string, error) {
	if len(hexStr) != 8 {
		return "", fmt.Errorf("invalid ipv4 hex len: %d", len(hexStr))
	}
	val, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return "", err
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(val))
	return net.IPv4(b[0], b[1], b[2], b[3]).String(), nil
}

// ParseIPv6Hex converts a 32-character hex string from /proc/net/tcp6 to a
// standard IPv6 string. The 16 bytes are stored as four 32-bit words, each
// in host (little-endian) byte order.
//
// Example: "00000000000000000000000001000000" → "::1"
func ParseIPv6Hex(hexStr string) (string, error) {
	if len(hexStr) != 32 {
		return "", fmt.Errorf("invalid ipv6 hex len: %d", len(hexStr))
	}
	b := make([]byte, 16)
	for i := 0; i < 4; i++ {
		group := hexStr[i*8 : (i+1)*8]
		val, err := strconv.ParseUint(group, 16, 32)
		if err != nil {
			return "", err
		}
		binary.LittleEndian.PutUint32(b[i*4:], uint32(val))
	}
	ip := net.IP(b)
	return ip.String(), nil
}
