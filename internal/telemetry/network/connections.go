// Package network provides network connection monitoring and DNS query logging.
//
// The connection tracker polls /proc/net/{tcp,tcp6,udp,udp6} to build a snapshot
// of active connections, diffs against the previous snapshot, and emits events
// for opened/closed connections.
//
// Events are emitted using ECS-compatible field names:
//   - source.ip / source.port   — the local endpoint
//   - destination.ip / destination.port — the remote endpoint
//   - source.user.id / source.user.name — process owner resolved from UID
//   - network.transport — "tcp" or "udp"
//   - network.type      — "ipv4" or "ipv6"
//   - network.direction — perimeter direction, or "unknown"
//   - network.community_id — deterministic 5-tuple flow identifier (Community ID v1)
//   - network.state     — TCP state string (non-ECS; useful for security analysis)
//   - process.pid / process.name / process.executable — enriched on opened events
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
	"strconv"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

const (
	defaultNetProcRoot = "/proc"
	defaultNetInterval = time.Second
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
	return fmt.Sprintf("%s:%d", c.flowKey(), c.Inode)
}

func (c ConnectionInfo) flowKey() string {
	return fmt.Sprintf("%s:%s:%d->%s:%d",
		c.Protocol, c.LocalAddr, c.LocalPort,
		c.RemoteAddr, c.RemotePort)
}

// NetworkCollector tracks TCP/UDP connections by periodically polling
// /proc/net/* and emitting events for changes. It implements capability.Capability.
type NetworkCollector struct {
	sourceMu        sync.RWMutex
	workers         sync.WaitGroup
	pipeline        *events.Pipeline
	agentID         string
	hostname        string
	interval        time.Duration
	intervalChanged chan struct{}
	procRoot        string // path to /proc; defaults to /proc
	etcPasswd       string // path to /etc/passwd for UID → username resolution
	sockets         *SocketSnapshotProvider
	perimeter       *Perimeter
	classification  *Perimeter // Last immutable host-address snapshot.

	mu         sync.Mutex
	health     capability.HealthStatus
	cancel     context.CancelFunc
	known      map[string]ConnectionInfo
	owners     map[string]*ProcessInfo
	directions map[string]string
	baseline   bool
}

// NewNetworkCollector creates a new network telemetry collector.
//
// Parameters:
//   - pipeline: the central event bus to emit events into
//   - agentID:  the enrolled agent identifier
//   - hostname: the host's name (for event enrichment)
//   - interval: how often to scan /proc/net (0 → 1 s default)
func NewNetworkCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *NetworkCollector {
	if interval <= 0 {
		interval = defaultNetInterval
	}
	perimeter, _ := NewPerimeter(nil)
	return &NetworkCollector{
		pipeline:        pipeline,
		agentID:         agentID,
		hostname:        hostname,
		interval:        interval,
		intervalChanged: make(chan struct{}, 1),
		procRoot:        defaultNetProcRoot,
		etcPasswd:       "/etc/passwd",
		health:          capability.HealthStopped,
		known:           make(map[string]ConnectionInfo),
		owners:          make(map[string]*ProcessInfo),
		directions:      make(map[string]string),
		sockets:         NewSocketSnapshotProvider(defaultNetProcRoot, agentID),
		perimeter:       perimeter,
	}
}

// SetProcRoot overrides the default /proc path (useful for testing).
func (n *NetworkCollector) SetProcRoot(path string) {
	n.sourceMu.Lock()
	defer n.sourceMu.Unlock()
	n.procRoot = path
	n.sockets.setProcRoot(path)
}

func (n *NetworkCollector) SetSocketSnapshotProvider(provider *SocketSnapshotProvider) {
	n.sourceMu.Lock()
	defer n.sourceMu.Unlock()
	n.sockets = provider
}

func (n *NetworkCollector) SetPerimeter(perimeter *Perimeter) {
	n.sourceMu.Lock()
	defer n.sourceMu.Unlock()
	n.perimeter = perimeter
	// Retained handshake classifications belong to the previous perimeter.
	n.mu.Lock()
	defer n.mu.Unlock()
	n.directions = make(map[string]string)
	n.classification = perimeter.snapshot()
	for key, conn := range n.known {
		n.directions[key] = n.classification.ConnectionDirection(conn)
	}
}

// SetInterval changes the running scan schedule without losing socket history.
func (n *NetworkCollector) SetInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	n.mu.Lock()
	n.interval = interval
	n.mu.Unlock()
	select {
	case n.intervalChanged <- struct{}{}:
	default:
	}
}

func (n *NetworkCollector) scanInterval() time.Duration {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.interval
}

// SetEtcPasswd overrides the /etc/passwd path (useful for testing).
func (n *NetworkCollector) SetEtcPasswd(path string) {
	n.sourceMu.Lock()
	defer n.sourceMu.Unlock()
	n.etcPasswd = path
}

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

	n.workers.Add(1)
	go func() { defer n.workers.Done(); n.loop(childCtx) }()
	return nil
}

func (n *NetworkCollector) Stop() error {
	n.mu.Lock()
	if n.cancel != nil {
		n.cancel()
	}
	n.mu.Unlock()
	n.workers.Wait()
	n.mu.Lock()
	n.health = capability.HealthStopped
	n.mu.Unlock()
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

	ticker := time.NewTicker(n.scanInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-n.intervalChanged:
			ticker.Reset(n.scanInterval())
		case <-ticker.C:
			n.scan()
		}
	}
}

// scan reads /proc/net/{tcp,tcp6,udp,udp6}, diffs with the previous snapshot,
// and emits events for new and closed connections.
func (n *NetworkCollector) scan() {
	n.sourceMu.RLock()
	defer n.sourceMu.RUnlock()
	perimeter := n.perimeter.snapshot()
	if n.classification != nil && n.classification.local != perimeter.local {
		for key, conn := range n.known {
			if n.classification.Direction(conn.LocalAddr, conn.RemoteAddr) != perimeter.Direction(conn.LocalAddr, conn.RemoteAddr) {
				n.directions[key] = perimeter.ConnectionDirection(conn)
			}
		}
	}
	n.classification = perimeter
	collected := n.sockets.Refresh()
	snapshot := make(map[string]ConnectionInfo)

	n.mu.Lock()
	prevKnown := n.known
	wasBaseline := n.baseline
	// A failed table read is not evidence that every socket disappeared.
	for key, conn := range prevKnown {
		if !collected.readOK[conn.Protocol] {
			snapshot[key] = conn
		}
	}
	previousFlows := make(map[string][]string)
	for key, conn := range prevKnown {
		previousFlows[conn.flowKey()] = append(previousFlows[conn.flowKey()], key)
	}
	for _, conn := range collected.Connections {
		key := conn.key()
		// Keep a stable instance across inode loss and TCP handshake inode
		// assignment. A later socket reusing a TIME_WAIT tuple is a new instance.
		if matches := previousFlows[conn.flowKey()]; len(matches) == 1 {
			previous := prevKnown[matches[0]]
			promoted := previous.Inode == 0 && strings.HasPrefix(conn.Protocol, "tcp") &&
				(previous.State == "SYN_RECV" || previous.State == "SYN_SENT")
			if conn.Inode == previous.Inode || conn.Inode == 0 || promoted {
				key = matches[0]
			}
		}
		snapshot[key] = conn
	}
	n.known = snapshot
	n.baseline = true
	n.health = capability.HealthRunning
	n.mu.Unlock()

	if !wasBaseline {
		for key, conn := range snapshot {
			n.directions[key] = perimeter.ConnectionDirection(conn)
		}
		log.Printf("network collector: baseline established with %d connections", len(snapshot))
		return
	}

	// Enrich a generation in one descriptor walk, retaining context for closure.
	for key, conn := range snapshot {
		previous, existed := prevKnown[key]
		if candidate := perimeter.ConnectionDirection(conn); candidate != "unknown" || n.directions[key] == "" {
			n.directions[key] = candidate
		}
		if n.owners[key] == nil && collected.readOK[conn.Protocol] {
			n.owners[key] = collected.ResolveInode(conn.Inode)
		}
		if !existed {
			n.emitEvent("network.connection_opened", conn, n.owners[key], n.directions[key], collected.ObservedAt)
		} else if previous.State != conn.State {
			n.emitEvent("network.connection_state_changed", conn, n.owners[key], n.directions[key], collected.ObservedAt)
		}
	}

	// Closed connections (in previous but not in snapshot)
	for key, conn := range prevKnown {
		if _, exists := snapshot[key]; !exists {
			n.emitEvent("network.connection_closed", conn, n.owners[key], n.directions[key], collected.ObservedAt)
			delete(n.owners, key)
			delete(n.directions, key)
		}
	}
}

// emitEvent publishes a network connection event into the pipeline.
// proc is optional and may contain the socket's last observed owner.
func (n *NetworkCollector) emitEvent(eventType string, conn ConnectionInfo, proc *ProcessInfo, direction string, observedAt time.Time) {
	tr := transport(conn.Protocol)
	netType := networkType(conn.Protocol)

	// Resolve username from UID.
	userName := usernameForUID(n.etcPasswd, conn.UID)

	// Compute Community ID hash.
	cid := CommunityID(conn.LocalAddr, conn.RemoteAddr, conn.LocalPort, conn.RemotePort, tr)

	sourceMap := map[string]interface{}{
		"ip":   conn.LocalAddr,
		"port": conn.LocalPort,
		"user": map[string]interface{}{
			"id":   strconv.Itoa(conn.UID),
			"name": userName,
		},
	}

	destinationMap := map[string]interface{}{
		"ip":   conn.RemoteAddr,
		"port": conn.RemotePort,
	}

	networkMap := map[string]interface{}{
		"transport":    tr,
		"type":         netType,
		"direction":    direction,
		"community_id": cid,
		"state":        conn.State,
		"inode":        conn.Inode,
	}

	payload := map[string]interface{}{
		"source":      sourceMap,
		"destination": destinationMap,
		"network":     networkMap,
	}

	// Include the socket's retained process context when available.
	if proc != nil {
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
		ID:        fmt.Sprintf("net-%s-%d", eventType, time.Now().UnixNano()),
		Timestamp: observedAt,
		Type:      eventType,
		Category:  "network",
		Kind:      "event",
		Severity:  events.SeverityInfo,
		Module:    "telemetry.network",
		AgentID:   n.agentID,
		Hostname:  n.hostname,
		Payload:   payload,
		Tags:      []string{"network", "telemetry"},
	}

	n.pipeline.Emit(event)
}

// direction uses the default perimeter for callers without configured context.
func direction(conn ConnectionInfo) string {
	perimeter, _ := NewPerimeter(nil)
	return perimeter.ConnectionDirection(conn)
}

// transport extracts the ECS network.transport value ("tcp" or "udp") from the
// procfs protocol string (tcp, tcp6, udp, udp6).
func transport(protocol string) string {
	if strings.HasPrefix(protocol, "tcp") {
		return "tcp"
	}
	return "udp"
}

// networkType returns the ECS network.type value ("ipv4" or "ipv6").
func networkType(protocol string) string {
	if strings.HasSuffix(protocol, "6") {
		return "ipv6"
	}
	return "ipv4"
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
