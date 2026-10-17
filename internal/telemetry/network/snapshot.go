package network

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SocketSnapshotProvider is the sole reader of socket tables. DNS consumes the
// last published generation and never triggers additional table reads.
type SocketSnapshotProvider struct {
	mu       sync.Mutex
	procRoot string
	agentID  string
	current  *SocketSnapshot
	read     func(string, string) ([]ConnectionInfo, error)
	owners   func(string, string) map[uint64]*ProcessInfo
}

// SocketSnapshot contains one collection cycle. Published table data is immutable;
// the descriptor walk is performed lazily, at most once for this generation.
type SocketSnapshot struct {
	Generation  uint64
	ObservedAt  time.Time
	Connections []ConnectionInfo
	readOK      map[string]bool
	bySocket    map[string][]ConnectionInfo
	ownersOnce  sync.Once
	byInode     map[uint64]*ProcessInfo
	loadOwners  func() map[uint64]*ProcessInfo
}

func NewSocketSnapshotProvider(procRoot, agentID string) *SocketSnapshotProvider {
	if procRoot == "" {
		procRoot = defaultNetProcRoot
	}
	return &SocketSnapshotProvider{procRoot: procRoot, agentID: agentID,
		read: ParseProcNet, owners: buildSocketOwnerSnapshot}
}

func (p *SocketSnapshotProvider) setProcRoot(root string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.procRoot = root
}

func (p *SocketSnapshotProvider) Current() *SocketSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current
}

// Refresh is called only by the connection collection loop, once per cycle.
func (p *SocketSnapshotProvider) Refresh() *SocketSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := &SocketSnapshot{Generation: 1, ObservedAt: time.Now().UTC(),
		readOK: make(map[string]bool), bySocket: make(map[string][]ConnectionInfo)}
	if p.current != nil {
		s.Generation = p.current.Generation + 1
	}
	root, agentID, owners := p.procRoot, p.agentID, p.owners
	s.loadOwners = func() map[uint64]*ProcessInfo { return owners(root, agentID) }
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		conns, err := p.read(filepath.Join(root, "net", proto), proto)
		if err != nil {
			continue
		}
		s.readOK[proto] = true
		s.Connections = append(s.Connections, conns...)
		if !strings.HasPrefix(proto, "udp") {
			continue
		}
		for _, conn := range conns {
			if conn.LocalPort > 0 && conn.Inode != 0 {
				key := dnsSocketKey(conn.LocalAddr, conn.LocalPort)
				s.bySocket[key] = append(s.bySocket[key], conn)
			}
		}
	}
	p.current = s
	return s
}

func (s *SocketSnapshot) ResolveInode(inode uint64) *ProcessInfo {
	if s == nil || inode == 0 {
		return nil
	}
	s.ownersOnce.Do(func() { s.byInode = s.loadOwners() })
	return s.byInode[inode]
}

func (s *SocketSnapshot) ResolveUDP(localIP string, localPort int) *ProcessInfo {
	return s.ResolveUDPFlow(localIP, localPort, "", 0)
}

// ResolveUDPFlow never chooses an arbitrary holder of a shared local endpoint.
func (s *SocketSnapshot) ResolveUDPFlow(localIP string, localPort int, remoteIP string, remotePort int) *ProcessInfo {
	if s == nil {
		return nil
	}
	wildcard := "0.0.0.0"
	if strings.Contains(localIP, ":") {
		wildcard = "::"
	}
	candidates := s.bySocket[dnsSocketKey(localIP, localPort)]
	if localIP != wildcard {
		candidates = append(append([]ConnectionInfo(nil), candidates...), s.bySocket[dnsSocketKey(wildcard, localPort)]...)
	}
	var inode uint64
	for _, conn := range candidates {
		peer := net.ParseIP(conn.RemoteAddr)
		if remoteIP != "" && peer != nil && !peer.IsUnspecified() && (conn.RemoteAddr != remoteIP || conn.RemotePort != remotePort) {
			continue
		}
		if inode != 0 && inode != conn.Inode {
			return nil
		}
		inode = conn.Inode
	}
	return s.ResolveInode(inode)
}

func dnsSocketKey(ip string, port int) string {
	return ip + ":" + strconv.Itoa(port)
}
