package process

// Tree maintains an in-memory process tree for behavioral analysis.
// The tree allows detection engines to reason about parent-child relationships,
// process lineage, and ancestor chains — critical for behavioral rules like
// "web server spawns shell" or "cron executes encoded command".
//
// ECS coverage:
//   process.parent.pid             → direct parent PID
//   process.parent.name            → direct parent name
//   process.parent.executable      → direct parent executable
//   process.parent.entity_id       → direct parent entity ID
//   process.parent.command_line    → direct parent command line
//   process.parent.args            → direct parent args
//   process.group_leader.pid       → process group leader PID
//   process.group_leader.entity_id → process group leader entity ID
//   process.ancestors[]            → full lineage up to the root (max 10 levels)

import (
	"sync"
	"time"
)

// maxAncestorDepth is the maximum number of ancestor levels reported in events.
const maxAncestorDepth = 10

// AncestorInfo is a compact process ancestry entry emitted inside
// process.ancestors[] in each event payload.
type AncestorInfo struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	Name       string   `json:"name"`
	Executable string   `json:"executable"`
	EntityID   string   `json:"entity_id"`
	StartTime  uint64   `json:"start_time"`
	Args       []string `json:"args,omitempty"`
}

// ProcessNode is a node in the in-memory process tree.
type ProcessNode struct {
	Info     ProcessInfo
	Parent   *ProcessNode
	Children []*ProcessNode
	ExitedAt time.Time // zero while alive
}

// ProcessTree is a thread-safe in-memory tree of running processes.
// It is rebuilt from /proc on agent start and updated incrementally as
// process.start / process.end events are detected.
type ProcessTree struct {
	mu    sync.RWMutex
	nodes map[int]*ProcessNode
}

// NewProcessTree creates an empty ProcessTree.
func NewProcessTree() *ProcessTree {
	return &ProcessTree{nodes: make(map[int]*ProcessNode)}
}

// Update inserts or refreshes a node and links it to its parent when the
// parent is already present in the tree.  Safe to call from multiple goroutines.
func (t *ProcessTree) Update(info ProcessInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	node, exists := t.nodes[info.PID]
	if !exists {
		node = &ProcessNode{}
		t.nodes[info.PID] = node
	}
	node.Info = info
	node.ExitedAt = time.Time{} // mark alive

	// Link to parent if present.
	if parent, ok := t.nodes[info.PPID]; ok && info.PPID != 0 {
		if node.Parent != parent {
			node.Parent = parent
			// Append to parent.Children only if not already there.
			found := false
			for _, c := range parent.Children {
				if c.Info.PID == info.PID {
					found = true
					break
				}
			}
			if !found {
				parent.Children = append(parent.Children, node)
			}
		}
	}
}

// Remove marks a process as exited and removes it from the tree.
// Its parent's Children list is pruned to keep the tree consistent.
func (t *ProcessTree) Remove(pid int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	node, exists := t.nodes[pid]
	if !exists {
		return
	}
	node.ExitedAt = time.Now()

	// Unlink from parent's children list.
	if node.Parent != nil {
		kept := node.Parent.Children[:0]
		for _, c := range node.Parent.Children {
			if c.Info.PID != pid {
				kept = append(kept, c)
			}
		}
		node.Parent.Children = kept
	}

	// Re-parent this node's children to their grandparent (or orphan them).
	for _, child := range node.Children {
		child.Parent = node.Parent
	}

	delete(t.nodes, pid)
}

// GetParent returns the ProcessInfo of pid's direct parent, or (zero, false)
// if the parent is unknown.
func (t *ProcessTree) GetParent(pid int) (ProcessInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	node, ok := t.nodes[pid]
	if !ok || node.Parent == nil {
		return ProcessInfo{}, false
	}
	return node.Parent.Info, true
}

// GetGroupLeader returns the ProcessInfo of pid's process group leader
// (i.e., the process whose PID equals the PGID), or (zero, false) if unknown.
// The PGID is stored in the ProcessInfo.SessionID field per /proc stat field 4.
// Note: for simplicity we look up the node whose PID == info.PPID chain leader.
// Since we don't store PGID separately yet, we return the nearest ancestor
// whose PID matches the session leader (process group leader approximation).
func (t *ProcessTree) GetGroupLeader(pid int) (ProcessInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	node, ok := t.nodes[pid]
	if !ok {
		return ProcessInfo{}, false
	}
	// The process is its own group leader when PID == its session_id.
	if node.Info.PID == node.Info.SessionID {
		return node.Info, true
	}
	// Try to find it in the tree directly.
	if leader, ok := t.nodes[node.Info.SessionID]; ok {
		return leader.Info, true
	}
	return ProcessInfo{}, false
}

// Children returns the direct children of pid. Returns nil if pid is not
// in the tree or has no children.
func (t *ProcessTree) Children(pid int) []ProcessInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	node, ok := t.nodes[pid]
	if !ok {
		return nil
	}
	out := make([]ProcessInfo, 0, len(node.Children))
	for _, c := range node.Children {
		out = append(out, c.Info)
	}
	return out
}

// Ancestors walks the parent chain of pid and returns up to maxAncestorDepth
// entries ordered from direct parent → root.
func (t *ProcessTree) Ancestors(pid int) []AncestorInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	node, ok := t.nodes[pid]
	if !ok {
		return nil
	}

	var chain []AncestorInfo
	cur := node.Parent
	for i := 0; cur != nil && i < maxAncestorDepth; i++ {
		chain = append(chain, AncestorInfo{
			PID:        cur.Info.PID,
			PPID:       cur.Info.PPID,
			Name:       cur.Info.Name,
			Executable: cur.Info.Executable,
			EntityID:   cur.Info.EntityID,
			StartTime:  cur.Info.StartTime,
			Args:       cur.Info.Args,
		})
		cur = cur.Parent
	}
	return chain
}

// Size returns the number of processes currently tracked by the tree.
func (t *ProcessTree) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.nodes)
}
