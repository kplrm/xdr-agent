package process

// Tree maintains an in-memory process tree for behavioral analysis.
// The tree allows detection engines to reason about parent-child relationships,
// process lineage, and ancestor chains — critical for behavioral rules like
// "web server spawns shell" or "cron executes encoded command".

// TODO: Implement process tree
// - Maintain map[pid]*ProcessNode with parent/child links
// - Rebuild tree on agent start from /proc
// - Update tree on exec/exit events
// - Support ancestor chain lookups (e.g., "is bash a descendant of httpd?")
// - Prune exited processes after configurable TTL
