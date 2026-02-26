package process

// Enrichment adds contextual metadata to process events.

// TODO: Implement process enrichment
// - Read /proc/[pid]/cmdline, /proc/[pid]/cwd, /proc/[pid]/exe
// - Resolve UID/GID to username/group
// - Calculate SHA256 hash of executable
// - Determine if process is running in a container (cgroup check)
// - Add process tree context (parent name, grandparent name)
