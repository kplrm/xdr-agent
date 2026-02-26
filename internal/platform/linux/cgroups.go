package linux

// Cgroups provides cgroup monitoring for container awareness.
// By reading a process's cgroup membership, the agent can determine
// whether a process runs inside a container and which container it belongs to.

// TODO: Implement cgroup utilities
// - ReadProcessCgroup(pid) → cgroup path, container ID
// - IsContainerized(pid) bool
// - ExtractContainerID(cgroupPath) string
// - Support cgroup v1 and v2
// - Detect container runtime: Docker, containerd, CRI-O, podman
