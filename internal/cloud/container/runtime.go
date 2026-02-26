// Package container provides container runtime monitoring and drift detection.
package container

// Runtime monitors container lifecycle events from Docker, containerd, and CRI-O.
//
// TODO: Implement container runtime monitor
// - Docker: listen to /var/run/docker.sock events API
// - containerd: gRPC events API
// - CRI-O: monitor via crictl events
// - Emit events: container.start, container.stop, container.exec
// - Collect: container ID, image, name, labels, command, user
// - Detect: privileged containers, host network/PID namespace usage
// - Detect: container escape techniques
