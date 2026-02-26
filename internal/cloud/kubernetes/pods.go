package kubernetes

// Pods monitors pod security contexts and detects risky configurations.

// TODO: Implement pod security monitoring
// - Query K8s API for pod specs
// - Detect risky security contexts:
//   * Privileged containers
//   * Host PID/network/IPC namespace sharing
//   * Root user (runAsUser: 0)
//   * Writable root filesystem
//   * Sensitive host path mounts (/etc, /var/run/docker.sock)
//   * Missing seccomp/AppArmor profiles
// - Emit compliance findings for non-compliant pods
