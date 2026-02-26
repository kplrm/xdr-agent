package kubernetes

// - Forward events to event pipeline// - Detect suspicious K8s API calls: privileged pod creation, host mount// - Collect events: pod creation, RBAC changes, secret access, exec into pod// - Option 2: Tail audit log file (/var/log/kubernetes/audit.log)// - Option 1: Webhook receiver (agent exposes HTTP endpoint for audit webhook)// TODO: Implement K8s audit log collection// Audit collects Kubernetes audit log events for security monitoring.package kubernetes
