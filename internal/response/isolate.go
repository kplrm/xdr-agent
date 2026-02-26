package response

// Isolate provides network isolation for compromised endpoints.
// When activated, the host is cut off from the network except for communication
// with the XDR control plane — allowing continued management and investigation.
//
// Implementation: iptables/nftables rules that:
//  1. Allow traffic to/from control plane IP(s)
//  2. Allow DNS resolution (for control plane FQDN)
//  3. Block all other inbound and outbound traffic
//  4. Allow loopback traffic
//
// Inspired by: CrowdStrike network containment, Elastic host isolation

// TODO: Implement network isolation
// - Insert iptables/nftables rules to block all traffic except control plane
// - Persist rules across reboot (while isolation is active)
// - Support un-isolation (restore original firewall rules)
// - Store original firewall state for restoration
// - Emit "response.isolate" and "response.unisolate" events
