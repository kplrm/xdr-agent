package network

// DNS monitors DNS queries made by the host to detect C2 communication,
// DGA (Domain Generation Algorithm) domains, and data exfiltration via DNS tunneling.

// TODO: Implement DNS monitor
// - Capture DNS queries via eBPF on udp_sendmsg (port 53)
// - Alternative: parse /var/log/syslog for dnsmasq logs
// - Alternative: pcap on lo/eth0 filtering port 53
// - Emit "network.dns" events with: query name, query type, response, PID (if available)
// - Feed into threat intel IoC matching (domain reputation)
