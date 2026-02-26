package behavioral

// Lateral detects lateral movement techniques.
//
// Monitored activities:
//  - SSH connections to internal hosts (especially from compromised processes)
//  - SSH tunneling / port forwarding (-L, -R, -D flags)
//  - SCP/rsync to internal hosts
//  - Unusual outbound connections from server processes
//  - Network scanning (port sweep, host discovery)
//  - Use of proxy tools (chisel, frp, ngrok)
//
// MITRE ATT&CK: T1021 (Remote Services), T1572 (Protocol Tunneling)

// TODO: Implement lateral movement detection
// - Correlate process exec + network connection events
// - Detect SSH with tunneling flags
// - Detect internal network scanning patterns
// - Alert on unusual internal-to-internal connections
