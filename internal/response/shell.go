package response

// Shell provides remote command execution for incident response.
// Commands are received from the control plane and executed on the endpoint.
//
// Security considerations:
//  - Commands must be signed by the control plane
//  - All command execution is logged to audit trail
//  - Configurable command allowlist (optional)
//  - Output is streamed back to control plane
//  - Command timeout enforcement
//
// Inspired by: CrowdStrike Real Time Response (RTR)

// TODO: Implement remote shell
// - Receive command from control plane via policy/action channel
// - Validate command signature
// - Execute with configurable timeout
// - Stream stdout/stderr back to control plane
// - Support: file listing, process listing, registry (Windows), network info
// - Safety: configurable command blocklist (e.g., rm -rf /)
