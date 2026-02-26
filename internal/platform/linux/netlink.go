package linux

// Netlink provides process and network event monitoring via Linux netlink sockets.
//
// Used for:
//  - Process events: PROC_EVENT_EXEC, PROC_EVENT_EXIT, PROC_EVENT_FORK
//    via NETLINK_CONNECTOR + CN_IDX_PROC
//  - Network diagnostics: SOCK_DIAG for connection enumeration
//  - Audit events: NETLINK_AUDIT for auditd integration

// TODO: Implement netlink wrappers
// - Process connector: subscribe to proc events → exec/fork/exit notifications
// - Sock diag: enumerate TCP/UDP sockets with associated process info
// - Audit: send/receive audit messages for rule management and event collection
