package compliance

// CIS implements Center for Internet Security (CIS) benchmark scanning.
//
// CIS benchmarks are industry-standard security configuration guides.
// Each benchmark contains hundreds of checks for OS, middleware, and application hardening.
//
// Supported benchmarks:
//  - CIS Debian Linux Benchmark
//  - CIS Ubuntu Linux Benchmark
//  - CIS Red Hat Enterprise Linux Benchmark
//  - CIS Amazon Linux Benchmark

// TODO: Implement CIS benchmark scanner
// - Load benchmark definitions from rules/compliance/cis_*.yml
// - Each check: ID, title, description, rationale, remediation, command, expected result
// - Execute checks: run commands, compare output to expected values
// - Report: pass/fail/not-applicable per check
// - Calculate overall compliance percentage
// - YAML format compatible with Wazuh SCA policy format
