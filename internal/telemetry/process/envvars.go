// Package process provides real-time process monitoring for the XDR agent.
// This file implements environment variable capture for process.start events
// (Phase 2c, MITRE T1574.006).
//
// ECS field: process.env (object map[string]string)
package process

import (
"bytes"
"os"
"path/filepath"
"strconv"
"strings"
)

// defaultEnvAllowlist is the set of environment variable names captured by
// default. Operators can extend this via capability policy.
var defaultEnvAllowlist = []string{
"LD_PRELOAD",
"LD_LIBRARY_PATH",
"LD_AUDIT",
"LD_DEBUG",
"PATH",
"HOME",
"SHELL",
"USER",
"LOGNAME",
"SUDO_USER",
"SUDO_COMMAND",
"PYTHONPATH",
"PYTHONSTARTUP",
"PERL5LIB",
"RUBYLIB",
"NODE_PATH",
"DYLD_INSERT_LIBRARIES",
}

// readEnvVars reads /proc/[pid]/environ and returns the subset of variables
// whose names appear in the allowlist. Returns nil if the file cannot be read
// (e.g. process already exited or insufficient privilege).
//
// /proc/[pid]/environ stores NUL-separated KEY=VALUE strings.
func readEnvVars(procRoot string, pid int, allowlist []string) map[string]string {
path := filepath.Join(procRoot, strconv.Itoa(pid), "environ")
data, err := os.ReadFile(path)
if err != nil {
return nil
}

allow := make(map[string]struct{}, len(allowlist))
for _, k := range allowlist {
allow[k] = struct{}{}
}

result := make(map[string]string)
for _, entry := range bytes.Split(data, []byte{0}) {
if len(entry) == 0 {
continue
}
idx := bytes.IndexByte(entry, '=')
if idx < 0 {
continue
}
key := strings.TrimSpace(string(entry[:idx]))
val := string(entry[idx+1:])
if _, ok := allow[key]; ok {
result[key] = val
}
}

if len(result) == 0 {
return nil
}
return result
}
