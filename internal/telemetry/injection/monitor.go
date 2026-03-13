//go:build linux

// Package injection monitors for process injection indicators:
//   - ptrace attach: TracerPid != 0 in /proc/[pid]/status
//   - anonymous executable regions in /proc/[pid]/maps (memfd, shellcode)
//
// MITRE ATT&CK: T1055 (Process Injection), T1620 (Reflective Code Loading)
package injection

import (
"bufio"
"context"
"fmt"
"log"
"os"
"path/filepath"
"strconv"
"strings"
"sync"
"time"

"xdr-agent/internal/capability"
"xdr-agent/internal/events"
)

const defaultInjectionInterval = 5 * time.Second

// injectionRecord tracks a known ptrace or memfd indicator for a pid.
type injectionRecord struct {
PID       int
Indicator string // "ptrace" or "anon_exec"
Detail    string // e.g. tracer pid, or the anon region address
}

// InjectionCollector polls /proc for ptrace and memfd injection indicators.
// It implements capability.Capability.
type InjectionCollector struct {
pipeline *events.Pipeline
agentID  string
hostname string
interval time.Duration

mu     sync.Mutex
known  map[string]injectionRecord
health capability.HealthStatus
cancel context.CancelFunc
}

// NewInjectionCollector creates a new process injection telemetry collector.
// Pass 0 for interval to use the 5 s default.
func NewInjectionCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *InjectionCollector {
if interval <= 0 {
interval = defaultInjectionInterval
}
return &InjectionCollector{
pipeline: pipeline,
agentID:  agentID,
hostname: hostname,
interval: interval,
known:    make(map[string]injectionRecord),
health:   capability.HealthStopped,
}
}

// ── capability.Capability ────────────────────────────────────────────────────

func (c *InjectionCollector) Name() string { return "telemetry.injection" }

func (c *InjectionCollector) Init(_ capability.Dependencies) error {
c.mu.Lock()
defer c.mu.Unlock()
c.health = capability.HealthStarting
return nil
}

func (c *InjectionCollector) Start(ctx context.Context) error {
childCtx, cancel := context.WithCancel(ctx)
c.mu.Lock()
c.cancel = cancel
c.health = capability.HealthRunning
c.mu.Unlock()

go c.loop(childCtx)
return nil
}

func (c *InjectionCollector) Stop() error {
c.mu.Lock()
defer c.mu.Unlock()
if c.cancel != nil {
c.cancel()
}
c.health = capability.HealthStopped
return nil
}

func (c *InjectionCollector) Health() capability.HealthStatus {
c.mu.Lock()
defer c.mu.Unlock()
return c.health
}

// ── internal ─────────────────────────────────────────────────────────────────

func (c *InjectionCollector) loop(ctx context.Context) {
// First scan builds baseline (suppresses events for pre-existing debugger sessions).
c.scan(ctx, true)

ticker := time.NewTicker(c.interval)
defer ticker.Stop()

for {
select {
case <-ctx.Done():
return
case <-ticker.C:
c.scan(ctx, false)
}
}
}

func (c *InjectionCollector) scan(ctx context.Context, baseline bool) {
entries, err := os.ReadDir("/proc")
if err != nil {
log.Printf("injection: read /proc: %v", err)
c.mu.Lock()
c.health = capability.HealthDegraded
c.mu.Unlock()
return
}

current := make(map[string]injectionRecord)

for _, entry := range entries {
if ctx.Err() != nil {
return
}
pid, parseErr := strconv.Atoi(entry.Name())
if parseErr != nil || pid <= 0 {
continue
}

// 1. ptrace detection via TracerPid in /proc/[pid]/status
if tracerPID := readTracerPID(pid); tracerPID > 0 {
key := fmt.Sprintf("%d:ptrace:%d", pid, tracerPID)
current[key] = injectionRecord{PID: pid, Indicator: "ptrace", Detail: strconv.Itoa(tracerPID)}
}

// 2. Anonymous executable region detection in /proc/[pid]/maps
for _, region := range readAnonExecRegions(pid) {
key := fmt.Sprintf("%d:anon_exec:%s", pid, region)
current[key] = injectionRecord{PID: pid, Indicator: "anon_exec", Detail: region}
}
}

c.mu.Lock()
previous := c.known
c.known = current
c.health = capability.HealthRunning
c.mu.Unlock()

if baseline {
log.Printf("injection: baseline — %d indicators recorded", len(current))
return
}

if ctx.Err() != nil {
return
}

for key, rec := range current {
if _, existed := previous[key]; !existed {
c.emitEvent(rec)
}
}
}

func (c *InjectionCollector) emitEvent(rec injectionRecord) {
procName := readComm(rec.PID)
exePath := readExe(rec.PID)

var action, mitreTechnique, mitreTactic, description string
var severity events.Severity

switch rec.Indicator {
case "ptrace":
action = "process_injection.ptrace_attach"
severity = events.SeverityHigh
mitreTechnique = "T1055"
mitreTactic = "Defense Evasion"
tracerName := readComm(atoiSafe(rec.Detail))
description = fmt.Sprintf("Process %d (%s) is being traced by PID %s (%s)",
rec.PID, procName, rec.Detail, tracerName)
case "anon_exec":
action = "process_injection.anon_exec_region"
severity = events.SeverityHigh
mitreTechnique = "T1620"
mitreTactic = "Defense Evasion"
description = fmt.Sprintf("Process %d (%s) has anonymous executable memory at %s",
rec.PID, procName, rec.Detail)
default:
action = "process_injection.unknown"
severity = events.SeverityMedium
mitreTechnique = "T1055"
mitreTactic = "Defense Evasion"
description = fmt.Sprintf("Process %d (%s): unknown injection indicator %s", rec.PID, procName, rec.Indicator)
}

injPayload := map[string]interface{}{
"indicator": rec.Indicator,
"detail":    rec.Detail,
"target": map[string]interface{}{
"pid":  rec.PID,
"name": procName,
"exe":  exePath,
},
}

if rec.Indicator == "ptrace" {
tracerPID := atoiSafe(rec.Detail)
injPayload["tracer"] = map[string]interface{}{
"pid":  tracerPID,
"name": readComm(tracerPID),
"exe":  readExe(tracerPID),
}
}

ev := events.Event{
ID:            fmt.Sprintf("inject-%s-%d-%d", rec.Indicator, rec.PID, time.Now().UnixNano()),
Timestamp:     time.Now().UTC(),
Type:          action,
Category:      "intrusion_detection",
Kind:          "alert",
Severity:      severity,
Module:        "telemetry.injection",
AgentID:       c.agentID,
Hostname:      c.hostname,
MitreTactic:   mitreTactic,
MitreTechique: mitreTechnique,
Tags:          []string{"injection", "ptrace", "process", "telemetry"},
Payload: map[string]interface{}{
"process": map[string]interface{}{
"pid":        rec.PID,
"name":       procName,
"executable": exePath,
},
"xdr": map[string]interface{}{
"injection": injPayload,
},
"description": description,
},
}
c.pipeline.Emit(ev)
}

// ── /proc helpers ─────────────────────────────────────────────────────────────

// readTracerPID returns the TracerPid from /proc/[pid]/status, or 0 if not traced.
func readTracerPID(pid int) int {
f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
if err != nil {
return 0
}
defer f.Close()

scanner := bufio.NewScanner(f)
for scanner.Scan() {
line := scanner.Text()
if strings.HasPrefix(line, "TracerPid:") {
fields := strings.Fields(line)
if len(fields) >= 2 {
if v, convErr := strconv.Atoi(fields[1]); convErr == nil {
return v
}
}
}
}
return 0
}

// readAnonExecRegions returns anonymous executable memory-region descriptors
// from /proc/[pid]/maps. These signal shellcode injection, memfd loaders, etc.
func readAnonExecRegions(pid int) []string {
f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
if err != nil {
return nil
}
defer f.Close()

var regions []string
scanner := bufio.NewScanner(f)
for scanner.Scan() {
line := scanner.Text()
// Format: addr-range perms offset dev inode [pathname]
fields := strings.Fields(line)
if len(fields) < 5 {
continue
}
perms := fields[1]
if !strings.Contains(perms, "x") {
continue
}

hasPath := len(fields) >= 6
if hasPath {
pathField := fields[5]
// Explicit memfd regions
if strings.Contains(pathField, "memfd:") {
regions = append(regions, fields[0]+":"+pathField)
continue
}
// Normal file-backed regions or well-known anonymous regions are safe to skip
if !strings.HasPrefix(pathField, "[") {
continue
}
// Skip kernel pseudo-regions
switch pathField {
case "[stack]", "[heap]", "[vdso]", "[vsyscall]", "[vvar]":
continue
}
}

// Remaining: truly anonymous r-x pages (no pathname or unknown [region])
label := "anon"
if hasPath {
label = fields[5]
}
regions = append(regions, fields[0]+":"+label)
}
return regions
}

func readComm(pid int) string {
b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
return strings.TrimSpace(string(b))
}

func readExe(pid int) string {
p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
if err != nil {
return ""
}
return filepath.Clean(p)
}

func atoiSafe(s string) int {
v, _ := strconv.Atoi(s)
return v
}
