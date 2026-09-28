// Package detection matches process and file telemetry against bundled YARA rules.
package detection

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"xdr-agent/internal/config"
	"xdr-agent/internal/detection/malware"
	"xdr-agent/internal/events"
	"xdr-agent/internal/platform/linux"
)

type Engine struct {
	cfg         config.Config
	pipeline    *events.Pipeline
	scanner     *malware.Scanner
	helperFiles []os.FileInfo // Avoid spawning YARA to scan its own short-lived child.
	guard       *linux.ExecGuard
	queue       chan events.Event
	mu          sync.RWMutex
	health      map[string]string
	cancel      context.CancelFunc
	workers     sync.WaitGroup
}

func NewEngine(cfg config.Config, pipeline *events.Pipeline) (*Engine, error) {
	e := &Engine{cfg: cfg, pipeline: pipeline, queue: make(chan events.Event, 256), health: map[string]string{"yara": "disabled", "execution_blocking": "disabled"}}
	log.Print("YARA: compiling bundled Linux rules")
	scanner, err := malware.NewScanner()
	if err != nil {
		return nil, err
	}
	e.scanner = scanner
	for _, path := range []string{scanner.Executable()} {
		if info, err := os.Stat(path); err == nil {
			e.helperFiles = append(e.helperFiles, info)
		}
	}
	if path, err := os.Executable(); err == nil {
		if info, err := os.Stat(path); err == nil {
			e.helperFiles = append(e.helperFiles, info)
		}
	}
	e.health["yara"] = "running"
	log.Print("YARA: bundled rules ready")
	return e, nil
}
func (e *Engine) Inventory() []malware.RuleInfo {
	if e.scanner == nil {
		return nil
	}
	return malware.Inventory().Rules
}
func (e *Engine) BundleInfo() malware.BundleInfo {
	info := malware.Inventory()
	info.Rules = nil
	return info
}
func (e *Engine) Health() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]string)
	for key, value := range e.health {
		result[key] = value
	}
	return result
}
func (e *Engine) setHealth(key, status string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.health[key] == status {
		return false
	}
	e.health[key] = status
	return true
}
func (e *Engine) Start(ctx context.Context) error {
	if e.scanner == nil {
		return nil
	}
	ctx, e.cancel = context.WithCancel(ctx)
	e.pipeline.Subscribe(func(event events.Event) {
		if event.Kind != "event" || (event.Category != "process" && event.Category != "file") || strings.HasSuffix(event.Type, ".end") || event.Module == "telemetry.file.access" {
			return
		}
		select {
		case e.queue <- event:
		default:
			e.setHealth("yara", "degraded: scan queue full")
		}
	})
	e.workers.Add(1)
	go func() {
		defer e.workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-e.queue:
				path := pathFromEvent(event)
				if path == "" || (event.Category == "process" && e.isOwnExecutable(path)) {
					continue
				}
				scanPath := path
				if process, ok := event.Payload["process"].(map[string]interface{}); ok {
					if pid, ok := process["pid"].(int); ok {
						scanPath = fmt.Sprintf("/proc/%d/exe", pid)
					}
				}
				result, err := e.scanner.ScanFile(ctx, scanPath)
				if err != nil {
					if !os.IsNotExist(err) && ctx.Err() == nil {
						if e.setHealth("yara", "degraded: scan error") {
							log.Printf("YARA scan failed for %q: %v", path, err)
						}
					}
					continue
				}
				if result.Matched() {
					e.emitAlert(event, path, result, false)
				}
			}
		}
	}()
	if !e.cfg.IsPreventionMode() {
		return nil
	}
	e.setHealth("execution_blocking", "starting")
	log.Printf("execution blocking: marking %d configured directory roots", len(e.cfg.ExecutionWatchPaths))
	guard, err := linux.NewExecGuard(e.cfg.ExecutionWatchPaths, []string{e.scanner.Executable()}, func(ctx context.Context, file *os.File, pid int) (bool, error) {
		result, err := e.scanner.ScanOpenFile(ctx, file)
		if err != nil {
			return false, err
		}
		if !result.Matched() {
			return false, nil
		}
		path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
		hostname, _ := os.Hostname()
		e.emitAlert(events.Event{Hostname: hostname, Payload: map[string]interface{}{"process.pid": pid}}, path, result, true)
		return true, nil
	}, func(err error) {
		if e.setHealth("execution_blocking", "degraded: "+err.Error()) {
			log.Printf("execution blocking degraded: %v", err)
		}
	})
	if err != nil {
		e.setHealth("execution_blocking", "degraded: "+err.Error())
		return err
	}
	guard.RecordDecision = func(pid int, denied bool, err error) {
		if !denied && err == nil {
			return
		}
		action := "execution_denied"
		if err != nil {
			action = "execution_response_failed"
		}
		e.pipeline.Emit(events.Event{Timestamp: time.Now().UTC(), Type: "prevention.action", Kind: "event", Category: "prevention", Module: "prevention.execution", Severity: events.SeverityHigh, Payload: map[string]interface{}{"action": action, "process.pid": pid}})
	}
	if err := guard.Start(ctx); err != nil {
		e.setHealth("execution_blocking", "degraded: "+err.Error())
		return err
	}
	e.guard = guard
	if e.Health()["execution_blocking"] == "starting" {
		e.setHealth("execution_blocking", "running")
	}
	log.Print("execution blocking: directory watch setup complete")
	return nil
}
func (e *Engine) Close() error {
	if e.cancel != nil {
		e.cancel()
	}
	if e.guard != nil {
		e.guard.Close()
	}
	e.workers.Wait()
	if e.scanner != nil {
		return e.scanner.Close()
	}
	return nil
}
func (e *Engine) emitAlert(source events.Event, path string, result malware.Result, denyRequested bool) {
	payload := map[string]interface{}{"rule.id": result.Rules[0], "rule.name": result.Rules[0], "rule.names": result.Rules, "file.path": path, "method": "yara", "execution.deny_requested": denyRequested, "source.event.id": source.ID}
	if st, ok := result.FileInfo.Sys().(*syscall.Stat_t); ok {
		payload["file.device"] = st.Dev
		payload["file.inode"] = st.Ino
		payload["file.size"] = result.FileInfo.Size()
		payload["file.mtime_ns"] = result.FileInfo.ModTime().UnixNano()
	}
	if process, ok := source.Payload["process"].(map[string]interface{}); ok {
		for key, value := range process {
			payload["process."+key] = value
		}
	}
	if pid, ok := source.Payload["process.pid"]; ok {
		payload["process.pid"] = pid
	}
	e.pipeline.Emit(events.Event{ID: "yara-" + strconv.FormatInt(time.Now().UnixNano(), 10), Timestamp: time.Now().UTC(), Type: "alert", Category: "threat", Kind: "alert", Severity: events.SeverityHigh, Module: "detection.malware", AgentID: source.AgentID, Hostname: source.Hostname, Payload: payload, Tags: []string{"yara", "malware"}})
}
func pathFromEvent(event events.Event) string {
	key, field := "file", "path"
	if event.Category == "process" {
		key, field = "process", "executable"
	}
	if nested, ok := event.Payload[key].(map[string]interface{}); ok {
		if path, ok := nested[field].(string); ok {
			return path
		}
	}
	path, _ := event.Payload[key+"."+field].(string)
	return path
}

// Skip the Agent and its YARA child even when the executable has a symlinked path.
func (e *Engine) isOwnExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	for _, helper := range e.helperFiles {
		if os.SameFile(info, helper) {
			return true
		}
	}
	return false
}
