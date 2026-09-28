// Package prevention terminates only the executable instance matched by YARA.
package prevention

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"xdr-agent/internal/config"
	"xdr-agent/internal/events"
	"xdr-agent/internal/telemetry/process"
)

type Manager struct {
	enabled  bool
	pipeline *events.Pipeline
}

func NewManager(cfg config.Config, pipeline *events.Pipeline) *Manager {
	return &Manager{enabled: cfg.IsPreventionMode(), pipeline: pipeline}
}
func (m *Manager) Handle(event events.Event) {
	if event.Kind != "alert" || event.Module != "detection.malware" || event.Payload["method"] != "yara" {
		return
	}
	if requested, _ := event.Payload["execution.deny_requested"].(bool); requested {
		return
	}
	action, detail := "alert_only", ""
	if m.enabled {
		if _, ok := event.Payload["process.pid"]; ok {
			if err := killMatchedProcess(event.Payload); err != nil {
				action = "kill_skipped"
				detail = err.Error()
			} else {
				action = "process_killed"
			}
		}
	}
	m.pipeline.Emit(events.Event{Timestamp: time.Now().UTC(), Type: "prevention.action", Category: "prevention", Kind: "event", Severity: event.Severity, Module: "prevention.manager", AgentID: event.AgentID, Hostname: event.Hostname, Payload: map[string]interface{}{"action": action, "detail": detail, "source.event.id": event.ID, "rule.id": event.Payload["rule.id"], "process.pid": event.Payload["process.pid"]}})
}

func killMatchedProcess(payload map[string]interface{}) error {
	pid, ok := payload["process.pid"].(int)
	if !ok || pid <= 1 || pid == os.Getpid() {
		return fmt.Errorf("invalid target process")
	}
	start, ok := payload["process.start_time"].(uint64)
	if !ok {
		return fmt.Errorf("missing process instance identity")
	}
	// pidfd pins the process identity; never fall back to a reusable numeric PID.
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("open process handle: %w", err)
	}
	defer unix.Close(fd)
	info, err := process.ReadProcessInfo("/proc", pid)
	if err != nil || info.StartTime != start {
		return fmt.Errorf("process instance changed")
	}
	executable, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}
	stat, ok := executable.Sys().(*syscall.Stat_t)
	if !ok || payload["file.device"] != stat.Dev || payload["file.inode"] != stat.Ino || payload["file.size"] != executable.Size() || payload["file.mtime_ns"] != executable.ModTime().UnixNano() {
		return fmt.Errorf("executable changed since YARA match")
	}
	return unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}
