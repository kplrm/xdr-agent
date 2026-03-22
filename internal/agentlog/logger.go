package agentlog

import (
	"fmt"
	"strings"
	"time"

	"xdr-agent/internal/events"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Logger struct {
	level    Level
	agentID  string
	hostname string
	pipeline *events.Pipeline
}

func New(levelRaw, agentID, hostname string, pipeline *events.Pipeline) *Logger {
	return &Logger{
		level:    parseLevel(levelRaw),
		agentID:  agentID,
		hostname: hostname,
		pipeline: pipeline,
	}
}

func (l *Logger) Debug(module, msg string, fields map[string]interface{}) {
	l.emit(LevelDebug, module, msg, fields)
}

func (l *Logger) Info(module, msg string, fields map[string]interface{}) {
	l.emit(LevelInfo, module, msg, fields)
}

func (l *Logger) Warn(module, msg string, fields map[string]interface{}) {
	l.emit(LevelWarn, module, msg, fields)
}

func (l *Logger) Error(module, msg string, fields map[string]interface{}) {
	l.emit(LevelError, module, msg, fields)
}

func (l *Logger) emit(level Level, module, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}
	if fields == nil {
		fields = map[string]interface{}{}
	}
	fields["message"] = msg
	fields["log.level"] = strings.ToUpper(level.String())

	l.pipeline.Emit(events.Event{
		Timestamp: time.Now().UTC(),
		Type:      "agent.log",
		Category:  "agent",
		Kind:      "event",
		Severity:  levelSeverity(level),
		Module:    "agent.logger",
		AgentID:   l.agentID,
		Hostname:  l.hostname,
		Payload:   fields,
		Tags:      []string{"agent-log", strings.ToLower(level.String()), fmt.Sprintf("module:%s", module)},
	})
}

func levelSeverity(level Level) events.Severity {
	switch level {
	case LevelDebug, LevelInfo:
		return events.SeverityInfo
	case LevelWarn:
		return events.SeverityMedium
	case LevelError:
		return events.SeverityHigh
	default:
		return events.SeverityInfo
	}
}

func parseLevel(raw string) Level {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "DEBUG":
		return LevelDebug
	case "WARN":
		return LevelWarn
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}
