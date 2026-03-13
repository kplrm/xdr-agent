// Package session monitors user sessions, authentication events, and privilege escalation.
//
// SessionCollector emits ECS-compatible events for:
//   - User logon / logoff (utmp binary polling, /var/run/utmp)
//   - SSH logins / failures (auth log tailing)
//   - sudo command executions (auth log tailing)
//   - su session switches (auth log tailing)
//
// ECS event fields emitted:
//   - event.category         — "authentication"
//   - event.type             — "start" | "end" | "denied" | "info"
//   - event.action           — "logged-in" | "logged-out" | "sudo" | "su" | "ssh-accepted" | "ssh-failed"
//   - event.outcome          — "success" | "failure"
//   - user.name              — the originating user
//   - user.effective.name    — target user (sudo / su only)
//   - source.ip              — remote IP for SSH events
//   - source.port            — remote port for SSH events (if present)
//   - process.pid            — PID extracted from auth log (sudo / su / sshd)
//   - process.command_line   — full sudo COMMAND= string
//   - session.type           — "tty" | "pts" | "ssh" | "remote"
//   - related.user           — []string with all user names in the event
//
//go:build linux

package session

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

// ── utmp constants ────────────────────────────────────────────────────────────

const (
	// utmpRecordSize is the fixed size of a single utmp/wtmp record in bytes.
	// Sized for Linux utmpx (struct utmpx) as found on x86-64 Debian/RHEL.
	//
	// Offsets:
	//   0  ut_type    int16
	//   2  _pad0      [2]byte
	//   4  ut_pid     int32
	//   8  ut_line    [UT_LINESIZE]byte   (32 bytes)
	//  40  ut_id      [4]byte
	//  44  ut_user    [UT_NAMESIZE]byte   (32 bytes)
	//  76  ut_host    [UT_HOSTSIZE]byte   (256 bytes)
	// 332  ut_exit    [4]byte
	// 336  ut_session int32
	// 340  tv_sec     int32
	// 344  tv_usec    int32
	// 348  ut_addr_v6 [16]byte
	// 364  pad        [20]byte
	// total: 384
	utmpRecordSize = 384

	// utmp ut_type values.
	utmpUserProcess = 7 // USER_PROCESS — active login session
	utmpDeadProcess = 8 // DEAD_PROCESS — session ended

	// Field offsets within a utmp record.
	utmpOffType  = 0
	utmpOffPID   = 4
	utmpOffLine  = 8
	utmpOffUser  = 44
	utmpOffHost  = 76
	utmpOffTvSec = 340

	// Default path.
	utmpPath = "/var/run/utmp"

	// utmpInterval is how frequently we re-read the utmp file.
	utmpInterval = 10 * time.Second

	// authLogInterval is how frequently we read new lines from the auth log.
	authLogInterval = 2 * time.Second
)

// ── SessionCollector definition ───────────────────────────────────────────────

// SessionCollector monitors user sessions and auth events.
type SessionCollector struct {
	pipeline *events.Pipeline
	agentID  string
	hostname string
	interval time.Duration
	utmpFile string

	mu     sync.Mutex
	health capability.HealthStatus
	cancel context.CancelFunc

	// utmp state: map of ut_line (tty) → ut_user (username). Used to detect new
	// logins (entry appears or changes) and logoffs (entry user becomes empty).
	utmpSessions map[string]string

	// authLogPath is resolved once at Init time.
	authLogPath string
	// authLogOffset tracks our read position in the auth log file.
	authLogOffset int64
}

// NewSessionCollector creates a SessionCollector.
// Pass interval=0 to use the default 10s utmp polling interval.
func NewSessionCollector(pipeline *events.Pipeline, agentID, hostname string, interval time.Duration) *SessionCollector {
	if interval <= 0 {
		interval = utmpInterval
	}
	return &SessionCollector{
		pipeline:     pipeline,
		agentID:      agentID,
		hostname:     hostname,
		interval:     interval,
		utmpFile:     utmpPath,
		utmpSessions: make(map[string]string),
	}
}

// ── capability.Capability interface ──────────────────────────────────────────

func (s *SessionCollector) Name() string { return "telemetry.session" }

func (s *SessionCollector) Init(_ capability.Dependencies) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Detect auth log path.
	for _, candidate := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if _, err := os.Stat(candidate); err == nil {
			s.authLogPath = candidate
			break
		}
	}
	if s.authLogPath == "" {
		log.Printf("session collector: auth log not found (tried /var/log/auth.log, /var/log/secure) — SSH/sudo events disabled")
	}

	// Seek auth log to EOF so we don't replay old events.
	if s.authLogPath != "" {
		if f, err := os.Open(s.authLogPath); err == nil {
			if off, err := f.Seek(0, io.SeekEnd); err == nil {
				s.authLogOffset = off
			}
			_ = f.Close()
		}
	}

	// Silently establish utmp baseline (establish existing sessions without events).
	if recs, err := readUtmp(s.utmpFile); err == nil {
		for _, r := range recs {
			if r.utType == utmpUserProcess && r.user != "" {
				s.utmpSessions[r.line] = r.user
			}
		}
	}

	s.health = capability.HealthStarting
	return nil
}

func (s *SessionCollector) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.health = capability.HealthRunning
	s.mu.Unlock()

	go s.utmpLoop(childCtx)
	if s.authLogPath != "" {
		go s.authLogLoop(childCtx)
	}

	log.Printf("session collector: started (utmp=%s, authlog=%s)", s.utmpFile, s.authLogPath)
	return nil
}

func (s *SessionCollector) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	s.health = capability.HealthStopped
	return nil
}

func (s *SessionCollector) Health() capability.HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.health
}

// ── utmp polling ──────────────────────────────────────────────────────────────

func (s *SessionCollector) utmpLoop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkUtmp()
		}
	}
}

func (s *SessionCollector) checkUtmp() {
	recs, err := readUtmp(s.utmpFile)
	if err != nil {
		return
	}

	// Build a snapshot of the current state.
	current := make(map[string]string)
	for _, r := range recs {
		if r.utType == utmpUserProcess && r.user != "" {
			current[r.line] = r.user
		}
	}

	s.mu.Lock()
	prev := s.utmpSessions
	s.mu.Unlock()

	// Detect new logins (lines present in current but not (or different) in prev).
	for line, user := range current {
		if prevUser, exists := prev[line]; !exists || prevUser != user {
			s.emitSessionEvent("logged-in", "start", "success", user, "", line, "", 0, "")
		}
	}

	// Detect logoffs (lines present in prev but gone from current).
	for line, user := range prev {
		if _, exists := current[line]; !exists {
			s.emitSessionEvent("logged-out", "end", "success", user, "", line, "", 0, "")
		}
	}

	s.mu.Lock()
	s.utmpSessions = current
	s.mu.Unlock()
}

// ── utmp binary reader ────────────────────────────────────────────────────────

type utmpRecord struct {
	utType int16
	pid    int32
	line   string // ut_line (tty name)
	user   string // ut_user
	host   string // ut_host (remote host for SSH sessions)
	tvSec  int32
}

func readUtmp(path string) ([]utmpRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []utmpRecord
	buf := make([]byte, utmpRecordSize)
	for {
		_, err := io.ReadFull(f, buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}

		r := utmpRecord{
			utType: int16(binary.LittleEndian.Uint16(buf[utmpOffType : utmpOffType+2])),
			pid:    int32(binary.LittleEndian.Uint32(buf[utmpOffPID : utmpOffPID+4])),
			line:   nullTermString(buf[utmpOffLine : utmpOffLine+32]),
			user:   nullTermString(buf[utmpOffUser : utmpOffUser+32]),
			host:   nullTermString(buf[utmpOffHost : utmpOffHost+256]),
			tvSec:  int32(binary.LittleEndian.Uint32(buf[utmpOffTvSec : utmpOffTvSec+4])),
		}
		records = append(records, r)
	}
	return records, nil
}

// nullTermString trims a null-terminated C string byte slice to a Go string.
func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ── auth log tailing ──────────────────────────────────────────────────────────

// Compiled regexes for common auth log patterns.
var (
	// sudo: user invoked a command as another user
	// e.g.: sudo:   alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt
	reSudo = regexp.MustCompile(
		`sudo:\s+(\S+)\s*:.*?TTY=(\S+)\s*;.*?USER=(\S+)\s*;.*?COMMAND=(.+)`)

	// sshd: Accepted publickey for bob from 10.0.0.1 port 22 ssh2
	reSSHAccepted = regexp.MustCompile(
		`sshd\[(\d+)\]: Accepted \S+ for (\S+) from (\S+) port (\d+)`)

	// sshd: Failed password for invalid user carol from 10.0.0.5 port 50124 ssh2
	reSSHFailed = regexp.MustCompile(
		`sshd\[(\d+)\]: Failed \S+ for (?:invalid user )?(\S+) from (\S+) port (\d+)`)

	// su: switch-user session
	// e.g.: su[1234]: (to root) alice on pts/0
	reSU = regexp.MustCompile(
		`su\[(\d+)\]: \(to (\S+)\) (\S+)`)
)

func (s *SessionCollector) authLogLoop(ctx context.Context) {
	ticker := time.NewTicker(authLogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.readNewAuthLines()
		}
	}
}

func (s *SessionCollector) readNewAuthLines() {
	f, err := os.Open(s.authLogPath)
	if err != nil {
		return
	}
	defer f.Close()

	s.mu.Lock()
	offset := s.authLogOffset
	s.mu.Unlock()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		// File may have been rotated; reset to beginning.
		s.mu.Lock()
		s.authLogOffset = 0
		s.mu.Unlock()
		_, _ = f.Seek(0, io.SeekStart)
	}

	data, err := io.ReadAll(f)
	if err != nil || len(data) == 0 {
		return
	}

	s.mu.Lock()
	s.authLogOffset = offset + int64(len(data))
	s.mu.Unlock()

	for _, line := range strings.Split(string(data), "\n") {
		s.parseAuthLine(line)
	}
}

func (s *SessionCollector) parseAuthLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	// sudo
	if m := reSudo.FindStringSubmatch(line); m != nil {
		user := m[1]
		// tty := m[2]  // available if needed
		targetUser := m[3]
		command := strings.TrimSpace(m[4])
		s.emitSessionEvent("sudo", "info", "success", user, targetUser, "", "", 0, command)
		return
	}

	// SSH accepted
	if m := reSSHAccepted.FindStringSubmatch(line); m != nil {
		pid, _ := strconv.Atoi(m[1])
		user := m[2]
		srcIP := m[3]
		srcPort, _ := strconv.Atoi(m[4])
		s.emitSSHEvent("ssh-accepted", "start", "success", user, srcIP, pid, srcPort)
		return
	}

	// SSH failed
	if m := reSSHFailed.FindStringSubmatch(line); m != nil {
		pid, _ := strconv.Atoi(m[1])
		user := m[2]
		srcIP := m[3]
		srcPort, _ := strconv.Atoi(m[4])
		s.emitSSHEvent("ssh-failed", "denied", "failure", user, srcIP, pid, srcPort)
		return
	}

	// su
	if m := reSU.FindStringSubmatch(line); m != nil {
		pid, _ := strconv.Atoi(m[1])
		targetUser := m[2]
		user := m[3]
		s.emitSUEvent(user, targetUser, pid)
		return
	}
}

// ── event emitters ────────────────────────────────────────────────────────────

func (s *SessionCollector) emitSessionEvent(
	action, eventType, outcome string,
	user, effectiveUser, tty, remoteHost string,
	pid int,
	commandLine string,
) {
	ts := time.Now().UTC()

	sessionType := "tty"
	if strings.HasPrefix(tty, "pts") || strings.HasPrefix(tty, "pty") {
		sessionType = "pts"
	}
	if remoteHost != "" {
		sessionType = "ssh"
	}

	payload := map[string]interface{}{
		"event": map[string]interface{}{
			"action":  action,
			"outcome": outcome,
		},
		"user": map[string]interface{}{
			"name": user,
		},
		"session": map[string]interface{}{
			"type": sessionType,
		},
		"related": map[string]interface{}{
			"user": buildRelatedUsers(user, effectiveUser),
		},
	}

	if tty != "" {
		payload["process"] = map[string]interface{}{
			"tty": map[string]interface{}{"name": tty},
		}
	}
	if pid != 0 {
		if pm, ok := payload["process"].(map[string]interface{}); ok {
			pm["pid"] = pid
		} else {
			payload["process"] = map[string]interface{}{"pid": pid}
		}
	}
	if effectiveUser != "" {
		userMap := payload["user"].(map[string]interface{})
		userMap["effective"] = map[string]interface{}{"name": effectiveUser}
	}
	if remoteHost != "" {
		payload["source"] = map[string]interface{}{"ip": remoteHost}
	}
	if commandLine != "" {
		procMap, ok := payload["process"].(map[string]interface{})
		if !ok {
			procMap = make(map[string]interface{})
			payload["process"] = procMap
		}
		procMap["command_line"] = commandLine
	}

	severity := events.SeverityInfo
	if outcome == "failure" {
		severity = events.SeverityMedium
	}

	ev := events.Event{
		ID:        fmt.Sprintf("session-%s-%d", action, rand.Int63()),
		Timestamp: ts,
		Type:      fmt.Sprintf("session.%s", action),
		Category:  "authentication",
		Kind:      "event",
		Severity:  severity,
		Module:    "telemetry.session",
		AgentID:   s.agentID,
		Hostname:  s.hostname,
		Payload:   payload,
		Tags:      []string{"session", "authentication", "telemetry"},
	}
	s.pipeline.Emit(ev)
}

func (s *SessionCollector) emitSSHEvent(action, eventType, outcome, user, srcIP string, pid, srcPort int) {
	ts := time.Now().UTC()

	sourceMap := map[string]interface{}{"ip": srcIP}
	if srcPort != 0 {
		sourceMap["port"] = srcPort
	}

	payload := map[string]interface{}{
		"event": map[string]interface{}{
			"action":  action,
			"outcome": outcome,
		},
		"user":    map[string]interface{}{"name": user},
		"source":  sourceMap,
		"session": map[string]interface{}{"type": "ssh"},
		"related": map[string]interface{}{
			"user": buildRelatedUsers(user, ""),
			"ip":   []string{srcIP},
		},
	}
	if pid != 0 {
		payload["process"] = map[string]interface{}{"pid": pid}
	}

	severity := events.SeverityInfo
	if outcome == "failure" {
		severity = events.SeverityMedium
	}

	ev := events.Event{
		ID:        fmt.Sprintf("session-%s-%d", action, rand.Int63()),
		Timestamp: ts,
		Type:      fmt.Sprintf("session.%s", action),
		Category:  "authentication",
		Kind:      "event",
		Severity:  severity,
		Module:    "telemetry.session",
		AgentID:   s.agentID,
		Hostname:  s.hostname,
		Payload:   payload,
		Tags:      []string{"session", "authentication", "ssh", "telemetry"},
	}
	s.pipeline.Emit(ev)
}

func (s *SessionCollector) emitSUEvent(user, targetUser string, pid int) {
	ts := time.Now().UTC()

	payload := map[string]interface{}{
		"event": map[string]interface{}{
			"action":  "su",
			"outcome": "success",
		},
		"user": map[string]interface{}{
			"name": user,
			"effective": map[string]interface{}{
				"name": targetUser,
			},
		},
		"session": map[string]interface{}{"type": "tty"},
		"related": map[string]interface{}{
			"user": buildRelatedUsers(user, targetUser),
		},
	}
	if pid != 0 {
		payload["process"] = map[string]interface{}{"pid": pid}
	}

	ev := events.Event{
		ID:        fmt.Sprintf("session-su-%d", rand.Int63()),
		Timestamp: ts,
		Type:      "session.su",
		Category:  "authentication",
		Kind:      "event",
		Severity:  events.SeverityInfo,
		Module:    "telemetry.session",
		AgentID:   s.agentID,
		Hostname:  s.hostname,
		Payload:   payload,
		Tags:      []string{"session", "authentication", "privilege", "telemetry"},
	}
	s.pipeline.Emit(ev)
}

// buildRelatedUsers collects all distinct non-empty user names for related.user.
func buildRelatedUsers(users ...string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, u := range users {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}
