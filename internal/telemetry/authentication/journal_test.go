package authentication

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

func journalFixture(cursor, message string) string {
	data, _ := json.Marshal(map[string]interface{}{
		"__CURSOR": cursor, "__REALTIME_TIMESTAMP": "1794000897031769",
		"_HOSTNAME": "node4", "SYSLOG_IDENTIFIER": "su", "_PID": "31", "MESSAGE": message,
	})
	return string(data)
}

func TestParseJournal(t *testing.T) {
	now := time.Now()
	line := journalFixture("cursor1", "pam_unix(su:session): session opened for user nobody(uid=65534) by root(uid=0)")
	event, keep, cursor, err := parseJournal([]byte(line), now, "agent", "fallback")
	if err != nil || !keep || cursor != "cursor1" {
		t.Fatalf("parse: keep=%v cursor=%q err=%v", keep, cursor, err)
	}
	data, _ := json.Marshal(event)
	var document map[string]interface{}
	json.Unmarshal(data, &document)
	for key, want := range map[string]interface{}{
		"@timestamp": "2026-11-06T21:34:57.031769Z", "host.hostname": "node4", "process.pid": float64(31),
		"user.name": "nobody", "source.user.name": "root", "event.action": "session-start",
		"event.original": nil, "log.logger": "systemd-journald", "log.file.path": nil,
		"xdr.authentication.method": nil,
	} {
		if got := lookup(document, key); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", key, got, want)
		}
	}
	cron := strings.Replace(line, `"SYSLOG_IDENTIFIER":"su"`, `"SYSLOG_IDENTIFIER":"CRON"`, 1)
	if _, keep, cursor, err := parseJournal([]byte(cron), now, "agent", "fallback"); err != nil || keep || cursor != "cursor1" {
		t.Fatalf("CRON must be skipped while retaining cursor: keep=%v cursor=%q err=%v", keep, cursor, err)
	}
	for _, invalid := range []string{`not JSON`, `{"MESSAGE":"missing metadata"}`} {
		if _, _, _, err := parseJournal([]byte(invalid), now, "agent", "fallback"); err == nil {
			t.Fatalf("accepted invalid journal record: %s", invalid)
		}
	}
	// Repeated/binary fields and missing optional metadata are valid journal JSON.
	var entry map[string]interface{}
	json.Unmarshal([]byte(line), &entry)
	entry["MESSAGE"] = []interface{}{"Accepted publickey for alice from 192.0.2.1 port 22 ssh2", "other value"}
	entry["_COMM"] = []int{115, 115, 104, 100}
	delete(entry, "SYSLOG_IDENTIFIER")
	delete(entry, "_HOSTNAME")
	data, _ = json.Marshal(entry)
	event, keep, _, err = parseJournal(data, now, "agent", "fallback")
	if err != nil || !keep || event.Hostname != "fallback" {
		t.Fatalf("metadata fallbacks: %v", err)
	}
	if got := event.Payload["xdr"].(map[string]interface{})["authentication"].(map[string]interface{})["method"]; got != "publickey" {
		t.Fatalf("SSH method lost: %v", got)
	}
}

func TestJournalAuthenticationSamples(t *testing.T) {
	observed := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		micros, message, action, timestamp string
		unparsed                           bool
	}{
		{"1794006462538386", "pam_unix(su:session): session closed for user nobody", "session-end", "2026-11-06T23:07:42.538386Z", false},
		{"1794006462534809", "pam_env(su:session): Unable to open env file: /etc/default/locale", "pam-environment-error", "2026-11-06T23:07:42.534809Z", false},
		{"1794006462534809", "pam_env(su:session): unsupported environment diagnostic", "authentication-log", "2026-11-06T23:07:42.534809Z", true},
		{"1794006462534920", "pam_unix(su:session): session opened for user nobody(uid=65534) by root(uid=0)", "session-start", "2026-11-06T23:07:42.53492Z", false},
		{"1794006462533668", "(to nobody) root on none", "su-command", "2026-11-06T23:07:42.533668Z", false},
	}
	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			data, _ := json.Marshal(map[string]string{
				"__CURSOR": "cursor1", "__REALTIME_TIMESTAMP": test.micros,
				"__SEQNUM": "5", "__SEQNUM_ID": "sequence", "__MONOTONIC_TIMESTAMP": "21602635043", "_BOOT_ID": "boot",
				"_HOSTNAME": "xdr-agent-dev", "SYSLOG_IDENTIFIER": "su", "SYSLOG_PID": "22", "_PID": "22", "_COMM": "su", "MESSAGE": test.message,
			})
			event, keep, cursor, err := parseJournal(data, observed, "agent", "host")
			if err != nil || !keep || cursor != "cursor1" {
				t.Fatalf("parse: keep=%v cursor=%q err=%v", keep, cursor, err)
			}
			if got := event.Payload["event.action"]; got != test.action {
				t.Errorf("action = %v, want %s", got, test.action)
			}
			if got := event.Timestamp.Format(time.RFC3339Nano); got != test.timestamp {
				t.Errorf("timestamp = %s, want %s", got, test.timestamp)
			}
			if got := slices.Contains(event.Tags, "authentication-unparsed"); got != test.unparsed {
				t.Errorf("tags = %v, want unparsed=%v", event.Tags, test.unparsed)
			}
			original, exists := event.Payload["event.original"]
			wantOriginal := test.timestamp + " xdr-agent-dev su[22]: " + test.message
			if exists != test.unparsed || (test.unparsed && original != wantOriginal) {
				t.Errorf("event.original = %#v (exists=%v), want unparsed=%v, original=%q", original, exists, test.unparsed, wantOriginal)
			}
		})
	}
}

func TestOversizedJournalLineDoesNotBlockNextRecord(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", maxJournalLine+1) + "\nnext\n"))
	if line, err := readJournalLine(reader); err != nil || len(line) != 0 {
		t.Fatalf("oversized line: length=%d err=%v", len(line), err)
	}
	if line, err := readJournalLine(reader); err != nil || string(line) != "next" {
		t.Fatalf("next record: %q %v", line, err)
	}
}

// A real subprocess exercises streaming, failure/restart and cancellation without
// depending on the test host's journal or reading its authentication records.
func TestJournalCommandHelper(t *testing.T) {
	mode := os.Getenv("XDR_AUTH_JOURNAL_TEST_MODE")
	if mode == "" {
		return
	}
	os.Stdout.WriteString(os.Getenv("XDR_AUTH_JOURNAL_TEST_OUTPUT") + "\n")
	if mode == "fail" {
		os.Stderr.WriteString("journal temporarily unavailable")
		os.Exit(1)
	}
	if mode == "follow" {
		time.Sleep(time.Hour)
	}
	os.Exit(0)
}

func journalHelper(ctx context.Context, mode, output string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJournalCommandHelper$")
	cmd.Env = append(os.Environ(), "XDR_AUTH_JOURNAL_TEST_MODE="+mode, "XDR_AUTH_JOURNAL_TEST_OUTPUT="+output)
	return cmd
}

func startJournalCollector(t *testing.T, command func(context.Context, ...string) *exec.Cmd) (*Collector, <-chan events.Event) {
	t.Helper()
	pipeline := events.NewPipeline(16)
	received := make(chan events.Event, 16)
	pipeline.Subscribe(func(event events.Event) { received <- event })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); pipeline.Run(ctx) }()
	collector := NewCollector(pipeline, "agent", "host")
	collector.path = filepath.Join(t.TempDir(), "auth.log")
	collector.journalCommand = command
	if err := collector.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); collector.Stop(); <-done })
	return collector, received
}

func TestJournalFallbackResumesAfterCursorAndStops(t *testing.T) {
	argsSeen := make(chan []string, 8)
	collector, received := startJournalCollector(t, func(ctx context.Context, args ...string) *exec.Cmd {
		argsSeen <- append([]string(nil), args...)
		if slices.Contains(args, "--lines=1") {
			return journalHelper(ctx, "probe", `{"__CURSOR":"baseline"}`)
		}
		cursor, mode := "cursor1", "fail"
		if slices.Contains(args, "--after-cursor=cursor1") {
			cursor, mode = "cursor2", "follow"
		}
		return journalHelper(ctx, mode, journalFixture(cursor, "pam_unix(su:session): session closed for user nobody"))
	})
	for range 2 {
		select {
		case event := <-received:
			if event.Payload["event.action"] != "session-end" {
				t.Fatalf("unexpected event: %v", event.Payload)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("journal did not resume and emit new records")
		}
	}
	probe, first, resumed := <-argsSeen, <-argsSeen, <-argsSeen
	if !slices.Contains(probe, "--output-fields=__CURSOR") || slices.Contains(probe, "--facility=auth,authpriv") {
		t.Fatalf("initial boundary must use the latest global cursor: %v", probe)
	}
	for index, args := range [][]string{first, resumed} {
		for _, expected := range []string{"--follow", "--output=json", "--all", "--no-tail", "--facility=auth,authpriv"} {
			if !slices.Contains(args, expected) {
				t.Errorf("stream %d missing %s: %v", index, expected, args)
			}
		}
	}
	if !slices.Contains(first, "--after-cursor=baseline") || !slices.Contains(resumed, "--after-cursor=cursor1") {
		t.Fatalf("cursor resume incorrect: first=%v resumed=%v", first, resumed)
	}
	if collector.Health() != capability.HealthRunning {
		t.Fatal("working journal source is not healthy")
	}
	// Shutdown must interrupt an idle journalctl child promptly.
	stopped := make(chan struct{})
	go func() { collector.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("journal child blocked shutdown")
	}
}

func TestJournalUnavailableRetriesFile(t *testing.T) {
	attempted := make(chan struct{}, 4)
	collector, _ := startJournalCollector(t, func(ctx context.Context, args ...string) *exec.Cmd {
		attempted <- struct{}{}
		return journalHelper(ctx, "fail", "")
	})
	select {
	case <-attempted:
	case <-time.After(2 * time.Second):
		t.Fatal("journal fallback not attempted")
	}
	if collector.Health() != capability.HealthDegraded {
		t.Fatal("unavailable sources must report degraded health")
	}
	if err := os.WriteFile(collector.path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for collector.Health() != capability.HealthRunning && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if collector.Health() != capability.HealthRunning {
		t.Fatal("auth.log did not recover after journal failure")
	}
}

func TestReadableAuthFileTakesPriority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	called := make(chan struct{}, 1)
	collector := NewCollector(events.NewPipeline(4), "agent", "host")
	collector.path = path
	collector.journalCommand = func(ctx context.Context, args ...string) *exec.Cmd {
		called <- struct{}{}
		return journalHelper(ctx, "fail", "")
	}
	if err := collector.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	collector.Stop()
	if collector.Health() != capability.HealthStopped {
		t.Fatal("collector did not stop")
	}
	select {
	case <-called:
		t.Fatal("journal must not be read alongside auth.log")
	default:
	}
}
