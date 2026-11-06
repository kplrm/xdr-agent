package authentication

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

const maxJournalLine = 4 * maxLine

// Keep both command output and diagnostic memory bounded.
type boundedOutput struct{ data bytes.Buffer }

func (b *boundedOutput) Bytes() []byte  { return b.data.Bytes() }
func (b *boundedOutput) String() string { return b.data.String() }

func (b *boundedOutput) Write(data []byte) (int, error) {
	n := len(data)
	if remaining := 8192 - b.data.Len(); remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.data.Write(data)
	}
	return n, nil
}

func (c *Collector) journalCmd(ctx context.Context, args ...string) *exec.Cmd {
	if c.journalCommand != nil {
		return c.journalCommand(ctx, args...)
	}
	return exec.CommandContext(ctx, "journalctl", args...)
}

func (c *Collector) followJournal(ctx context.Context) error {
	if c.journalCursor == "" {
		// Check that a readable journal exists and establish a boundary without
		// replaying history. The follow command also includes records after this probe.
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		probe := c.journalCmd(probeCtx, "--no-pager", "--output=json", "--lines=1", "--output-fields=__CURSOR")
		var output, diagnostics boundedOutput
		probe.Stdout, probe.Stderr = &output, &diagnostics
		if err := probe.Run(); err != nil {
			return fmt.Errorf("read journal cursor: %w: %s", err, strings.TrimSpace(diagnostics.String()))
		}
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &entry); err != nil || journalString(entry["__CURSOR"]) == "" {
			return fmt.Errorf("no readable journal records: %s", strings.TrimSpace(diagnostics.String()))
		}
		c.journalCursor = journalString(entry["__CURSOR"])
	}

	cmd := c.journalCmd(ctx, "--follow", "--no-pager", "--output=json", "--all", "--no-tail",
		"--facility=auth,authpriv", "--after-cursor="+c.journalCursor,
		"--output-fields=MESSAGE,SYSLOG_IDENTIFIER,SYSLOG_PID,_COMM,_PID,_HOSTNAME")
	var diagnostics boundedOutput
	cmd.Stderr = &diagnostics
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		return err
	}
	c.setHealth(capability.HealthRunning)
	log.Print("authentication: following system journal (auth/authpriv)")
	reader := bufio.NewReader(stdout)
	for {
		line, readErr := readJournalLine(reader)
		if len(line) > 0 && readErr == nil {
			event, keep, cursor, parseErr := parseJournal(line, time.Now(), c.agentID, c.hostname)
			if parseErr != nil {
				c.setHealth(capability.HealthDegraded)
				log.Printf("authentication: invalid journal record: %v", parseErr)
			} else {
				if keep {
					c.pipeline.Emit(event)
				}
				c.journalCursor = cursor
				c.setHealth(capability.HealthRunning)
			}
		}
		if readErr != nil {
			if readErr != io.EOF && ctx.Err() == nil {
				_ = cmd.Process.Kill()
			}
			break
		}
	}
	err = cmd.Wait()
	return fmt.Errorf("journal stream ended (%v): %s", err, strings.TrimSpace(diagnostics.String()))
}

// Discard an oversized JSON line through its newline, then resume with the next record.
func readJournalLine(reader *bufio.Reader) ([]byte, error) {
	var line []byte
	oversized := false
	for {
		part, err := reader.ReadSlice('\n')
		if len(line)+len(part) > maxJournalLine {
			line, oversized = nil, true
		}
		if !oversized {
			line = append(line, part...)
		}
		if err != bufio.ErrBufferFull {
			return bytes.TrimSuffix(line, []byte{'\n'}), err
		}
	}
}

// Journal JSON can encode repeated fields as string arrays and binary fields as byte arrays.
func journalString(value json.RawMessage) string {
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	var texts []string
	if json.Unmarshal(value, &texts) == nil && len(texts) > 0 {
		return texts[0]
	}
	var raw []byte
	if json.Unmarshal(value, &raw) == nil {
		return string(raw)
	}
	return ""
}

func parseJournal(line []byte, observed time.Time, agentID, hostname string) (events.Event, bool, string, error) {
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(line, &entry); err != nil {
		return events.Event{}, false, "", err
	}
	cursor := journalString(entry["__CURSOR"])
	micros, err := strconv.ParseInt(journalString(entry["__REALTIME_TIMESTAMP"]), 10, 64)
	if err != nil || cursor == "" {
		return events.Event{}, false, "", fmt.Errorf("missing or invalid journal cursor/timestamp")
	}
	message := journalString(entry["MESSAGE"])
	if message == "" || len(message) > maxLine {
		return events.Event{}, false, cursor, nil
	}
	if name := journalString(entry["_HOSTNAME"]); name != "" {
		hostname = name
	}
	program := journalString(entry["SYSLOG_IDENTIFIER"])
	if program == "" {
		program = journalString(entry["_COMM"])
	}
	if program == "" {
		program = "unknown"
	}
	pid := journalString(entry["SYSLOG_PID"])
	if _, err := strconv.Atoi(pid); err != nil {
		pid = journalString(entry["_PID"])
	}
	if _, err := strconv.Atoi(pid); err == nil {
		program += "[" + pid + "]"
	}
	// Reuse message parsing while retaining the original structured journal record
	// as evidence and identifying the journal rather than inventing a file path.
	normalized := time.UnixMicro(micros).UTC().Format(time.RFC3339Nano) + " " + hostname + " " + program + ": " + message
	event, keep := parse(normalized, observed, agentID, hostname, "")
	if keep {
		event.Payload["event.original"] = string(line)
		event.Payload["log"] = map[string]interface{}{"logger": "systemd-journald"}
	}
	return event, keep, cursor, nil
}
