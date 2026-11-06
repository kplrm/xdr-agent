// Package authentication collects local authentication and privilege logs.
package authentication

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"xdr-agent/internal/events"
)

var (
	headerRE         = regexp.MustCompile(`^(\d{4}-\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s*(.*)$`)
	sshRE            = regexp.MustCompile(`^(Accepted|Failed|Partial) (\S+) for (invalid user )?(\S+) from (\S+) port (\d+) (ssh\d)(?::? (.*))?$`)
	keyRE            = regexp.MustCompile(`^(\S+) ((?:SHA256:|MD5:)[^ ]+)`)
	invalidUserRE    = regexp.MustCompile(`^Invalid user (\S+) from (\S+)(?: port (\d+))?`)
	pamRE            = regexp.MustCompile(`^(pam_\w+)\(([^:]+):([^)]+)\): (.*)$`)
	sessionRE        = regexp.MustCompile(`^session (opened|closed) for user ([^ (]+)(?:\(uid=(\d+)\))?(?: by ([^ (]*)(?:\(uid=(\d+)\))?)?$`)
	pamFieldRE       = regexp.MustCompile(`(?:^|[; ]+)(logname|uid|euid|tty|ruser|rhost|user)=([^; ]*)`)
	suRE             = regexp.MustCompile(`^\(to ([^)]+)\) (\S+) on (.+)$`)
	sudoRE           = regexp.MustCompile(`^\s*(\S+)\s*:\s*(.*?)(?: ; )?TTY=([^;]*?)\s*;\s*PWD=([^;]*?)\s*;\s*USER=([^;]*?)\s*;\s*(?:ENV=(.*?)\s*;\s*)?COMMAND=(.*)$`)
	pkexecRE         = regexp.MustCompile(`^(\S+): Executing command \[USER=([^]]+)\] \[TTY=([^]]+)\] \[CWD=([^]]+)\] \[COMMAND=(.*)\]$`)
	logindRE         = regexp.MustCompile(`^New session '?([^' ]+)'? of user '?([^' ]+?)'?(?: with class '([^']+)' and type '([^']+)')?\.$`)
	removedSessionRE = regexp.MustCompile(`^Removed session '?([^'. ]+)'?\.$`)
)

// parse retains unknown lines for inspection; false means an intentionally skipped CRON record.
func parse(line string, observed time.Time, agentID, hostname, path string) (events.Event, bool) {
	fields := map[string]interface{}{
		"event.created": observed.UTC(), "event.original": line, "event.dataset": "system.auth",
		"event.action": "authentication-log", "event.outcome": "unknown", "message": line,
		"log": map[string]interface{}{"file": map[string]interface{}{"path": path}},
	}
	event := events.Event{Timestamp: observed.UTC(), Type: "info", Category: "authentication", Kind: "event",
		Module: "telemetry.authentication", AgentID: agentID, Hostname: hostname, Payload: fields}
	header := headerRE.FindStringSubmatch(line)
	if header == nil {
		event.Tags = []string{"authentication-parse-failure"}
		return event, true
	}
	program, message := header[3], header[5]
	if strings.EqualFold(program, "cron") || strings.EqualFold(program, "crond") {
		return events.Event{}, false
	}
	if timestamp, err := time.Parse(time.RFC3339Nano, header[1]); err == nil {
		event.Timestamp = timestamp.UTC()
	} else if timestamp, err := time.ParseInLocation("Jan _2 15:04:05 2006", header[1]+" "+strconv.Itoa(observed.Year()), observed.Location()); err == nil {
		if timestamp.After(observed.Add(24 * time.Hour)) {
			timestamp = timestamp.AddDate(-1, 0, 0)
		}
		event.Timestamp = timestamp.UTC()
	} else {
		event.Tags = []string{"authentication-parse-failure"}
	}
	event.Hostname = header[2]
	process := map[string]interface{}{"name": program}
	if pid, err := strconv.Atoi(header[4]); err == nil {
		process["pid"] = pid
	}
	fields["process"], fields["message"] = process, message
	service := strings.TrimSuffix(program, "-session")
	fields["service"] = map[string]interface{}{"name": service}
	user, auth := map[string]interface{}{}, map[string]interface{}{}
	fields["user"] = user
	fields["xdr"] = map[string]interface{}{"authentication": auth}
	setAction := func(action, kind, outcome string) {
		fields["event.action"], event.Type, fields["event.outcome"] = action, kind, outcome
	}
	setSource := func(address, port string) {
		if address == "" {
			return
		}
		source := map[string]interface{}{"address": address}
		if net.ParseIP(address) != nil {
			source["ip"] = address
		}
		if number, err := strconv.Atoi(port); err == nil && number > 0 && number <= 65535 {
			source["port"] = number
		}
		fields["source"] = source
	}
	if match := sshRE.FindStringSubmatch(message); match != nil && strings.HasPrefix(program, "sshd") {
		user["name"], auth["method"], auth["invalid_user"] = match[4], match[2], match[3] != ""
		setSource(match[5], match[6])
		fields["network"] = map[string]interface{}{"transport": "tcp", "protocol": "ssh"}
		auth["ssh_version"] = match[7]
		if key := keyRE.FindStringSubmatch(match[8]); key != nil {
			auth["key"] = map[string]interface{}{"algorithm": key[1], "fingerprint": key[2]}
		}
		switch match[1] {
		case "Accepted":
			setAction("authentication-success", "start", "success")
		case "Failed":
			setAction("authentication-failure", "denied", "failure")
			if match[3] != "" {
				fields["event.reason"] = "invalid user"
			} else {
				fields["event.reason"] = "credentials rejected"
			}
		default:
			setAction("authentication-partial", "info", "unknown")
		}
	} else if match := invalidUserRE.FindStringSubmatch(message); match != nil && strings.HasPrefix(program, "sshd") {
		user["name"], auth["invalid_user"] = match[1], true
		setSource(match[2], match[3])
		// This is context for a later Failed record, not another failed attempt.
		setAction("invalid-user", "info", "unknown")
	} else if match := pamRE.FindStringSubmatch(message); match != nil {
		if strings.EqualFold(match[2], "cron") || strings.EqualFold(match[2], "crond") {
			return events.Event{}, false
		}
		fields["service"] = map[string]interface{}{"name": match[2]}
		auth["pam"] = map[string]interface{}{"module": match[1], "type": match[3]}
		if session := sessionRE.FindStringSubmatch(match[4]); session != nil {
			user["name"] = session[2]
			if session[3] != "" {
				user["id"] = session[3]
			}
			if session[4] != "" || session[5] != "" {
				actor := map[string]interface{}{}
				if session[4] != "" {
					actor["name"] = session[4]
				}
				if session[5] != "" {
					actor["id"] = session[5]
				}
				// The source user opened the session for the root-level user.
				fields["source"] = map[string]interface{}{"user": actor}
			}
			if session[1] == "opened" {
				setAction("session-start", "start", "success")
			} else {
				setAction("session-end", "end", "success")
			}
		} else {
			for _, pair := range pamFieldRE.FindAllStringSubmatch(match[4], -1) {
				if pair[2] == "" {
					continue
				}
				switch pair[1] {
				case "user":
					user["name"] = pair[2]
				case "rhost":
					setSource(pair[2], "")
				case "tty":
					process["tty"] = map[string]interface{}{"name": pair[2]}
				default:
					auth[pair[1]] = pair[2]
				}
			}
			if strings.HasPrefix(match[4], "authentication failure") {
				setAction("authentication-failure", "denied", "failure")
				fields["event.reason"] = "PAM authentication failure"
			} else {
				event.Tags = append(event.Tags, "authentication-unparsed")
			}
		}
	} else if match := suRE.FindStringSubmatch(message); match != nil && program == "su" {
		user["name"], user["effective"] = match[2], map[string]interface{}{"name": match[1]}
		process["tty"] = map[string]interface{}{"name": match[3]}
		// The summary names the actor and target, but not the credential method or result.
		setAction("su-command", "change", "unknown")
	} else if match := sudoRE.FindStringSubmatch(message); match != nil && program == "sudo" {
		user["name"] = match[1]
		user["effective"] = map[string]interface{}{"name": match[5]}
		process["tty"], process["working_directory"], process["command_line"] = map[string]interface{}{"name": match[3]}, match[4], match[7]
		if match[6] != "" {
			auth["environment"] = match[6]
		}
		setAction("sudo-command", "change", "success")
		if reason := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(match[2]), ";")); reason != "" {
			setAction("sudo-command", "denied", "failure")
			fields["event.reason"] = reason
		}
	} else if match := pkexecRE.FindStringSubmatch(message); match != nil && program == "pkexec" {
		user["name"], user["effective"] = match[1], map[string]interface{}{"name": match[2]}
		process["tty"], process["working_directory"], process["command_line"] = map[string]interface{}{"name": match[3]}, match[4], match[5]
		setAction("pkexec-command", "change", "success")
	} else if match := logindRE.FindStringSubmatch(message); match != nil && program == "systemd-logind" {
		user["name"] = match[2]
		session := map[string]interface{}{"id": match[1]}
		if match[3] != "" {
			session["class"], session["type"] = match[3], match[4]
		}
		auth["session"] = session
		setAction("session-start", "start", "success")
	} else if match := removedSessionRE.FindStringSubmatch(message); match != nil && program == "systemd-logind" {
		auth["session"] = map[string]interface{}{"id": match[1]}
		setAction("session-end", "end", "success")
	} else {
		event.Tags = append(event.Tags, "authentication-unparsed")
	}
	return event, true
}
