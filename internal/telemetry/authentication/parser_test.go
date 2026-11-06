package authentication

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseAuthenticationLogs(t *testing.T) {
	observed := time.Date(2026, 11, 3, 18, 0, 0, 0, time.FixedZone("local", 3600))
	tests := []struct {
		name, line string
		want       map[string]interface{}
	}{
		{"public key", "2026-11-03T17:15:14.649352+01:00 node2 sshd-session[2557810]: Accepted publickey for alice from 192.168.2.63 port 39082 ssh2: ED25519 SHA256:example/fingerprint", map[string]interface{}{
			"@timestamp": "2026-11-03T16:15:14.649352Z", "host.hostname": "node2", "process.pid": float64(2557810),
			"user.name": "alice", "event.type": "start", "event.action": "authentication-success", "event.outcome": "success",
			"source.ip": "192.168.2.63", "source.port": float64(39082), "service.name": "sshd",
			"xdr.authentication.method": "publickey", "xdr.authentication.key.algorithm": "ED25519",
			"xdr.authentication.key.fingerprint": "SHA256:example/fingerprint", "xdr.authentication.invalid_user": false,
		}},
		{"legacy failure", "Mar  3 20:06:27 laptop sshd[99999]: Failed password for invalid user xdr_test from 127.0.0.1 port 55555 ssh2", map[string]interface{}{
			"@timestamp": "2026-03-03T19:06:27Z", "user.name": "xdr_test", "event.type": "denied",
			"event.action": "authentication-failure", "event.outcome": "failure", "event.reason": "invalid user",
			"source.ip": "127.0.0.1", "source.port": float64(55555), "xdr.authentication.invalid_user": true,
			"xdr.authentication.method": "password", "xdr.authentication.key": nil,
		}},
		{"password ipv6", "2026-11-03T17:15:14Z node2 sshd[42]: Accepted password for root from 2001:db8::1 port 22 ssh2", map[string]interface{}{
			"user.name": "root", "source.ip": "2001:db8::1", "xdr.authentication.method": "password", "event.outcome": "success",
		}},
		{"sudo", "2026-03-02T19:01:44.421869+01:00 laptop sudo:    alice : TTY=pts/2 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/true", map[string]interface{}{
			"user.name": "alice", "user.effective.name": "root", "process.tty.name": "pts/2", "process.working_directory": "/home/alice",
			"process.command_line": "/usr/bin/true", "event.action": "sudo-command", "event.outcome": "success",
		}},
		{"sudo environment", "Mar  3 20:06:27 laptop sudo:    root : TTY=pts/99 ; PWD=/tmp ; USER=nobody ; ENV=XDR_TEST=yes ; COMMAND=/usr/bin/true --flag=a;b", map[string]interface{}{
			"user.name": "root", "user.effective.name": "nobody", "xdr.authentication.environment": "XDR_TEST=yes",
			"process.command_line": "/usr/bin/true --flag=a;b", "event.outcome": "success",
		}},
		{"sudo denied", "Mar  3 20:06:27 laptop sudo: alice : user NOT in sudoers ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/true", map[string]interface{}{
			"event.outcome": "failure", "event.type": "denied", "event.reason": "user NOT in sudoers",
		}},
		{"su summary", "2026-11-06T21:34:57.031197+00:00 xdr-agent-dev su[31]: (to nobody) root on none", map[string]interface{}{
			"user.name": "root", "user.effective.name": "nobody", "process.tty.name": "none", "process.pid": float64(31),
			"event.action": "su-command", "event.type": "change", "event.outcome": "unknown",
			"xdr.authentication.method": nil, "tags": nil,
		}},
		{"su pam open", "2026-11-06T21:34:57.031769+00:00 xdr-agent-dev su[31]: pam_unix(su:session): session opened for user nobody(uid=65534) by root(uid=0)", map[string]interface{}{
			"user.name": "nobody", "user.id": "65534", "source.user.name": "root", "source.user.id": "0",
			"event.action": "session-start", "event.outcome": "success", "service.name": "su",
			"xdr.authentication.pam.module": "pam_unix", "xdr.authentication.pam.type": "session",
			"xdr.authentication.method": nil, "user.effective.name": nil, "tags": nil,
		}},
		{"su pam close", "2026-11-06T21:34:57.035518+00:00 xdr-agent-dev su[31]: pam_unix(su:session): session closed for user nobody", map[string]interface{}{
			"user.name": "nobody", "event.action": "session-end", "event.outcome": "success",
			"xdr.authentication.method": nil, "user.effective.name": nil, "source.user.name": nil, "tags": nil,
		}},
		{"pam environment diagnostic", "2026-11-06T23:33:48.432036Z xdr-agent-dev su[22]: pam_env(su:session): Unable to open env file: /etc/default/locale", map[string]interface{}{
			"@timestamp": "2026-11-06T23:33:48.432036Z", "process.pid": float64(22),
			"event.action": "pam-environment-error", "event.type": "info", "event.outcome": "unknown", "service.name": "su",
			"event.reason": "Unable to open env file: /etc/default/locale", "file.path": "/etc/default/locale",
			"xdr.authentication.pam.module": "pam_env", "xdr.authentication.pam.type": "session",
			"user.name": nil, "user.effective.name": nil, "xdr.authentication.method": nil,
			"tags": nil, "event.original": nil,
		}},
		{"pam environment diagnostic without path", "2026-11-06T23:33:48.432036Z xdr-agent-dev su[22]: pam_env(su:session): Unable to open env file: ", map[string]interface{}{
			"event.action": "authentication-log", "file.path": nil,
			"tags": []interface{}{"authentication-unparsed"},
		}},
		{"pam user environment deprecation", "2026-11-06T23:50:10.842254Z node4 sshd[237340]: pam_env(sshd:session): deprecated reading of user environment enabled", map[string]interface{}{
			"@timestamp": "2026-11-06T23:50:10.842254Z", "host.hostname": "node4", "process.pid": float64(237340),
			"event.action": "pam-environment-warning", "event.type": "info", "event.outcome": "unknown",
			"event.reason": "deprecated reading of user environment enabled", "service.name": "sshd",
			"xdr.authentication.pam.module": "pam_env", "xdr.authentication.pam.type": "session",
			"user.name": nil, "xdr.authentication.method": nil, "file.path": nil,
			"tags": nil, "event.original": nil,
		}},
		{"environment deprecation from another module", "2026-11-06T23:50:10.842254Z node4 sshd[237340]: pam_other(sshd:session): deprecated reading of user environment enabled", map[string]interface{}{
			"event.action": "authentication-log", "event.outcome": "unknown",
			"tags": []interface{}{"authentication-unparsed"},
		}},
		{"unknown pam diagnostic", "2026-11-06T23:33:48.432036Z xdr-agent-dev su[22]: pam_env(su:session): unsupported environment diagnostic", map[string]interface{}{
			"event.action": "authentication-log", "event.outcome": "unknown", "file.path": nil,
			"tags": []interface{}{"authentication-unparsed"},
		}},
		{"pam open", "2026-11-03T17:15:14.651210+01:00 node2 sshd-session[2557810]: pam_unix(sshd:session): session opened for user alice(uid=1000) by alice(uid=0)", map[string]interface{}{
			"user.name": "alice", "user.id": "1000", "source.user.name": "alice", "source.user.id": "0", "event.action": "session-start",
			"xdr.authentication.pam.module": "pam_unix", "xdr.authentication.pam.type": "session", "service.name": "sshd",
		}},
		{"pam close", "2026-03-02T19:02:17.302232+01:00 laptop sudo: pam_unix(sudo:session): session closed for user root", map[string]interface{}{
			"user.name": "root", "event.action": "session-end", "event.type": "end", "user.id": nil, "event.outcome": "success",
		}},
		{"systemd pam", "2026-11-03T17:15:14.720159+01:00 node2 (systemd): pam_unix(systemd-user:session): session opened for user alice(uid=1000) by (uid=0)", map[string]interface{}{
			"process.name": "(systemd)", "service.name": "systemd-user", "user.id": "1000", "source.user.id": "0",
		}},
		{"pkexec", "2026-03-02T19:02:33.599027+01:00 laptop pkexec[61586]: alice: Executing command [USER=root] [TTY=unknown] [CWD=/home/alice] [COMMAND=/usr/lib/update-notifier/package-system-locked]", map[string]interface{}{
			"user.name": "alice", "user.effective.name": "root", "process.pid": float64(61586), "process.tty.name": "unknown",
			"process.working_directory": "/home/alice", "process.command_line": "/usr/lib/update-notifier/package-system-locked", "event.action": "pkexec-command",
		}},
		{"logind", "2026-11-03T17:15:14.662261+01:00 node2 systemd-logind[1615]: New session '3584' of user 'alice' with class 'user' and type 'tty'.", map[string]interface{}{
			"user.name": "alice", "xdr.authentication.session.id": "3584", "xdr.authentication.session.class": "user",
			"xdr.authentication.session.type": "tty", "event.action": "session-start",
		}},
		{"logind legacy", "Mar  3 20:06:27 laptop systemd-logind[1615]: New session 42 of user alice.", map[string]interface{}{
			"user.name": "alice", "xdr.authentication.session.id": "42", "event.action": "session-start",
		}},
		{"pam failure", "Mar  3 20:06:27 laptop sshd[42]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1 user=alice", map[string]interface{}{
			"user.name": "alice", "source.ip": "192.0.2.1", "process.tty.name": "ssh", "xdr.authentication.uid": "0",
			"xdr.authentication.euid": "0", "event.action": "authentication-failure", "event.outcome": "failure",
		}},
		{"invalid user context", "Mar  3 20:06:27 laptop sshd[42]: Invalid user alice from 192.0.2.1 port 22", map[string]interface{}{
			"user.name": "alice", "event.action": "invalid-user", "event.outcome": "unknown", "source.ip": "192.0.2.1",
		}},
		{"unknown", "Mar  3 20:06:27 laptop login[42]: unsupported authentication message", map[string]interface{}{
			"event.action": "authentication-log", "event.outcome": "unknown", "message": "unsupported authentication message",
		}},
		{"malformed", "not a syslog line", map[string]interface{}{
			"event.outcome": "unknown", "message": "not a syslog line",
			"tags": []interface{}{"authentication-parse-failure", "authentication-unparsed"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, keep := parse(test.line, observed, "agent-1", "fallback", "/var/log/auth.log")
			if !keep {
				t.Fatal("unexpectedly ignored record")
			}
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]interface{}
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			for key, want := range test.want {
				if got := lookup(document, key); !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v, want %#v", key, got, want)
				}
			}
			for key, want := range map[string]interface{}{"event.category": "authentication", "event.module": "telemetry.authentication", "agent.id": "agent-1", "event.created": "2026-11-03T17:00:00Z", "log.file.path": "/var/log/auth.log"} {
				if got := lookup(document, key); got != want {
					t.Errorf("%s = %#v, want %#v", key, got, want)
				}
			}
			original, exists := document["event.original"]
			if unparsed := slices.Contains(event.Tags, "authentication-unparsed"); exists != unparsed || (unparsed && original != test.line) {
				t.Errorf("event.original = %#v (exists=%v), tags=%v", original, exists, event.Tags)
			}
			if _, exists := document["event.severity"]; exists {
				t.Fatal("authentication telemetry must be unscored")
			}
		})
	}
}

func lookup(document map[string]interface{}, key string) interface{} {
	if value, exists := document[key]; exists {
		return value
	}
	parts := strings.SplitN(key, ".", 2)
	if len(parts) == 2 {
		if nested, ok := document[parts[0]].(map[string]interface{}); ok {
			return lookup(nested, parts[1])
		}
	}
	return nil
}

func TestIgnoreCronAndInferLegacyYear(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, line := range []string{
		"2026-03-02T18:45:01.188159+01:00 laptop CRON[53218]: pam_unix(cron:session): session closed for user root",
		"Mar  3 20:06:27 laptop crond[42]: pam_unix(crond:session): session opened for user root(uid=0) by root(uid=0)",
		"Mar  3 20:06:27 laptop other[42]: pam_unix(cron:session): session closed for user root",
	} {
		if _, keep := parse(line, now, "agent", "host", "auth.log"); keep {
			t.Errorf("retained CRON: %s", line)
		}
	}
	event, _ := parse("Dec 31 23:59:59 laptop sshd[42]: Failed password for root from 127.0.0.1 port 22 ssh2", now, "agent", "host", "auth.log")
	if event.Timestamp.Year() != 2026 {
		t.Fatalf("year = %d", event.Timestamp.Year())
	}
}
