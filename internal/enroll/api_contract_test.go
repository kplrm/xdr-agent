package enroll_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
	"xdr-agent/internal/config"
	"xdr-agent/internal/controlplane"
	"xdr-agent/internal/enroll"
	"xdr-agent/internal/events"
	"xdr-agent/internal/identity"
)

// TestAgentAPI verifies outbound paths, headers, gzip batches, errors, and docs.
// Collector-specific event payloads are tested separately by telemetry packages.
func TestAgentAPI(t *testing.T) {
	exercised := map[string]bool{}
	for _, name := range []string{"enroll", "heartbeat", "commands", "telemetry", "security", "logs"} {
		t.Run(name, func(t *testing.T) {
			method := "POST"
			if name == "commands" {
				method = "GET"
			}
			path := "/api/v1/agents/" + name
			exercised[method+" "+path] = true
			for _, status := range []int{200, 401} {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.Method != method || r.URL.Path != "/dashboards"+path {
						t.Errorf("wrong route: %s %s", r.Method, r.URL.Path)
					}
					if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("osd-xsrf") != "true" {
						t.Error("missing auth/XSRF headers")
					}
					var body map[string]interface{}
					if name == "commands" {
						if r.URL.Query().Get("agent_id") != "agent-1" || r.URL.Query().Get("agent_version") != "1.0.0" {
							t.Error("missing command identity")
						}
					} else {
						var reader io.Reader = r.Body
						if name == "telemetry" || name == "security" || name == "logs" {
							if r.Header.Get("Content-Encoding") != "gzip" {
								t.Error("batch is not compressed")
							}
							gz, err := gzip.NewReader(r.Body)
							if err != nil {
								t.Error(err)
								return
							}
							defer gz.Close()
							reader = gz
						}
						if err := json.NewDecoder(reader).Decode(&body); err != nil {
							t.Error(err)
						}
						if body["agent_id"] != "agent-1" {
							t.Error("missing owner")
						}
						if name == "heartbeat" {
							p, ok := body["protection"].(map[string]interface{})
							if !ok || p["rule_count"] != float64(7) {
								t.Error("missing inventory")
							}
						}
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					io.WriteString(w, `{"enrollment_id":"agent-1","message":"ok","indexed":1,"pending_commands":["upgrade:2.0.0"]}`)
				}))
				cfg := config.Config{ControlPlaneURL: server.URL + "/dashboards", EnrollmentToken: "test-token", EnrollmentPath: "/api/v1/agents/enroll", HeartbeatPath: "/api/v1/agents/heartbeat", CommandsPath: "/api/v1/agents/commands", PolicyID: "default-endpoint", RequestTimeoutSeconds: 2}
				state := identity.State{AgentID: "agent-1", Hostname: "host"}
				var err error
				switch name {
				case "enroll":
					_, err = enroll.Enroll(context.Background(), cfg, state, "1.0.0")
				case "heartbeat":
					_, err = enroll.Heartbeat(context.Background(), cfg, state, "1.0.0", enroll.ProtectionInventory{RuleCount: 7})
				case "commands":
					_, err = enroll.PollCommands(context.Background(), cfg, state, "1.0.0")
				default:
					s := controlplane.NewShipper(controlplane.ShipperConfig{TelemetryURL: cfg.ControlPlaneURL, TelemetryPath: path, AgentID: state.AgentID, EnrollmentToken: cfg.EnrollmentToken, RequestTimeout: time.Second})
					s.Enqueue(events.Event{Type: "fixture", Timestamp: time.Now().UTC()})
					err = s.Flush(context.Background())
				}
				server.Close()
				if calls != 1 {
					t.Errorf("expected one request, got %d", calls)
				}
				if (err != nil) != (status != 200) {
					t.Fatalf("status=%d error=%v", status, err)
				}
			}
		})
	}
	document, err := os.ReadFile("../../docs/api-endpoints.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, r := range regexp.MustCompile(`(?m)^\| (GET|POST|PUT|DELETE|PATCH) \| (/api/[^ ]+) \|`).FindAllStringSubmatch(string(document), -1) {
		documented[r[1]+" "+r[2]] = true
	}
	if strings.Join(keys(documented), "\n") != strings.Join(keys(exercised), "\n") {
		t.Fatalf("documented API differs: documented=%v exercised=%v", keys(documented), keys(exercised))
	}
	literal := regexp.MustCompile(`"(/api/[^"?]+)"`)
	err = filepath.WalkDir("../../internal", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range literal.FindAllStringSubmatch(string(source), -1) {
			found := false
			for endpoint := range documented {
				if strings.HasSuffix(endpoint, " "+m[1]) {
					found = true
				}
			}
			if !found {
				t.Errorf("undocumented API path %s in %s", m[1], path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
