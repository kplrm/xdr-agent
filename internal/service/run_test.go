package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"xdr-agent/internal/config"
	"xdr-agent/internal/enroll"
	"xdr-agent/internal/identity"
)

func TestRunPersistsMissingDefaultsToSelectedConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enrollment_id":"agent"}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-config.json")
	content := `{"max_cpu_cores":0,"control_plane_url":"` + server.URL + `","state_path":"` + filepath.Join(dir, "state.json") + `","telemetry_interval_seconds":5}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Run(ctx, path, true, ""); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved config.Config
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.InternalNetworks) != 4 || saved.ProcessScanIntervalSeconds != 5 || saved.NetworkScanIntervalSeconds != 5 || saved.TelemetryShipIntervalSeconds != 30 || saved.ControlPlaneURL != server.URL {
		t.Fatal("startup did not persist effective defaults to the selected file")
	}
}

func TestUpgradeAttemptIDsDeduplicateAcrossPollsAndRestartsAndReportErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var beats, attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := "job:2"
		if r.URL.Path == "/heartbeat" {
			var request enroll.HeartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			switch beats.Add(1) {
			case 1:
				id = "job:1"
			case 2:
				id = "job:1" // Duplicate delivery must not restart the failed download.
				if request.UpgradeID != id || request.UpgradeError != "temporary download failure" || request.UpgradeRetryable == nil || !*request.UpgradeRetryable {
					t.Error("upgrade failure was not acknowledged")
				}
			default:
				cancel()
			}
		}
		fmt.Fprintf(w, `{"pending_commands":["upgrade:2.0.0"],"upgrade_id":%q}`, id)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "state.json")
	cfg := config.Config{ControlPlaneURL: server.URL, HeartbeatPath: "/heartbeat", CommandsPath: "/commands", RequestTimeoutSeconds: 1, EnrollIntervalSeconds: 30, HeartbeatIntervalSeconds: 30, CommandPollIntervalSeconds: 1, StatePath: path}
	state := identity.State{AgentID: "agent", Enrolled: true}
	perform := func(context.Context, string) error { attempts.Add(1); return errors.New("temporary download failure") }
	runFleetWithUpgrade(ctx, cfg, &state, func() enroll.ProtectionInventory { return enroll.ProtectionInventory{} }, func() {}, perform)
	if attempts.Load() != 2 {
		t.Fatalf("performed %d upgrades, want one per attempt ID", attempts.Load())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var restarted identity.State
	if err := json.Unmarshal(content, &restarted); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	// The fixture cancels the original context; bound this restart independently.
	ctx2, stop := context.WithTimeout(ctx2, 500*time.Millisecond)
	defer stop()
	runFleetWithUpgrade(ctx2, cfg, &restarted, func() enroll.ProtectionInventory { return enroll.ProtectionInventory{} }, func() {}, perform)
	if attempts.Load() != 2 || restarted.UpgradeID != "job:2" || beats.Load() < 4 {
		t.Fatal("restart repeated a command or did not report persisted state")
	}
}

func TestFleetRetriesEnrollmentAndReportsPeriodicHealth(t *testing.T) {
	var enrollments, beats atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/enroll":
			if enrollments.Add(1) == 1 {
				w.WriteHeader(503)
				return
			}
			w.Write([]byte(`{"enrollment_id":"agent"}`))
		case "/heartbeat":
			var req enroll.HeartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.Protection == nil || req.Protection.Health["yara"] != "running" {
				t.Error("health absent")
			}
			w.Write([]byte(`{"message":"ok"}`))
			if beats.Add(1) >= 2 {
				cancel()
			}
		default:
			w.Write([]byte(`{"message":"ok"}`))
		}
	}))
	defer server.Close()
	cfg := config.Config{ControlPlaneURL: server.URL, EnrollmentPath: "/enroll", HeartbeatPath: "/heartbeat", CommandsPath: "/commands", RequestTimeoutSeconds: 1, EnrollIntervalSeconds: 1, HeartbeatIntervalSeconds: 1, CommandPollIntervalSeconds: 1, StatePath: filepath.Join(t.TempDir(), "state.json")}
	state := identity.State{AgentID: "agent"}
	started := 0
	err := runFleet(ctx, cfg, &state, func() enroll.ProtectionInventory {
		return enroll.ProtectionInventory{Health: map[string]string{"yara": "running"}}
	}, func() { started++ })
	if !errors.Is(err, context.Canceled) || enrollments.Load() != 2 || beats.Load() < 2 || started != 1 {
		t.Fatalf("err=%v enrollments=%d beats=%d started=%d", err, enrollments.Load(), beats.Load(), started)
	}
}

func TestFleetAppliesPolicyAndAcknowledgesOnlyPersistedRevisions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "config.json")
	var beats atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/heartbeat" {
			w.Write([]byte(`{"message":"ok"}`))
			return
		}
		var request enroll.HeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		switch beats.Add(1) {
		case 1:
			if request.ConfigRevision != "" || request.ConfigError != "" {
				t.Error("agent acknowledged policy before receiving one")
			}
			w.Write([]byte(`{"managed_config":{"schema_version":1,"revision":"policy:1","settings":{"process_scan_interval_seconds":2}}}`))
		case 2:
			if request.ConfigRevision != "policy:1" || request.ConfigError != "" {
				t.Errorf("missing successful acknowledgment: %+v", request)
			}
			w.Write([]byte(`{"managed_config":{"schema_version":1,"revision":"policy:2","settings":{"internal_networks":["invalid"]}}}`))
		case 3:
			if request.ConfigRevision != "policy:1" || request.ConfigError == "" {
				t.Errorf("invalid policy must retain last successful revision and report an error: %+v", request)
			}
			w.Write([]byte(`{"managed_config":{"schema_version":1,"revision":"policy:3","settings":{}}}`))
		default:
			if request.ConfigRevision != "policy:3" || request.ConfigError != "" {
				t.Errorf("clear did not acknowledge/reset error: %+v", request)
			}
			w.Write([]byte(`{"message":"ok"}`))
			cancel()
		}
	}))
	defer server.Close()
	if err := os.WriteFile(path, []byte(`{"control_plane_url":"`+server.URL+`","heartbeat_path":"/heartbeat","commands_path":"/commands","heartbeat_interval_seconds":1,"command_poll_interval_seconds":1,"state_path":"`+filepath.Join(t.TempDir(), "state.json")+`","telemetry_ship_interval_seconds":17}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	state := identity.State{AgentID: "agent", Enrolled: true}
	var applied []int
	err = runFleet(ctx, cfg, &state, func() enroll.ProtectionInventory { return enroll.ProtectionInventory{} }, func() {}, func(current config.Config, managed config.ManagedConfig) (config.Config, error) {
		next, changed, err := config.ApplyManaged(path, current, managed)
		if changed && err == nil {
			applied = append(applied, next.ProcessScanIntervalSeconds)
		}
		return next, err
	})
	if !errors.Is(err, context.Canceled) || beats.Load() < 4 {
		t.Fatalf("fleet result=%v, beats=%d", err, beats.Load())
	}
	if len(applied) != 2 || applied[0] != 2 || applied[1] != 1 {
		t.Fatalf("invalid policy changed runtime or clear failed: %v", applied)
	}
	persisted, err := config.Load(path)
	if err != nil || persisted.ManagedConfigRevision != "policy:3" || persisted.ProcessScanIntervalSeconds != 1 || persisted.TelemetryShipIntervalSeconds != 17 {
		t.Fatalf("wrong persisted configuration: %+v, error=%v", persisted, err)
	}
}
