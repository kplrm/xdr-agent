package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func managedSettings(t *testing.T, value string) ManagedConfig {
	t.Helper()
	var settings map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &settings); err != nil {
		t.Fatal(err)
	}
	return ManagedConfig{SchemaVersion: 1, Revision: "policy:1", Settings: settings}
}

func TestManagedConfigPersistsAndResetsOnlyOwnedSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := `{"control_plane_url":"https://coordinator.invalid","enrollment_token":"keep-token","state_path":"` + filepath.Join(t.TempDir(), "state.json") + `","internal_networks":["203.0.113.0/24"],"telemetry_interval_seconds":9,"telemetry_ship_interval_seconds":17,"opensearch":{"url":"https://search.invalid","username":"local-writer","password_env":"KEEP_SECRET"},"future_local_setting":{"keep":true}}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	current, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	managed := managedSettings(t, `{"internal_networks":[],"process_scan_interval_seconds":2,"network_scan_interval_seconds":3}`)
	next, changed, err := ApplyManaged(path, current, managed)
	if err != nil || !changed {
		t.Fatalf("ApplyManaged changed=%t error=%v", changed, err)
	}
	if len(next.InternalNetworks) != 0 || next.ProcessScanInterval() != 2*time.Second || next.NetworkScanInterval() != 3*time.Second || next.TelemetryShipInterval() != 17*time.Second {
		t.Fatalf("wrong managed settings: %+v", next)
	}
	if next.EnrollmentToken != current.EnrollmentToken || next.OpenSearch != current.OpenSearch || next.ControlPlaneURL != current.ControlPlaneURL {
		t.Fatal("managed settings changed local enrollment or secrets")
	}
	persisted, err := Load(path)
	if err != nil || persisted.ManagedConfigRevision != "policy:1" || !reflect.DeepEqual(persisted.ManagedConfigKeys, next.ManagedConfigKeys) {
		t.Fatalf("managed metadata did not survive restart: %+v, %v", persisted, err)
	}
	data, _ := os.ReadFile(path)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || string(raw["future_local_setting"]) != "{\n    \"keep\": true\n  }" {
		t.Fatalf("unknown local setting lost: %s", data)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config mode=%o, want 600", info.Mode().Perm())
	}
	// Reapplying the same revision does not rewrite the file.
	if nextAgain, changed, err := ApplyManaged(path, persisted, managed); err != nil || changed || !reflect.DeepEqual(nextAgain, persisted) {
		t.Fatalf("repeat policy changed config=%t, error=%v", changed, err)
	}
	repeated, _ := os.Stat(path)
	if !os.SameFile(info, repeated) {
		t.Fatal("unchanged policy rewrote local configuration")
	}
	clear := managedSettings(t, `{}`)
	clear.Revision = "policy:2"
	reset, _, err := ApplyManaged(path, persisted, clear)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reset.InternalNetworks, DefaultInternalNetworks()) || reset.ProcessScanInterval() != time.Second || reset.NetworkScanInterval() != time.Second || reset.TelemetryShipInterval() != 17*time.Second || len(reset.ManagedConfigKeys) != 0 {
		t.Fatalf("removed overrides must reset defaults, preserving never-managed settings: %+v", reset)
	}
	if reset.ManagedConfigRevision != "policy:2" {
		t.Fatal("clear was not acknowledged")
	}
}

func TestManagedConfigRejectsWholeInvalidPolicyWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, Config{EnrollmentToken: "local-token", ProcessScanIntervalSeconds: 5}); err != nil {
		t.Fatal(err)
	}
	current, _ := LoadRaw(path)
	original, _ := os.ReadFile(path)
	for _, settings := range []string{
		`{"process_scan_interval_seconds":2,"control_plane_url":"https://attacker.invalid"}`,
		`{"internal_networks":null}`,
		`{"internal_networks":["invalid"]}`,
		`{"internal_networks":[42]}`,
		`{"process_scan_interval_seconds":0}`,
		`{"process_scan_interval_seconds":-1}`,
		`{"network_scan_interval_seconds":86401}`,
		`{"telemetry_ship_interval_seconds":1.5}`,
		`{"telemetry_ship_interval_seconds":"5"}`,
		`{"telemetry_ship_interval_seconds":null}`,
		`null`,
	} {
		t.Run(settings, func(t *testing.T) {
			policy := managedSettings(t, settings)
			if _, changed, err := ApplyManaged(path, current, policy); err == nil || changed {
				t.Fatalf("invalid policy accepted: changed=%t, error=%v", changed, err)
			}
			data, _ := os.ReadFile(path)
			if string(data) != string(original) {
				t.Fatal("invalid policy changed local configuration")
			}
		})
	}
	for _, policy := range []ManagedConfig{
		{SchemaVersion: 2, Revision: "policy:1", Settings: map[string]json.RawMessage{}},
		{SchemaVersion: 1, Settings: map[string]json.RawMessage{}},
	} {
		if _, _, err := ApplyManaged(path, current, policy); err == nil {
			t.Fatal("unsupported schema or absent revision accepted")
		}
	}
}

func TestManagedConfigPersistenceFailureKeepsCurrentRevision(t *testing.T) {
	current := Config{ManagedConfigRevision: "policy:1", NetworkScanIntervalSeconds: 5}
	next, changed, err := ApplyManaged(filepath.Join(t.TempDir(), "missing", "config.json"), current, managedSettings(t, `{"network_scan_interval_seconds":2}`))
	if err == nil || changed || !reflect.DeepEqual(next, current) {
		t.Fatalf("failed persistence changed config: changed=%t, error=%v", changed, err)
	}
}
