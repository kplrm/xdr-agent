package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMinimalConfigurationDefaultsToDetectionAndPeriodicDelivery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"control_plane_url":"https://localhost:5601","state_path":"`+filepath.Join(dir, "state.json")+`"}`), 0600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IsPreventionMode() || !cfg.Logging.Ship.Enabled {
		t.Fatal("wrong detection/logging defaults")
	}
	if cfg.OpenSearch.URL != "" {
		t.Fatal("direct delivery enabled without an API URL")
	}
	if cfg.OpenSearch.Username != "xdr-agent" {
		t.Fatal("wrong default OpenSearch username")
	}
	if cfg.HeartbeatInterval() != 30*time.Second || cfg.TelemetryInterval() != 5*time.Second || cfg.TelemetryShipInterval() != 30*time.Second || cfg.SecurityShipInterval() != 30*time.Second || cfg.LogsShipInterval() != 30*time.Second || len(cfg.ExecutionWatchPaths) == 0 {
		t.Fatal("wrong defaults")
	}
}

func TestPreventionRequiresExplicitMode(t *testing.T) {
	cfg := defaults()
	if cfg.IsPreventionMode() {
		t.Fatal("prevention enabled by default")
	}
	cfg.DetectionPrevention.Mode = ModePrevent
	if !cfg.IsPreventionMode() {
		t.Fatal("explicit prevention mode ignored")
	}
}

func TestTelemetryIntervalHasSafetyFloor(t *testing.T) {
	for configured, want := range map[int]time.Duration{
		0: 5 * time.Second, 1: 5 * time.Second, 5: 5 * time.Second, 10: 10 * time.Second,
	} {
		cfg := Config{TelemetryIntervalSeconds: configured}
		if got := cfg.TelemetryInterval(); got != want {
			t.Errorf("telemetry interval %d: got %s, want %s", configured, got, want)
		}
	}
}

func TestSaveKeepsEnrollmentTokenPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, Config{EnrollmentToken: "test-token"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestDirectIngestionRequiresHTTPS(t *testing.T) {
	for _, url := range []string{"http://localhost:9200", "https://user:password@localhost:9200", "https://localhost:9200?token=secret", "https://localhost:9200/#fragment"} {
		if err := (OpenSearchConfig{URL: url, Username: "xdr-agent"}).Validate(); err == nil {
			t.Errorf("invalid direct URL accepted: %s", url)
		}
	}
	if err := (OpenSearchConfig{URL: "https://localhost:9200", Username: "custom-writer"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (OpenSearchConfig{}).Validate(); err != nil {
		t.Fatal("Coordinator-only configuration rejected")
	}
	if (OpenSearchConfig{}).PasswordVariable() != "XDR_OPENSEARCH_PASSWORD" {
		t.Fatal("wrong default credential variable")
	}
	for _, username := range []string{"", " ", "user:password"} {
		if err := (OpenSearchConfig{URL: "https://localhost:9200", Username: username}).Validate(); err == nil {
			t.Error("invalid Basic-auth username accepted")
		}
	}
}

func TestMaxCPUCoresDefaultAndUnlimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, test := range []struct {
		name  string
		field string
		want  int
		err   bool
	}{
		{"default", "", 1, false},
		{"unlimited", `,"max_cpu_cores":0`, 0, false},
		{"multiple", `,"max_cpu_cores":2`, 2, false},
		{"negative", `,"max_cpu_cores":-1`, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(`{"control_plane_url":"https://localhost:5601","state_path":"`+filepath.Join(t.TempDir(), "state.json")+`"`+test.field+`}`), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err != nil) != test.err {
				t.Fatalf("Load error = %v, want error = %t", err, test.err)
			}
			if err == nil && cfg.MaxCPUCores != test.want {
				t.Fatalf("max_cpu_cores = %d, want %d", cfg.MaxCPUCores, test.want)
			}
		})
	}
}
