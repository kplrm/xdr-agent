package main

import (
	"os"
	"path/filepath"
	"testing"

	"xdr-agent/internal/config"
)

func TestEnrollmentConfigUsesInstalledPathWithoutChangingSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.json")
	target := filepath.Join(dir, "installed.json")
	original := []byte(`{"control_plane_url":"http://localhost:5601","enrollment_token":""}`)
	if err := os.WriteFile(source, original, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"enrollment_token":"old"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if got := targetConfigPath("enroll", source); got != config.DefaultConfigPath {
		t.Fatalf("enroll target = %q, want %q", got, config.DefaultConfigPath)
	}
	if got := targetConfigPath("run", source); got != source {
		t.Fatalf("run target = %q, want %q", got, source)
	}
	if err := saveConfigWithOverrides(source, target, func(cfg *config.Config) {
		cfg.EnrollmentToken = "new-token"
	}); err != nil {
		t.Fatal(err)
	}
	unchanged, err := os.ReadFile(source)
	if err != nil || string(unchanged) != string(original) {
		t.Fatalf("source changed: %q, err=%v", unchanged, err)
	}
	installed, err := config.LoadRaw(target)
	if err != nil {
		t.Fatal(err)
	}
	if installed.EnrollmentToken != "new-token" || installed.ControlPlaneURL != "http://localhost:5601" {
		t.Fatalf("installed config missing source settings or token: %+v", installed)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("installed config permissions = %o, want 600", info.Mode().Perm())
	}
}
