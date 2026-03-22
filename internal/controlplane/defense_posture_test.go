package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr-agent/internal/config"
)

func TestDefensePostureStateRoundTrip(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "defense_posture.json")

	input := DefensePosture{
		PolicyID: "default-endpoint",
		Mode:     "detect",
		Capabilities: map[string]bool{
			"memory.fileless": true,
		},
		Version:   7,
		UpdatedAt: "2026-03-22T14:00:00Z",
	}

	if err := SaveDefensePosture(path, input); err != nil {
		t.Fatalf("SaveDefensePosture() error = %v", err)
	}

	got, err := LoadDefensePosture(path)
	if err != nil {
		t.Fatalf("LoadDefensePosture() error = %v", err)
	}
	if got.PolicyID != input.PolicyID || got.Mode != input.Mode || got.Version != input.Version {
		t.Fatalf("round-trip mismatch: got=%+v input=%+v", got, input)
	}
	if got.ReceivedAt == "" {
		t.Fatalf("receivedAt should be populated")
	}
}

func TestShouldApplyDefensePosture(t *testing.T) {
	t.Parallel()

	cached := DefensePosture{Version: 3}
	if !ShouldApplyDefensePosture(cached, DefensePosture{Version: 4}) {
		t.Fatalf("expected newer version to be applied")
	}
	if ShouldApplyDefensePosture(cached, DefensePosture{Version: 3}) {
		t.Fatalf("expected same version to be ignored")
	}
	if ShouldApplyDefensePosture(cached, DefensePosture{Version: 2}) {
		t.Fatalf("expected older version to be ignored")
	}
}

func TestApplyDefensePostureToConfig(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		DetectionPrevention: config.DetectionPreventionConfig{Mode: config.ModeDetect},
	}
	posture := DefensePosture{
		Mode: "prevent",
		Capabilities: map[string]bool{
			"memory.fileless":                 true,
			"prevention.enabled":              true,
			"malware.hash_detection":          true,
			"behavioral.rules":                true,
			"local_updates.enable_hot_reload": true,
		},
	}

	ApplyDefensePosture(&cfg, posture)
	if cfg.DetectionPrevention.Mode != config.ModePrevent {
		t.Fatalf("mode not applied: got=%s", cfg.DetectionPrevention.Mode)
	}
	if !cfg.DetectionPrevention.Capabilities.Memory.Fileless {
		t.Fatalf("memory.fileless should be true")
	}
	if !cfg.DetectionPrevention.Capabilities.Prevention.Enabled {
		t.Fatalf("prevention.enabled should be true")
	}
}

func TestFetchAndAckDefensePosture(t *testing.T) {
	t.Parallel()

	const policyID = "default-endpoint"
	var gotAckBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/xdr-defense/policy-overlays/"+policyID:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"manager_policy_id":"default-endpoint","mode":"detect","capabilities":{"memory.fileless":true},"updatedAt":"2026-03-22T14:00:00Z","version":5}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/xdr-defense/policy-rollouts/ack":
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&gotAckBody); err != nil {
				t.Fatalf("decode ack body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "", 5*time.Second, false)
	posture, err := client.FetchDefensePosture(context.Background(), policyID)
	if err != nil {
		t.Fatalf("FetchDefensePosture() error = %v", err)
	}
	if posture.Version != 5 || posture.PolicyID != policyID {
		t.Fatalf("unexpected posture: %+v", posture)
	}
	if !posture.Capabilities["memory.fileless"] {
		t.Fatalf("expected memory.fileless capability")
	}

	err = client.AckDefensePosture(context.Background(), "/api/xdr-defense/policy-rollouts/ack", DefensePostureAckRequest{
		AgentID:        "agent-1",
		PolicyID:       policyID,
		PostureVersion: 5,
		Hostname:       "srv-1",
	})
	if err != nil {
		t.Fatalf("AckDefensePosture() error = %v", err)
	}

	if gotAckBody["agent_id"] != "agent-1" || gotAckBody["policy_id"] != policyID {
		t.Fatalf("unexpected ack payload: %+v", gotAckBody)
	}
}

func TestDefensePostureStateFileReadableJSON(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "defense_posture.json")
	if err := SaveDefensePosture(path, DefensePosture{PolicyID: "p-1", Mode: "detect", Capabilities: map[string]bool{}, Version: 1}); err != nil {
		t.Fatalf("SaveDefensePosture() error = %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "\"policy_id\"") || !strings.Contains(text, "\"receivedAt\"") {
		t.Fatalf("expected stable readable JSON schema, got: %s", text)
	}
}
