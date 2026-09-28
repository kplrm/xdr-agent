package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"xdr-agent/internal/config"
	"xdr-agent/internal/enroll"
	"xdr-agent/internal/identity"
)

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
