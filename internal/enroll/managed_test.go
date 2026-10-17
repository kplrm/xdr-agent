package enroll

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"xdr-agent/internal/config"
	"xdr-agent/internal/identity"
)

func TestManagedConfigUsesExistingHeartbeatAndCommandResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var request HeartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if request.ConfigRevision != "policy:1" || request.ConfigError != "previous update rejected" {
				t.Errorf("missing last-good config acknowledgment: %+v", request)
			}
		}
		w.Write([]byte(`{"message":"ok","managed_config":{"schema_version":1,"revision":"policy:2","settings":{"network_scan_interval_seconds":2}}}`))
	}))
	defer server.Close()
	cfg := config.Config{ControlPlaneURL: server.URL, HeartbeatPath: "/heartbeat", CommandsPath: "/commands", RequestTimeoutSeconds: 1, ManagedConfigRevision: "policy:1", ManagedConfigError: "previous update rejected"}
	for _, name := range []string{"heartbeat", "commands"} {
		t.Run(name, func(t *testing.T) {
			var response HeartbeatResponse
			var err error
			if name == "heartbeat" {
				response, err = Heartbeat(context.Background(), cfg, identity.State{AgentID: "agent"}, "1.0.0")
			} else {
				response, err = PollCommands(context.Background(), cfg, identity.State{AgentID: "agent"}, "1.0.0")
			}
			if err != nil || response.ManagedConfig == nil || response.ManagedConfig.SchemaVersion != 1 || response.ManagedConfig.Revision != "policy:2" || string(response.ManagedConfig.Settings["network_scan_interval_seconds"]) != "2" {
				t.Fatalf("managed policy response lost: %+v, error=%v", response, err)
			}
		})
	}
}
