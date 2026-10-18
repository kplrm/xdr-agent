package controlplane

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xdr-agent/internal/config"
	"xdr-agent/internal/events"
)

func directFixture(t *testing.T, handler http.HandlerFunc) (config.OpenSearchConfig, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDR_TEST_PASSWORD", "private-password:with-special-chars!")
	return config.OpenSearchConfig{URL: server.URL + "/opensearch", Username: "custom-writer", PasswordEnv: "XDR_TEST_PASSWORD", CAFile: ca}, server
}

func TestDirectBulkUsesTrustedTLSBasicAuthNDJSONAndStableCreates(t *testing.T) {
	var requests atomic.Int32
	target, _ := directFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/opensearch/_bulk" || r.Method != "POST" {
			t.Errorf("wrong request target: %s %s", r.Method, r.URL.Path)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "custom-writer" || password != "private-password:with-special-chars!" {
			t.Error("missing OpenSearch Basic authentication")
		}
		if strings.Contains(r.Header.Get("Authorization"), "enrollment-token") {
			t.Error("enrollment token leaked to OpenSearch")
		}
		if r.Header.Get("Content-Type") != "application/x-ndjson" {
			t.Error("wrong bulk content type")
		}
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		defer gz.Close()
		decoder := json.NewDecoder(gz)
		var action map[string]map[string]string
		var document map[string]interface{}
		if err := decoder.Decode(&action); err != nil {
			t.Error(err)
		}
		if err := decoder.Decode(&document); err != nil {
			t.Error(err)
		}
		if action["create"]["_index"] != TelemetryStream || action["create"]["_id"] != "agent:event" || document["agent.id"] != "agent" {
			t.Error("incorrect stream, identity or operation")
		}
		for _, field := range []string{"id", "_id"} {
			if _, exists := document[field]; exists {
				t.Errorf("identity field %q leaked into the document body", field)
			}
		}
		if document["payload"] != nil || document["process"].(map[string]interface{})["pid"] != float64(42) {
			t.Error("event details were not sent at the root")
		}
		w.Header().Set("Content-Type", "application/json")
		if requests.Load() == 1 {
			fmt.Fprint(w, `{"errors":true,"items":[{"create":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"private event value"}}}]}`)
		} else {
			fmt.Fprint(w, `{"errors":true,"items":[{"create":{"status":409,"error":{"type":"version_conflict_engine_exception"}}}]}`)
		}
	})
	s, err := NewOpenSearchShipper(ShipperConfig{AgentID: "agent", EnrollmentToken: "enrollment-token", InsecureSkipTLS: true}, target, TelemetryStream)
	if err != nil {
		t.Fatal(err)
	}
	if s.client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("direct TLS verification disabled")
	}
	s.Enqueue(events.Event{ID: "event", AgentID: "spoofed", Timestamp: time.Now(), Payload: map[string]interface{}{"process": map[string]interface{}{"pid": 42}}})
	if err := s.Flush(context.Background()); err == nil || strings.Contains(err.Error(), "private event value") {
		t.Fatal("bulk item failure was lost or leaked event contents")
	}
	if len(s.buffer) != 1 {
		t.Fatal("failed event not retained")
	}
	if s.buffer[0].ID != "event" {
		t.Fatal("shipping mutated the buffered event identity")
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.buffer) != 0 || requests.Load() != 2 {
		t.Fatal("conflicting retry was not acknowledged")
	}
}

func TestDirectBulkRejectsMissingCredentialsInvalidCAAndUnexpectedStreams(t *testing.T) {
	t.Setenv("XDR_TEST_PASSWORD", "")
	target := config.OpenSearchConfig{URL: "https://localhost:9200", Username: "xdr-agent", PasswordEnv: "XDR_TEST_PASSWORD"}
	if _, err := NewOpenSearchShipper(ShipperConfig{}, target, TelemetryStream); err == nil {
		t.Fatal("missing password accepted")
	}
	t.Setenv("XDR_TEST_PASSWORD", "private-password")
	target.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := NewOpenSearchShipper(ShipperConfig{}, target, TelemetryStream); err == nil {
		t.Fatal("missing CA accepted")
	}
	if _, err := NewOpenSearchShipper(ShipperConfig{}, target, ".kibana"); err == nil {
		t.Fatal("unrelated stream accepted")
	}
}

func TestDirectBulkRetainsEventsOnIncompleteResponsesAndDoesNotFollowRedirects(t *testing.T) {
	var redirect atomic.Bool
	target, _ := directFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if redirect.Load() {
			w.Header().Set("Location", "https://unexpected.example/_bulk")
			w.WriteHeader(307)
			return
		}
		fmt.Fprint(w, `{"errors":false,"items":[]}`)
	})
	s, err := NewOpenSearchShipper(ShipperConfig{AgentID: "agent"}, target, LogsStream)
	if err != nil {
		t.Fatal(err)
	}
	s.Enqueue(events.Event{Timestamp: time.Now()})
	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("incomplete response accepted")
	}
	redirect.Store(true)
	if err := s.Flush(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect not rejected: %v", err)
	}
	if len(s.buffer) != 1 {
		t.Fatal("failed event not retained")
	}
}

func TestDirectBulkRetainsEventsOnAuthenticationFailure(t *testing.T) {
	var requests atomic.Int32
	target, _ := directFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"private-password:with-special-chars!"}`)
	})
	s, err := NewOpenSearchShipper(ShipperConfig{AgentID: "agent"}, target, SecurityStream)
	if err != nil {
		t.Fatal(err)
	}
	s.Enqueue(events.Event{ID: "event", Timestamp: time.Now()})
	err = s.Flush(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), s.password) {
		t.Fatal("authentication failure was lost or leaked credentials")
	}
	if len(s.buffer) != 1 || requests.Load() != 1 {
		t.Fatal("authentication failure discarded the batch or retried immediately")
	}
}

func TestDirectBulkValidatesServerCertificate(t *testing.T) {
	target, _ := directFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted request reached server") })
	target.CAFile = ""
	s, err := NewOpenSearchShipper(ShipperConfig{AgentID: "agent", InsecureSkipTLS: true}, target, SecurityStream)
	if err != nil {
		t.Fatal(err)
	}
	s.Enqueue(events.Event{Timestamp: time.Now()})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := s.Flush(ctx); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if len(s.buffer) != 1 {
		t.Fatal("event lost after TLS failure")
	}
}
