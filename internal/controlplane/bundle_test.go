package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchSignedYaraBundle_BuildsQueryAsQueryString(t *testing.T) {
	t.Parallel()

	const policyID = "default endpoint/blue"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/xdr-defense/yara/bundle" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("policy_id"); got != policyID {
			t.Fatalf("unexpected policy_id query: got=%q want=%q", got, policyID)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"manifest_version":1,"policy_id":"default endpoint/blue","bundle_version":1,"generated_at":"2026-03-22T14:00:00Z","signing_alg":"ed25519","rules":[],"active_checksums":[],"signature_base64":"","signed_payload_base64":""}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "", 5*time.Second, false)
	bundle, err := client.FetchSignedYaraBundle(context.Background(), policyID)
	if err != nil {
		t.Fatalf("FetchSignedYaraBundle() error = %v", err)
	}
	if bundle.PolicyID != policyID {
		t.Fatalf("unexpected bundle policy id: got=%q want=%q", bundle.PolicyID, policyID)
	}
}
