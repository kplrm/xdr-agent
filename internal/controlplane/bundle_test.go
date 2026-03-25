package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchSignedYaraBundle_ParsesLargeResponse(t *testing.T) {
	t.Parallel()

	const (
		policyID = "default"
		// Keep this above the previous 10MB cap so truncation regressions are caught.
		ruleContentSize = 11 * 1024 * 1024
	)

	largeRuleContent := strings.Repeat("A", ruleContentSize)

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
		_, _ = w.Write([]byte(fmt.Sprintf(`{"manifest_version":1,"policy_id":%q,"bundle_version":7,"generated_at":"2026-03-24T12:00:00Z","signing_alg":"ed25519","rules":[{"id":"r1","filename":"large_rule.yar","content":%q,"sha256":"","enabled":true,"source":"forge","updatedAt":"2026-03-24T12:00:00Z"}],"active_checksums":[],"signature_base64":"","signed_payload_base64":""}`,
			policyID,
			largeRuleContent,
		)))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "", 5*time.Second, false)
	bundle, err := client.FetchSignedYaraBundle(context.Background(), policyID)
	if err != nil {
		t.Fatalf("fetch large signed bundle error = %v", err)
	}
	if bundle.PolicyID != policyID {
		t.Fatalf("unexpected bundle policy id: got=%q want=%q", bundle.PolicyID, policyID)
	}
	if len(bundle.Rules) != 1 {
		t.Fatalf("unexpected rule count: got=%d want=1", len(bundle.Rules))
	}
	if got := len(bundle.Rules[0].Content); got != ruleContentSize {
		t.Fatalf("unexpected large rule content length: got=%d want=%d", got, ruleContentSize)
	}
}

func TestFetchSignedYaraBundle_BuildsQueryAsQueryString(t *testing.T) {
	t.Parallel()

	const policyID = "default endpoint/blue"
	runFetchSignedBundleQueryTest(t, "/api/xdr-defense/yara/bundle", policyID, func(c *Client, pid string) (*SignedYaraBundle, error) {
		return c.FetchSignedYaraBundle(context.Background(), pid)
	})
}

func TestFetchSignedHashesBundle_BuildsQueryAsQueryString(t *testing.T) {
	t.Parallel()

	const policyID = "hashes/policy"
	runFetchSignedBundleQueryTest(t, "/api/xdr-defense/hashes/bundle", policyID, func(c *Client, pid string) (*SignedYaraBundle, error) {
		return c.FetchSignedHashesBundle(context.Background(), pid)
	})
}

func TestFetchSignedBehavioralBundle_BuildsQueryAsQueryString(t *testing.T) {
	t.Parallel()

	const policyID = "behavioral policy/v2"
	runFetchSignedBundleQueryTest(t, "/api/xdr-defense/behavioral/bundle", policyID, func(c *Client, pid string) (*SignedYaraBundle, error) {
		return c.FetchSignedBehavioralBundle(context.Background(), pid)
	})
}

func runFetchSignedBundleQueryTest(
	t *testing.T,
	endpointPath string,
	policyID string,
	fetchFn func(*Client, string) (*SignedYaraBundle, error),
) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != endpointPath {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("policy_id"); got != policyID {
			t.Fatalf("unexpected policy_id query: got=%q want=%q", got, policyID)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"manifest_version":1,"policy_id":%q,"bundle_version":1,"generated_at":"2026-03-22T14:00:00Z","signing_alg":"ed25519","rules":[],"active_checksums":[],"signature_base64":"","signed_payload_base64":""}`,
			policyID,
		)))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "", 5*time.Second, false)
	bundle, err := fetchFn(client, policyID)
	if err != nil {
		t.Fatalf("fetch bundle error = %v", err)
	}
	if bundle.PolicyID != policyID {
		t.Fatalf("unexpected bundle policy id: got=%q want=%q", bundle.PolicyID, policyID)
	}
}

func TestFetchSigningPublicKey(t *testing.T) {
	t.Parallel()

	const (
		wantKeyB64 = "TRBp8Y7q0v9y9iS0LvxIt/wQ1KHNd+r/78boNhPKTtw="
		wantKeyID  = "k-2026-03"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/xdr-defense/signing/public-key" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"public_key_b64":%q,"key_id":%q}`, wantKeyB64, wantKeyID)))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "", 5*time.Second, false)
	resp, err := client.FetchSigningPublicKey(context.Background())
	if err != nil {
		t.Fatalf("FetchSigningPublicKey error = %v", err)
	}
	if resp.PublicKeyB64 != wantKeyB64 {
		t.Fatalf("unexpected public key: got=%q want=%q", resp.PublicKeyB64, wantKeyB64)
	}
	if resp.KeyID != wantKeyID {
		t.Fatalf("unexpected key id: got=%q want=%q", resp.KeyID, wantKeyID)
	}
}

func TestFetchSigningPublicKey_Non2xx(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"message":"upstream unavailable"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "", 5*time.Second, false)
	_, err := client.FetchSigningPublicKey(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status=502") {
		t.Fatalf("expected status code in error, got: %v", err)
	}
}

func TestFetchSigningPublicKey_MissingPublicKey(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"k-2026-03"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "", 5*time.Second, false)
	_, err := client.FetchSigningPublicKey(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing public_key_b64") {
		t.Fatalf("expected missing public_key_b64 error, got: %v", err)
	}
}
