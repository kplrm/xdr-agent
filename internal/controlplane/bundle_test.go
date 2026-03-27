package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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

func TestFetchSignedHashesCustomOverlayBundle_BuildsQueryAsQueryString(t *testing.T) {
	t.Parallel()

	const policyID = "custom-overlay/policy"
	runFetchSignedBundleQueryTest(t, "/api/xdr-defense/hashes/custom-overlay/bundle", policyID, func(c *Client, pid string) (*SignedYaraBundle, error) {
		return c.FetchSignedHashesCustomOverlayBundle(context.Background(), pid)
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

func TestActivateSignedHashesOverlayBundle_ManagesOnlyOverlayFiles(t *testing.T) {
	t.Parallel()

	outputDir := t.TempDir()
	metadataPath := filepath.Join(t.TempDir(), "hashes-custom-overlay-metadata.json")
	baselinePath := filepath.Join(outputDir, "baseline.yaml")
	if err := os.WriteFile(baselinePath, []byte("hashes:\n  - sha256: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n    name: \"baseline\"\n"), 0o600); err != nil {
		t.Fatalf("write baseline file: %v", err)
	}
	staleOverlayPath := filepath.Join(outputDir, "custom-critical-hashes-2026-03-26-00001.yaml")
	if err := os.WriteFile(staleOverlayPath, []byte("old"), 0o600); err != nil {
		t.Fatalf("write stale overlay file: %v", err)
	}
	if err := SaveHashesOverlayMetadata(metadataPath, HashesOverlayMetadata{
		BundleMetadata: BundleMetadata{
			BundleVersion:   1,
			PolicyID:        "policy-1",
			ActiveChecksums: []string{"oldsum"},
			RuleCount:       1,
		},
		ManagedFiles: []string{"custom-critical-hashes-2026-03-26-00001.yaml"},
	}); err != nil {
		t.Fatalf("seed overlay metadata: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}

	bundle := mustSignBundle(t, priv, &SignedYaraBundle{
		ManifestVersion: 1,
		PolicyID:        "policy-1",
		BundleVersion:   2,
		GeneratedAt:     "2026-03-27T12:00:00Z",
		SigningAlg:      "ed25519",
		Rules: []YaraRuleEntry{
			{
				ID:        "doc-123",
				Filename:  "custom-critical-hashes-2026-03-27-00001.yaml",
				Content:   "hashes:\n  - sha256: \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n    name: \"overlay-b\"\n",
				Enabled:   true,
				Source:    "custom",
				UpdatedAt: "2026-03-27T12:00:00Z",
			},
			{
				ID:        "doc 456",
				Filename:  "do-not-manage.yaml",
				Content:   "sha256: \"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"\nname: \"overlay-c\"\n",
				Enabled:   true,
				Source:    "custom",
				UpdatedAt: "2026-03-27T12:01:00Z",
			},
		},
	})

	if err := ActivateSignedHashesOverlayBundle(bundle, base64.StdEncoding.EncodeToString(pub), outputDir, metadataPath); err != nil {
		t.Fatalf("ActivateSignedHashesOverlayBundle error = %v", err)
	}

	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("expected baseline file to remain: %v", err)
	}
	if _, err := os.Stat(staleOverlayPath); !os.IsNotExist(err) {
		t.Fatalf("expected stale overlay file to be removed, stat err = %v", err)
	}

	newOverlayOne := filepath.Join(outputDir, "custom-critical-hashes-2026-03-27-00001.yaml")
	if content, err := os.ReadFile(newOverlayOne); err != nil {
		t.Fatalf("read first overlay file: %v", err)
	} else if !strings.Contains(string(content), "overlay-b") {
		t.Fatalf("unexpected first overlay content: %q", string(content))
	}
	unmanagedOverlay := filepath.Join(outputDir, "do-not-manage.yaml")
	if _, err := os.Stat(unmanagedOverlay); !os.IsNotExist(err) {
		t.Fatalf("expected unmanaged overlay filename to be skipped, stat err = %v", err)
	}

	meta, err := LoadHashesOverlayMetadata(metadataPath)
	if err != nil {
		t.Fatalf("LoadHashesOverlayMetadata error = %v", err)
	}
	if meta.BundleVersion != 2 {
		t.Fatalf("unexpected bundle version: got=%d want=2", meta.BundleVersion)
	}
	wantManaged := []string{"custom-critical-hashes-2026-03-27-00001.yaml"}
	if !reflect.DeepEqual(meta.ManagedFiles, wantManaged) {
		t.Fatalf("unexpected managed files: got=%v want=%v", meta.ManagedFiles, wantManaged)
	}
}

func TestReportHashesRolloutStatus(t *testing.T) {
	t.Parallel()

	var (
		gotMethod string
		gotPath   string
		gotBody   map[string]interface{}
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "", 5*time.Second, false)
	report := &HashesRolloutStatusReport{
		AgentID:             "agent-1",
		AgentHostname:       "host-1",
		PolicyID:            "policy-1",
		State:               "active",
		FullBundleVersion:   11,
		CustomBundleVersion: 12,
		ReportedAt:          1774600000,
	}

	if err := client.ReportHashesRolloutStatus(context.Background(), report); err != nil {
		t.Fatalf("ReportHashesRolloutStatus error = %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("unexpected method: got=%s want=%s", gotMethod, http.MethodPost)
	}
	if gotPath != "/api/xdr-defense/hashes/rollouts/status/report" {
		t.Fatalf("unexpected path: got=%s", gotPath)
	}
	if gotBody["agent_id"] != "agent-1" || gotBody["policy_id"] != "policy-1" {
		t.Fatalf("unexpected payload: %v", gotBody)
	}
}

func mustSignBundle(t *testing.T, privateKey ed25519.PrivateKey, bundle *SignedYaraBundle) *SignedYaraBundle {
	t.Helper()

	payload := BundlePayload{
		ManifestVersion: bundle.ManifestVersion,
		PolicyID:        bundle.PolicyID,
		BundleVersion:   bundle.BundleVersion,
		GeneratedAt:     bundle.GeneratedAt,
		SigningAlg:      bundle.SigningAlg,
		Rules:           append([]YaraRuleEntry(nil), bundle.Rules...),
		ActiveChecksums: append([]string(nil), bundle.ActiveChecksums...),
	}
	for index := range payload.Rules {
		payload.Rules[index].SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(payload.Rules[index].Content)))
		bundle.Rules[index].SHA256 = payload.Rules[index].SHA256
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signature := ed25519.Sign(privateKey, payloadBytes)
	bundle.SignatureBase64 = base64.StdEncoding.EncodeToString(signature)
	bundle.SignedPayloadB64 = base64.StdEncoding.EncodeToString(payloadBytes)
	return bundle
}
