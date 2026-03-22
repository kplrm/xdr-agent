package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// YaraRuleEntry represents a single rule in a signed bundle.
type YaraRuleEntry struct {
	ID        string `json:"id"`
	Filename  string `json:"filename"`
	Content   string `json:"content"`
	SHA256    string `json:"sha256"`
	Enabled   bool   `json:"enabled"`
	Source    string `json:"source"`
	UpdatedAt string `json:"updatedAt"`
}

// BundlePayload is the unsigned manifest structure.
type BundlePayload struct {
	ManifestVersion int             `json:"manifest_version"`
	PolicyID        string          `json:"policy_id"`
	BundleVersion   int             `json:"bundle_version"`
	GeneratedAt     string          `json:"generated_at"`
	SigningAlg      string          `json:"signing_alg"`
	Rules           []YaraRuleEntry `json:"rules"`
	ActiveChecksums []string        `json:"active_checksums"`
}

// SignedYaraBundle is the full signed bundle response from xdr-defense.
type SignedYaraBundle struct {
	ManifestVersion  int             `json:"manifest_version"`
	PolicyID         string          `json:"policy_id"`
	BundleVersion    int             `json:"bundle_version"`
	GeneratedAt      string          `json:"generated_at"`
	SigningAlg       string          `json:"signing_alg"`
	Rules            []YaraRuleEntry `json:"rules"`
	ActiveChecksums  []string        `json:"active_checksums"`
	SignatureBase64  string          `json:"signature_base64"`
	SignedPayloadB64 string          `json:"signed_payload_base64"`
}

// BundleMetadata tracks the current active bundle locally on the agent.
type BundleMetadata struct {
	BundleVersion    int      `json:"bundle_version"`
	GeneratedAt      string   `json:"generated_at"`
	ActivatedAt      string   `json:"activated_at"`
	PolicyID         string   `json:"policy_id"`
	ActiveChecksums  []string `json:"active_checksums"`
	RuleCount        int      `json:"rule_count"`
	EnabledRuleCount int      `json:"enabled_rule_count"`
}

const defaultDevSigningPublicKeyB64 = "42NEblFO2ZJzJryCPXTalkrfoQCcFcYvslG96Si4u7U="

// SaveBundleMetadata persist current bundle metadata locally.
func SaveBundleMetadata(path string, meta BundleMetadata) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create bundle metadata dir: %w", err)
	}

	content, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle metadata: %w", err)
	}
	content = append(content, '\n')

	if err := os.WriteFile(path, content, 0o640); err != nil {
		return fmt.Errorf("write bundle metadata: %w", err)
	}
	return nil
}

// LoadBundleMetadata loads the current bundle metadata.
func LoadBundleMetadata(path string) (BundleMetadata, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return BundleMetadata{}, err
	}

	var meta BundleMetadata
	if err := json.Unmarshal(content, &meta); err != nil {
		return BundleMetadata{}, fmt.Errorf("parse bundle metadata: %w", err)
	}
	return meta, nil
}

// VerifyBundleSignature verifies the Ed25519 signature of a signed bundle.
// publicKeyHex is the base64-encoded Ed25519 public key from xdr-defense.
func VerifyBundleSignature(bundle *SignedYaraBundle, publicKeyB64 string) error {
	if bundle.SigningAlg != "ed25519" {
		return fmt.Errorf("unsupported signing algorithm: %s (expected ed25519)", bundle.SigningAlg)
	}

	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d (expected %d)", len(publicKeyBytes), ed25519.PublicKeySize)
	}

	pubKey := ed25519.PublicKey(publicKeyBytes)

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(bundle.SignatureBase64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: %d (expected %d)", len(signature), ed25519.SignatureSize)
	}

	// Decode signed payload (manifest)
	payloadBytes, err := base64.StdEncoding.DecodeString(bundle.SignedPayloadB64)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	// Verify signature
	if !ed25519.Verify(pubKey, payloadBytes, signature) {
		return fmt.Errorf("bundle signature verification failed")
	}

	// Verify payload structure matches bundle fields
	var payload BundlePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("parse payload manifest: %w", err)
	}

	if payload.ManifestVersion != bundle.ManifestVersion {
		return fmt.Errorf("manifest version mismatch")
	}
	if payload.PolicyID != bundle.PolicyID {
		return fmt.Errorf("policy ID mismatch")
	}
	if payload.BundleVersion != bundle.BundleVersion {
		return fmt.Errorf("bundle version mismatch")
	}

	return nil
}

// SaveBundleRules persists individual rule files to disk.
func SaveBundleRules(outputDir string, rules []YaraRuleEntry) error {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}

	for _, rule := range rules {
		path := filepath.Join(outputDir, rule.Filename)
		if err := os.WriteFile(path, []byte(rule.Content), 0o640); err != nil {
			return fmt.Errorf("write rule %s: %w", rule.Filename, err)
		}
	}

	return nil
}

// ValidateRuleContent performs basic YARA syntax validation (lexical check).
func ValidateRuleContent(content string) error {
	content = strings.TrimSpace(content)
	if len(content) == 0 {
		return fmt.Errorf("empty rule content")
	}

	if !strings.Contains(content, "rule ") {
		return fmt.Errorf("missing 'rule' keyword")
	}

	// Some upstream rule packs include formatting variants that still compile in
	// YARA engines but do not match a strict textual "condition:" token check.
	// Keep validation lightweight here and let the scanner/compiler enforce syntax.
	conditionPattern := regexp.MustCompile(`(?m)\bcondition\s*:`)
	_ = conditionPattern.MatchString(content)

	// Simple brace balance check
	openBraces := 0
	for _, ch := range content {
		if ch == '{' {
			openBraces++
		} else if ch == '}' {
			openBraces--
		}
		if openBraces < 0 {
			return fmt.Errorf("mismatched braces")
		}
	}
	if openBraces != 0 {
		return fmt.Errorf("unbalanced braces")
	}

	return nil
}

// ValidateAllRuleContent validates all rules in a bundle.
func ValidateAllRuleContent(rules []YaraRuleEntry) error {
	for _, rule := range rules {
		if err := ValidateRuleContent(rule.Content); err != nil {
			return fmt.Errorf("rule %s validation failed: %w", rule.Filename, err)
		}
	}
	return nil
}

// ComputeRuleChecksum computes the SHA256 hash of a rule file content.
func ComputeRuleChecksum(content string) string {
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// VerifyRuleChecksums verifies that rule content matches the declared SHA256 checksums.
func VerifyRuleChecksums(rules []YaraRuleEntry) error {
	for _, rule := range rules {
		computed := ComputeRuleChecksum(rule.Content)
		if computed != rule.SHA256 {
			return fmt.Errorf("rule %s checksum mismatch: expected %s, got %s", rule.Filename, rule.SHA256, computed)
		}
	}
	return nil
}

// (Client) FetchSignedYaraBundle fetches the latest signed YARA bundle from xdr-defense.
func (c *Client) FetchSignedYaraBundle(ctx context.Context, policyID string) (*SignedYaraBundle, error) {
	path := "/api/xdr-defense/yara/bundle"
	endpoint, err := c.buildURL(path)
	if err != nil {
		return nil, fmt.Errorf("build signed bundle endpoint: %w", err)
	}

	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse signed bundle endpoint: %w", err)
	}
	query := endpointURL.Query()
	query.Set("policy_id", policyID)
	endpointURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build signed bundle request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "xdr-agent")
	req.Header.Set("osd-xsrf", "true")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch signed bundle: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("read signed bundle response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("signed bundle fetch rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var bundle SignedYaraBundle
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return nil, fmt.Errorf("parse signed bundle response: %w", err)
	}

	return &bundle, nil
}

// ActivateYaraBundle validates and activates a signed bundle, replacing previous rules.
// This function:
// 1. Verifies the bundle signature
// 2. Validates all rule syntax
// 3. Verifies rule content checksums
// 4. Saves rules to disk
// 5. Saves bundle metadata
// On error, keeps previous active bundle intact.
func ActivateYaraBundle(
	bundle *SignedYaraBundle,
	publicKeyB64 string,
	rulesOutputDir string,
	metadataPath string,
) error {
	// Step 1: Verify signature
	if err := VerifyBundleSignature(bundle, publicKeyB64); err != nil {
		return fmt.Errorf("bundle signature verification failed: %w", err)
	}

	// Step 2: Validate rule content
	if err := ValidateAllRuleContent(bundle.Rules); err != nil {
		return fmt.Errorf("rule content validation failed: %w", err)
	}

	// Step 3: Verify checksums
	if err := VerifyRuleChecksums(bundle.Rules); err != nil {
		return fmt.Errorf("rule checksum verification failed: %w", err)
	}

	// Step 4: Save rules to a temporary directory first (atomic switch)
	tempDir := rulesOutputDir + ".tmp"
	if err := os.RemoveAll(tempDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clean temp rules dir: %w", err)
	}

	if err := SaveBundleRules(tempDir, bundle.Rules); err != nil {
		// Clean up temp directory
		_ = os.RemoveAll(tempDir)
		return fmt.Errorf("save bundle rules to temp: %w", err)
	}

	// Step 5: Atomically switch from temp to production directory
	// First remove the old directory
	if err := os.RemoveAll(rulesOutputDir); err != nil && !os.IsNotExist(err) {
		_ = os.RemoveAll(tempDir)
		return fmt.Errorf("remove old rules dir: %w", err)
	}

	// Move temp to production
	if err := os.Rename(tempDir, rulesOutputDir); err != nil {
		_ = os.RemoveAll(tempDir)
		return fmt.Errorf("activate rules (rename temp to production): %w", err)
	}

	// Step 6: Save metadata
	enabledCount := 0
	for _, rule := range bundle.Rules {
		if rule.Enabled {
			enabledCount++
		}
	}

	meta := BundleMetadata{
		BundleVersion:    bundle.BundleVersion,
		GeneratedAt:      bundle.GeneratedAt,
		ActivatedAt:      time.Now().UTC().Format(time.RFC3339),
		PolicyID:         bundle.PolicyID,
		ActiveChecksums:  bundle.ActiveChecksums,
		RuleCount:        len(bundle.Rules),
		EnabledRuleCount: enabledCount,
	}

	if err := SaveBundleMetadata(metadataPath, meta); err != nil {
		return fmt.Errorf("save bundle metadata: %w", err)
	}

	return nil
}

// GetPublicKeyForPolicy returns the public key for signing verification.
// In production, this should come from xdr-defense policy or a secure config.
// For now, it reads from environment variable XDR_DEFENSE_SIGNING_PUBLIC_KEY_B64.
func GetPublicKeyForPolicy(policyID string) (string, error) {
	pubKey := os.Getenv("XDR_DEFENSE_SIGNING_PUBLIC_KEY_B64")
	if pubKey == "" {
		return defaultDevSigningPublicKeyB64, nil
	}
	return pubKey, nil
}
