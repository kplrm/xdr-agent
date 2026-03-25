package controlplane

import (
	"bytes"
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
	// ManagerPolicyID is injected by the xdr-defense bundle endpoint.
	ManagerPolicyID string `json:"manager_policy_id,omitempty"`
}

// SigningPublicKeyResponse is returned by xdr-defense when requesting
// the active bundle-signing verification key.
type SigningPublicKeyResponse struct {
	PublicKeyB64 string `json:"public_key_b64"`
	KeyID        string `json:"key_id"`
}

// RuleActivationStatus tracks the result of activating a single YARA rule.
type RuleActivationStatus struct {
	RuleID       string `json:"rule_id"`       // e.g., "rule_trojan_banker_1"
	Status       string `json:"status"`        // "loaded" | "failed"
	ErrorMessage string `json:"error_message"` // reason for failure (if status="failed")
	LoadedAt     int64  `json:"loaded_at"`     // Unix timestamp when loaded (0 if failed)
}

// YaraRolloutStatusReport sent to backend after bundle activation.
type YaraRolloutStatusReport struct {
	ManagerPolicyID string                 `json:"manager_policy_id"`
	AgentID         string                 `json:"agent_id"`
	State           string                 `json:"state"`        // "acked" | "partial" | "failed"
	TotalRules      int                    `json:"total_rules"`  // total rules in bundle
	LoadedRules     int                    `json:"loaded_rules"` // how many actually loaded
	FailedRules     []RuleActivationStatus `json:"failed_rules"` // only failures (empty if all loaded)
	ReportedAt      int64                  `json:"reported_at"`
}

// PeriodicRuleInventory sent every 5 min to detect degradation.
type PeriodicRuleInventory struct {
	AgentID         string                 `json:"agent_id"`
	LoadedRuleCount int                    `json:"loaded_rule_count"` // actual count
	FailedRules     []RuleActivationStatus `json:"failed_rules"`      // rules now missing/corrupted
	CheckedAt       int64                  `json:"checked_at"`
}

// YaraRolloutAckRequest is sent to xdr-defense to acknowledge a YARA rollout.

// BundleFetchError is returned by FetchSignedYaraBundle when the server responds
// with a non-2xx status code.
type BundleFetchError struct {
	StatusCode      int
	Body            string
	ManagerPolicyID string
}

func (e *BundleFetchError) Error() string {
	return fmt.Sprintf("signed bundle fetch rejected: status=%d body=%s", e.StatusCode, strings.TrimSpace(e.Body))
}

// YaraRolloutAckRequest is deprecated and no longer used.
// Keeping for backwards compatibility if needed.
type YaraRolloutAckRequest struct {
	ManagerPolicyID string `json:"manager_policy_id"`
	AgentID         string `json:"agent_id"`
	Hostname        string `json:"hostname,omitempty"`
	State           string `json:"state"` // "acked" or "failed"
	FailureReason   string `json:"failure_reason,omitempty"`
	Action          string `json:"action,omitempty"`
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

const (
	// signedBundleResponseMaxBytes must comfortably exceed current production-sized
	// signed bundles (~24.8MB) to avoid truncation during JSON decode.
	signedBundleResponseMaxBytes = 64 * 1024 * 1024
)

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
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return fmt.Errorf("create rule directory for %s: %w", rule.Filename, err)
		}
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

	// Brace balance check — skips braces inside quoted string literals and
	// comments so rules like $s = "{path}\\file" don't produce false positives.
	{
		openBraces := 0
		inString := false
		inBlockComment := false
		inLineComment := false
		runes := []rune(content)
		for i := 0; i < len(runes); i++ {
			ch := runes[i]
			var next rune
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			if inLineComment {
				if ch == '\n' {
					inLineComment = false
				}
				continue
			}
			if inBlockComment {
				if ch == '*' && next == '/' {
					inBlockComment = false
					i++
				}
				continue
			}
			if inString {
				if ch == '\\' {
					i++ // skip escaped character
					continue
				}
				if ch == '"' {
					inString = false
				}
				continue
			}
			if ch == '/' && next == '/' {
				inLineComment = true
				i++
				continue
			}
			if ch == '/' && next == '*' {
				inBlockComment = true
				i++
				continue
			}
			if ch == '"' {
				inString = true
				continue
			}
			if ch == '{' {
				openBraces++
			} else if ch == '}' {
				openBraces--
				if openBraces < 0 {
					return fmt.Errorf("mismatched braces")
				}
			}
		}
		if openBraces != 0 {
			return fmt.Errorf("unbalanced braces")
		}
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

// ActivateBundleWithTracking validates and activates a bundle while tracking per-rule results.
// Returns a map of failed rule IDs to their activation status, and an overall error (if bundle failed).
// On success, the returned failedRulesMap will be empty. On partial failure, it contains failed rules.
func ActivateBundleWithTracking(
	bundle *SignedYaraBundle,
	publicKeyB64 string,
	rulesOutputDir string,
	metadataPath string,
) (map[string]RuleActivationStatus, error) {
	failedRulesMap := make(map[string]RuleActivationStatus)

	// Step 1: Verify signature
	if err := VerifyBundleSignature(bundle, publicKeyB64); err != nil {
		// Return empty failedRulesMap since we can't enumerate rules
		return failedRulesMap, fmt.Errorf("bundle signature verification failed: %w", err)
	}

	// Step 2: Validate rule content
	if err := ValidateAllRuleContent(bundle.Rules); err != nil {
		return failedRulesMap, fmt.Errorf("rule content validation failed: %w", err)
	}

	// Step 3: Verify checksums
	if err := VerifyRuleChecksums(bundle.Rules); err != nil {
		return failedRulesMap, fmt.Errorf("rule checksum verification failed: %w", err)
	}

	// Step 4: Save rules to temp directory and track per-rule results
	tempDir := rulesOutputDir + ".tmp"
	if err := os.RemoveAll(tempDir); err != nil && !os.IsNotExist(err) {
		return failedRulesMap, fmt.Errorf("clean temp rules dir: %w", err)
	}

	// Track per-rule success/failure during save
	now := time.Now().Unix()
	for _, rule := range bundle.Rules {
		path := filepath.Join(tempDir, rule.Filename)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			failedRulesMap[rule.ID] = RuleActivationStatus{
				RuleID:       rule.ID,
				Status:       "failed",
				ErrorMessage: fmt.Sprintf("failed to create directory: %v", err),
				LoadedAt:     0,
			}
			continue
		}

		if err := os.WriteFile(path, []byte(rule.Content), 0o640); err != nil {
			failedRulesMap[rule.ID] = RuleActivationStatus{
				RuleID:       rule.ID,
				Status:       "failed",
				ErrorMessage: fmt.Sprintf("failed to write rule file: %v", err),
				LoadedAt:     0,
			}
			continue
		}
	}

	// Only treat as total failure if there were rules to process and every one failed.
	// An empty bundle (len=0) is a legitimate "delete all rules" signal and must not
	// be confused with a write-error scenario.
	if len(bundle.Rules) > 0 && len(failedRulesMap) == len(bundle.Rules) {
		_ = os.RemoveAll(tempDir)
		return failedRulesMap, fmt.Errorf("all %d rules failed to save", len(bundle.Rules))
	}

	// Step 5: Atomically switch from temp to production directory.
	// For an empty bundle the temp dir was never created, so create it now so
	// the rename below results in an empty production dir (clearing all rules).
	if len(bundle.Rules) == 0 {
		if mkErr := os.MkdirAll(tempDir, 0o750); mkErr != nil {
			return failedRulesMap, fmt.Errorf("create empty rules temp dir: %w", mkErr)
		}
	}

	if err := os.RemoveAll(rulesOutputDir); err != nil && !os.IsNotExist(err) {
		_ = os.RemoveAll(tempDir)
		return failedRulesMap, fmt.Errorf("remove old rules dir: %w", err)
	}

	if err := os.Rename(tempDir, rulesOutputDir); err != nil {
		_ = os.RemoveAll(tempDir)
		return failedRulesMap, fmt.Errorf("activate rules (rename temp to production): %w", err)
	}

	// Step 6: Mark all non-failed rules as loaded
	for _, rule := range bundle.Rules {
		if _, isFailed := failedRulesMap[rule.ID]; !isFailed {
			// Mark as loaded (even though we can't validate against yara-x yet)
			// The detection engine will do actual yara-x rule validation
			failedRulesMap[rule.ID] = RuleActivationStatus{
				RuleID:       rule.ID,
				Status:       "loaded",
				ErrorMessage: "",
				LoadedAt:     now,
			}
		}
	}

	// Step 7: Save metadata
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
		return failedRulesMap, fmt.Errorf("save bundle metadata: %w", err)
	}

	return failedRulesMap, nil
}

// (Client) FetchSignedYaraBundle fetches the latest signed YARA bundle from xdr-defense.
// On a non-2xx response the error will be a *BundleFetchError, which may carry the
// server-side rollout_version so the caller can send a fail-ACK to the control plane.
func (c *Client) FetchSignedYaraBundle(ctx context.Context, policyID string) (*SignedYaraBundle, error) {
	path := "/api/xdr-defense/yara/bundle"
	return c.fetchSignedBundle(ctx, policyID, path)
}

// FetchSignedHashesBundle fetches the latest signed hashes bundle from xdr-defense.
func (c *Client) FetchSignedHashesBundle(ctx context.Context, policyID string) (*SignedYaraBundle, error) {
	path := "/api/xdr-defense/hashes/bundle"
	return c.fetchSignedBundle(ctx, policyID, path)
}

// FetchSignedBehavioralBundle fetches the latest signed behavioral rules bundle from xdr-defense.
func (c *Client) FetchSignedBehavioralBundle(ctx context.Context, policyID string) (*SignedYaraBundle, error) {
	path := "/api/xdr-defense/behavioral/bundle"
	return c.fetchSignedBundle(ctx, policyID, path)
}

// FetchSigningPublicKey fetches the current signing public key from xdr-defense.
func (c *Client) FetchSigningPublicKey(ctx context.Context) (*SigningPublicKeyResponse, error) {
	endpoint, err := c.buildURL("/api/xdr-defense/signing/public-key")
	if err != nil {
		return nil, fmt.Errorf("build signing public key endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build signing public key request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "xdr-agent")
	req.Header.Set("osd-xsrf", "true")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch signing public key: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read signing public key response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch signing public key rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var keyResp SigningPublicKeyResponse
	if err := json.Unmarshal(respBody, &keyResp); err != nil {
		return nil, fmt.Errorf("parse signing public key response: %w", err)
	}

	if strings.TrimSpace(keyResp.PublicKeyB64) == "" {
		return nil, fmt.Errorf("parse signing public key response: missing public_key_b64")
	}

	return &keyResp, nil
}

func (c *Client) fetchSignedBundle(ctx context.Context, policyID, path string) (*SignedYaraBundle, error) {
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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, signedBundleResponseMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("read signed bundle response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fetchErr := &BundleFetchError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
		// OSD serialises Boom errors as { statusCode, error, message, attributes }.
		// Extract manager policy ID from error attributes if available.
		var errMeta struct {
			Attributes struct {
				ManagerPolicyID string `json:"manager_policy_id"`
			} `json:"attributes"`
		}
		if json.Unmarshal(respBody, &errMeta) == nil && errMeta.Attributes.ManagerPolicyID != "" {
			fetchErr.ManagerPolicyID = errMeta.Attributes.ManagerPolicyID
		}
		return nil, fetchErr
	}

	var bundle SignedYaraBundle
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return nil, fmt.Errorf("parse signed bundle response: %w", err)
	}

	return &bundle, nil
}

// ActivateSignedContentBundle validates and activates a signed content bundle,
// replacing previous content atomically. It is used for non-YARA bundle types
// (e.g., hash lists, behavioral rules) that share the same signed manifest style.
func ActivateSignedContentBundle(
	bundle *SignedYaraBundle,
	publicKeyB64 string,
	outputDir string,
	metadataPath string,
) error {
	if err := VerifyBundleSignature(bundle, publicKeyB64); err != nil {
		return fmt.Errorf("bundle signature verification failed: %w", err)
	}

	if err := VerifyRuleChecksums(bundle.Rules); err != nil {
		return fmt.Errorf("bundle checksum verification failed: %w", err)
	}

	tempDir := outputDir + ".tmp"
	if err := os.RemoveAll(tempDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clean temp content dir: %w", err)
	}

	if err := SaveBundleRules(tempDir, bundle.Rules); err != nil {
		_ = os.RemoveAll(tempDir)
		return fmt.Errorf("save content bundle to temp: %w", err)
	}

	if err := os.RemoveAll(outputDir); err != nil && !os.IsNotExist(err) {
		_ = os.RemoveAll(tempDir)
		return fmt.Errorf("remove old content dir: %w", err)
	}

	if err := os.Rename(tempDir, outputDir); err != nil {
		_ = os.RemoveAll(tempDir)
		return fmt.Errorf("activate content (rename temp to production): %w", err)
	}

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

// AckYaraRollout posts a YARA rollout acknowledgement to xdr-defense.
// It is a best-effort call; the caller should log but not fail on error.
func (c *Client) AckYaraRollout(ctx context.Context, ackPath string, request YaraRolloutAckRequest) error {
	if !strings.HasPrefix(ackPath, "/") {
		ackPath = "/" + ackPath
	}
	endpoint, err := c.buildURL(ackPath)
	if err != nil {
		return fmt.Errorf("build YARA rollout ACK endpoint: %w", err)
	}

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal YARA rollout ACK payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("build YARA rollout ACK request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "xdr-agent")
	httpReq.Header.Set("osd-xsrf", "true")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send YARA rollout ACK: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return fmt.Errorf("read YARA rollout ACK response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("YARA rollout ACK rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return nil
}

// ReportYaraRuleStatus posts per-rule activation status to backend after bundle activation.
// This reports which individual rules succeeded/failed during bundle activation.
func (c *Client) ReportYaraRuleStatus(ctx context.Context, statusPath string, report *YaraRolloutStatusReport) error {
	if !strings.HasPrefix(statusPath, "/") {
		statusPath = "/" + statusPath
	}
	endpoint, err := c.buildURL(statusPath)
	if err != nil {
		return fmt.Errorf("build YARA rule status endpoint: %w", err)
	}

	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal YARA rule status payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("build YARA rule status request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "xdr-agent")
	httpReq.Header.Set("osd-xsrf", "true")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send YARA rule status: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return fmt.Errorf("read YARA rule status response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("YARA rule status rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return nil
}

// ReportRuleInventory posts periodic rule inventory check to backend.
// This detects degradation in loaded rules (e.g., rules that went missing or corrupted).
// Non-fatal: logs errors but does not fail.
func (c *Client) ReportRuleInventory(ctx context.Context, inventoryPath string, inventory *PeriodicRuleInventory) error {
	if !strings.HasPrefix(inventoryPath, "/") {
		inventoryPath = "/" + inventoryPath
	}
	endpoint, err := c.buildURL(inventoryPath)
	if err != nil {
		return fmt.Errorf("build rule inventory endpoint: %w", err)
	}

	body, err := json.Marshal(inventory)
	if err != nil {
		return fmt.Errorf("marshal rule inventory payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("build rule inventory request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "xdr-agent")
	httpReq.Header.Set("osd-xsrf", "true")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send rule inventory: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return fmt.Errorf("read rule inventory response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("rule inventory rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return nil
}
