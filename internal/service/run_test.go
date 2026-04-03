package service

import (
	"testing"

	"xdr-agent/internal/controlplane"
)

func TestShouldSkipApply_DigestMatchIgnoresVersionChurn(t *testing.T) {
	state := bundleSyncState{
		lastAppliedVersion: 5,
		lastAppliedDigest:  "abc123",
	}
	bundle := &controlplane.SignedYaraBundle{BundleVersion: 999}

	if !shouldSkipApply(state, bundle, "abc123") {
		t.Fatal("expected skip when digest is unchanged even if bundle version churns")
	}
}

func TestShouldSkipApply_DigestChangedForcesApply(t *testing.T) {
	state := bundleSyncState{
		lastAppliedVersion: 5,
		lastAppliedDigest:  "abc123",
	}
	bundle := &controlplane.SignedYaraBundle{BundleVersion: 5}

	if shouldSkipApply(state, bundle, "def456") {
		t.Fatal("expected apply when digest changed")
	}
}

func TestShouldSkipApply_FallbackChecksumsWithoutDigest(t *testing.T) {
	state := bundleSyncState{
		lastAppliedVersion:   10,
		lastAppliedCount:     2,
		lastAppliedChecksums: []string{"a", "b"},
	}
	bundle := &controlplane.SignedYaraBundle{
		BundleVersion:   999,
		Rules:           []controlplane.YaraRuleEntry{{ID: "1"}, {ID: "2"}},
		ActiveChecksums: []string{"a", "b"},
	}

	if !shouldSkipApply(state, bundle, "") {
		t.Fatal("expected skip when digest unavailable but count/checksums unchanged")
	}
}

func TestEngineReloadState_DigestDriven(t *testing.T) {
	state := &engineReloadState{name: "malware"}

	reload, reason := state.shouldReload("digest-a", 1)
	if !reload || reason != "startup" {
		t.Fatalf("startup reload mismatch: reload=%t reason=%s", reload, reason)
	}
	state.markReloaded("digest-a", 1)

	reload, reason = state.shouldReload("digest-a", 2)
	if reload || reason != "unchanged" {
		t.Fatalf("unchanged digest should skip reload: reload=%t reason=%s", reload, reason)
	}

	reload, reason = state.shouldReload("digest-b", 2)
	if !reload || reason != "digest_changed" {
		t.Fatalf("changed digest should reload: reload=%t reason=%s", reload, reason)
	}
}

func TestBundleDigest_IgnoresVersionAndTimestampChurn(t *testing.T) {
	b1 := &controlplane.SignedYaraBundle{
		PolicyID:      "default-endpoint",
		BundleVersion: 100,
		GeneratedAt:   "2026-04-03T09:00:00Z",
		SigningAlg:    "ed25519",
		Rules: []controlplane.YaraRuleEntry{
			{ID: "r1", Filename: "a.yar", SHA256: "aaa", Enabled: true},
			{ID: "r2", Filename: "b.yar", SHA256: "bbb", Enabled: false},
		},
		ActiveChecksums: []string{"aaa"},
	}

	b2 := &controlplane.SignedYaraBundle{
		PolicyID:      "default-endpoint",
		BundleVersion: 101,
		GeneratedAt:   "2026-04-03T09:00:05Z",
		SigningAlg:    "ed25519",
		Rules: []controlplane.YaraRuleEntry{
			{ID: "r2", Filename: "b.yar", SHA256: "bbb", Enabled: false},
			{ID: "r1", Filename: "a.yar", SHA256: "aaa", Enabled: true},
		},
		ActiveChecksums: []string{"aaa"},
	}

	if bundleDigest(b1) != bundleDigest(b2) {
		t.Fatal("expected identical digest when rule/checksum content is unchanged")
	}
}
