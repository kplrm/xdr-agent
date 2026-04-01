package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"xdr-agent/internal/agentlog"
	"xdr-agent/internal/buildinfo"
	"xdr-agent/internal/capability"
	"xdr-agent/internal/config"
	"xdr-agent/internal/controlplane"
	"xdr-agent/internal/detection"
	"xdr-agent/internal/enroll"
	"xdr-agent/internal/events"
	"xdr-agent/internal/identity"
	"xdr-agent/internal/prevention"
	"xdr-agent/internal/telemetry/file"
	"xdr-agent/internal/telemetry/injection"
	"xdr-agent/internal/telemetry/ipc"
	"xdr-agent/internal/telemetry/kernel"
	"xdr-agent/internal/telemetry/library"
	"xdr-agent/internal/telemetry/network"
	"xdr-agent/internal/telemetry/process"
	"xdr-agent/internal/telemetry/scheduled"
	"xdr-agent/internal/telemetry/session"
	"xdr-agent/internal/telemetry/system"
	"xdr-agent/internal/telemetry/tty"
	"xdr-agent/internal/upgrade"
)

type bundleSyncState struct {
	name                 string
	lastAppliedVersion   int
	lastAppliedDigest    string
	lastAppliedCount     int
	lastAppliedChecksums []string
	lastAppliedSource    string
	lastSkippedDuplicate int
	lastFailureSignature string
	lastFailureCount     int
	lastOutcome          string
}

func bundleDigest(bundle *controlplane.SignedYaraBundle) string {
	if bundle == nil {
		return ""
	}

	type digestRule struct {
		ID       string `json:"id"`
		Filename string `json:"filename"`
		SHA256   string `json:"sha256"`
		Enabled  bool   `json:"enabled"`
	}

	rules := make([]digestRule, 0, len(bundle.Rules))
	for _, rule := range bundle.Rules {
		rules = append(rules, digestRule{
			ID:       rule.ID,
			Filename: rule.Filename,
			SHA256:   strings.ToLower(strings.TrimSpace(rule.SHA256)),
			Enabled:  rule.Enabled,
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Filename == rules[j].Filename {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Filename < rules[j].Filename
	})

	checksums := append([]string(nil), bundle.ActiveChecksums...)
	sort.Strings(checksums)

	payload := struct {
		PolicyID       string       `json:"policy_id"`
		BundleVersion  int          `json:"bundle_version"`
		GeneratedAt    string       `json:"generated_at"`
		SigningAlg     string       `json:"signing_alg"`
		Rules          []digestRule `json:"rules"`
		ActiveChecksum []string     `json:"active_checksums"`
	}{
		PolicyID:       bundle.PolicyID,
		BundleVersion:  bundle.BundleVersion,
		GeneratedAt:    bundle.GeneratedAt,
		SigningAlg:     bundle.SigningAlg,
		Rules:          rules,
		ActiveChecksum: checksums,
	}

	serialized, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(serialized)
	return hex.EncodeToString(hash[:])
}

func loadInitialBundleState(name, metadataPath string) bundleSyncState {
	state := bundleSyncState{name: name, lastOutcome: "unknown"}
	meta, err := controlplane.LoadBundleMetadata(metadataPath)
	if err != nil {
		if !os.IsNotExist(err) {
			state.lastOutcome = "metadata_error"
		}
		return state
	}
	state.lastAppliedVersion = meta.BundleVersion
	state.lastAppliedCount = meta.RuleCount
	state.lastAppliedChecksums = append([]string(nil), meta.ActiveChecksums...)
	sort.Strings(state.lastAppliedChecksums)
	state.lastAppliedSource = "metadata"
	state.lastOutcome = "active"
	return state
}

func loadInitialHashesOverlayBundleState(name, metadataPath string) bundleSyncState {
	state := bundleSyncState{name: name, lastOutcome: "unknown"}
	meta, err := controlplane.LoadHashesOverlayMetadata(metadataPath)
	if err != nil {
		if !os.IsNotExist(err) {
			state.lastOutcome = "metadata_error"
		}
		return state
	}
	state.lastAppliedVersion = meta.BundleVersion
	state.lastAppliedCount = meta.RuleCount
	state.lastAppliedChecksums = append([]string(nil), meta.ActiveChecksums...)
	sort.Strings(state.lastAppliedChecksums)
	state.lastAppliedSource = "metadata"
	state.lastOutcome = "active"
	return state
}

func (s bundleSyncState) summaryLabel() string {
	if s.lastOutcome == "disabled" {
		return "disabled"
	}
	if s.lastAppliedVersion > 0 || s.lastAppliedSource != "" {
		return fmt.Sprintf("v%d,count=%d,state=%s", s.lastAppliedVersion, s.lastAppliedCount, s.lastOutcome)
	}
	return fmt.Sprintf("state=%s", s.lastOutcome)
}

func shouldSkipApply(state bundleSyncState, bundle *controlplane.SignedYaraBundle, digest string) bool {
	if bundle == nil {
		return false
	}
	if state.lastAppliedVersion <= 0 {
		return false
	}
	if digest != "" && state.lastAppliedDigest != "" {
		return state.lastAppliedVersion == bundle.BundleVersion && state.lastAppliedDigest == digest
	}
	if state.lastAppliedVersion != bundle.BundleVersion || state.lastAppliedCount != len(bundle.Rules) {
		return false
	}
	if len(state.lastAppliedChecksums) == 0 && len(bundle.ActiveChecksums) == 0 {
		return true
	}
	bundleChecksums := append([]string(nil), bundle.ActiveChecksums...)
	sort.Strings(bundleChecksums)
	return strings.Join(state.lastAppliedChecksums, ",") == strings.Join(bundleChecksums, ",")
}

func Run(ctx context.Context, configPath string, once bool, enrollmentToken string) error {
	// Load configuration from config.json
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if enrollmentToken != "" {
		cfg.EnrollmentToken = enrollmentToken
	}

	postureState := controlplane.DefensePosture{}
	if cachedPosture, postureErr := controlplane.LoadDefensePosture(cfg.DefensePosturePath); postureErr == nil {
		controlplane.ApplyDefensePosture(&cfg, cachedPosture)
		postureState = cachedPosture
		log.Printf("Defense Posture cache loaded: policy_id=%s version=%d mode=%s", cachedPosture.PolicyID, cachedPosture.Version, cachedPosture.Mode)
	} else if !os.IsNotExist(postureErr) {
		log.Printf("warning: failed to load Defense Posture cache: %v", postureErr)
	}

	// Ensure identity State from 'state_path' is initialized and load current state
	state, err := identity.Ensure(cfg.StatePath)
	if err != nil {
		return fmt.Errorf("initialize identity state: %w", err)
	}

	log.Printf("xdr-agent starting: agent_id=%s machine_id=%s hostname=%s", state.AgentID, state.MachineID, state.Hostname)

	controlPlaneClient := controlplane.NewClient(cfg.ControlPlaneURL, cfg.EnrollmentToken, cfg.RequestTimeout(), cfg.InsecureSkipTLSVerify)

	enrollAttempt := func() error {
		resp, enrollErr := enroll.Enroll(ctx, cfg, state, buildinfo.Version) // Attempt enrollment with the current state and configuration
		state = identity.MarkEnrollment(state, resp.EnrollmentID, enrollErr) // Update state with enrollment results (success or failure)
		if saveErr := identity.Save(cfg.StatePath, state); saveErr != nil {
			return fmt.Errorf("save state: %w", saveErr)
		}

		if enrollErr != nil {
			return enrollErr
		}

		log.Printf("enrollment successful: enrollment_id=%s message=%s", resp.EnrollmentID, resp.Message)
		return nil
	}

	heartbeatAttempt := func() (enroll.HeartbeatResponse, error) {
		hbResp, err := enroll.Heartbeat(ctx, cfg, state, buildinfo.Version)
		if err != nil {
			return enroll.HeartbeatResponse{}, err
		}

		log.Printf("heartbeat successful: agent_id=%s", state.AgentID)
		return hbResp, nil
	}

	// handleHeartbeatCommands processes any commands returned by the control
	// plane in the heartbeat response (e.g. upgrade:0.3.2).
	var detectionEngine *detection.Engine
	var syncYaraBundle func(bool) bool

	handleHeartbeatCommands := func(resp enroll.HeartbeatResponse) {
		for _, cmd := range resp.PendingCommands {
			if strings.HasPrefix(cmd, "upgrade:") {
				targetVersion := strings.TrimPrefix(cmd, "upgrade:")
				if targetVersion == "" || targetVersion == buildinfo.Version {
					continue
				}
				log.Printf("upgrade command received: target_version=%s current_version=%s", targetVersion, buildinfo.Version)
				if err := upgrade.Perform(ctx, targetVersion); err != nil {
					log.Printf("upgrade failed (will retry on next heartbeat): %v", err)
				}
				continue
			}

			if strings.HasPrefix(cmd, "yara-rollout:") {
				parts := strings.SplitN(strings.TrimPrefix(cmd, "yara-rollout:"), ":", 2)
				commandPolicyID := ""
				commandBundleVersion := ""
				if len(parts) >= 1 {
					commandPolicyID = strings.TrimSpace(parts[0])
				}
				if len(parts) == 2 {
					commandBundleVersion = strings.TrimSpace(parts[1])
				}
				// Accept commands for this agent's enrolled policy OR for the
				// global-default YARA bundle policy (used by xdr-defense for all agents).
				if commandPolicyID != "" && commandPolicyID != cfg.PolicyID && commandPolicyID != "global-default" {
					continue
				}
				log.Printf("YARA rollout command received: policy_id=%s bundle_version=%s", cfg.PolicyID, commandBundleVersion)
				if syncYaraBundle != nil && syncYaraBundle(true) && detectionEngine != nil {
					detectionEngine.ReloadMalwareRules()
				}
			}
		}
	}

	if once {
		return enrollAttempt()
	}

	if !state.Enrolled {
		if err := enrollAttempt(); err != nil {
			log.Printf("initial enrollment failed: %v", err)
		}
	}

	yaraMetadataPath := "/etc/xdr-agent/state/yara-bundle-metadata.json"
	hashesMetadataPath := "/etc/xdr-agent/state/hashes-bundle-metadata.json"
	hashesOverlayMetadataPath := "/etc/xdr-agent/state/hashes-custom-overlay-metadata.json"
	behavioralMetadataPath := "/etc/xdr-agent/state/behavioral-bundle-metadata.json"

	yaraState := loadInitialBundleState("yara", yaraMetadataPath)
	hashesState := loadInitialBundleState("hashes", hashesMetadataPath)
	hashesOverlayState := loadInitialHashesOverlayBundleState("hashes_overlay", hashesOverlayMetadataPath)
	behavioralState := loadInitialBundleState("behavioral", behavioralMetadataPath)
	postureStatus := "active"
	if postureState.Version == 0 {
		postureStatus = "unknown"
	}

	logHeartbeatContentSummary := func() {
		log.Printf("heartbeat content summary: posture=%s yara=%s hashes=%s hashes_overlay=%s behavioral=%s", postureStatus, yaraState.summaryLabel(), hashesState.summaryLabel(), hashesOverlayState.summaryLabel(), behavioralState.summaryLabel())
	}

	syncDefensePosture := func() bool {
		fetchedPosture, postureErr := controlPlaneClient.FetchDefensePosture(ctx, cfg.PolicyID)
		if postureErr != nil {
			var fetchErr *controlplane.DefensePostureFetchError
			if errors.As(postureErr, &fetchErr) && fetchErr.StatusCode == 404 {
				if postureStatus != "optional-404" {
					log.Printf("Defense Posture endpoint not configured (status=404); posture sync is optional and will stay quiet until status changes")
				}
				postureStatus = "optional-404"
				return false
			}
			postureStatus = "error"
			log.Printf("warning: Defense Posture fetch failed: %v", postureErr)
			return false
		}

		if postureStatus != "active" && postureStatus != "unknown" {
			log.Printf("Defense Posture endpoint is available again")
		}
		postureStatus = "active"

		if !controlplane.ShouldApplyDefensePosture(postureState, fetchedPosture) {
			return false
		}

		controlplane.ApplyDefensePosture(&cfg, fetchedPosture)
		if err := controlplane.SaveDefensePosture(cfg.DefensePosturePath, fetchedPosture); err != nil {
			log.Printf("warning: failed to persist Defense Posture: %v", err)
		}

		postureState = fetchedPosture
		log.Printf("Defense Posture updated: policy_id=%s version=%d mode=%s", fetchedPosture.PolicyID, fetchedPosture.Version, fetchedPosture.Mode)

		ackErr := controlPlaneClient.AckDefensePosture(ctx, cfg.DefensePostureAckPath, controlplane.DefensePostureAckRequest{
			AgentID:        state.AgentID,
			PolicyID:       cfg.PolicyID,
			PostureVersion: fetchedPosture.Version,
			Hostname:       state.Hostname,
		})
		if ackErr != nil {
			log.Printf("warning: Defense Posture ACK failed: %v", ackErr)
			return true
		}
		log.Printf("Defense Posture ACK sent: policy_id=%s version=%d", cfg.PolicyID, fetchedPosture.Version)
		return true
	}

	resolveBundleVerificationKey := func(bundleType string) (string, error) {
		keyResp, err := controlPlaneClient.FetchSigningPublicKey(ctx)
		if err == nil {
			return keyResp.PublicKeyB64, nil
		}

		log.Printf("warning: failed to fetch signing public key from control plane for %s bundle: %v", bundleType, err)

		publicKeyB64, fallbackErr := controlplane.GetPublicKeyForPolicy(cfg.PolicyID)
		if fallbackErr != nil {
			return "", fallbackErr
		}

		return publicKeyB64, nil
	}

	// Sync YARA rules bundle from xdr-defense with per-rule tracking.
	syncYaraBundle = func(forceApply bool) bool {
		if !cfg.DetectionPrevention.Capabilities.Malware.YaraDetection {
			yaraState.lastOutcome = "disabled"
			return false
		}

		// YARA bundles are always built for the global-default policy in xdr-defense.
		// Fetch from global-default regardless of the agent's enrolled policy ID so
		// all agents receive the same global YARA ruleset.
		bundle, err := controlPlaneClient.FetchSignedYaraBundle(ctx, "global-default")
		if err != nil {
			yaraState.lastOutcome = "fetch_error"
			log.Printf("warning: failed to fetch YARA bundle: %v", err)
			return false
		}

		digest := bundleDigest(bundle)
		if !forceApply && shouldSkipApply(yaraState, bundle, digest) {
			yaraState.lastSkippedDuplicate++
			yaraState.lastOutcome = "unchanged"
			return false
		}

		publicKeyB64, err := resolveBundleVerificationKey("yara")
		if err != nil {
			yaraState.lastOutcome = "key_error"
			log.Printf("warning: failed to resolve signing public key: %v", err)
			return false
		}

		failedRulesMap, activateErr := controlplane.ActivateBundleWithTracking(bundle, publicKeyB64, cfg.Rules.YaraDir, yaraMetadataPath)
		activationState := "acked"
		loadedCount := 0
		failedRulesList := make([]controlplane.RuleActivationStatus, 0)
		for _, status := range failedRulesMap {
			if status.Status == "loaded" {
				loadedCount++
			}
			if status.Status == "failed" {
				failedRulesList = append(failedRulesList, status)
			}
		}

		if activateErr != nil {
			activationState = "failed"
		} else if len(failedRulesList) > 0 {
			activationState = "partial"
		} else if len(bundle.Rules) > 0 {
			loadedCount = len(bundle.Rules)
		}

		if activateErr != nil {
			yaraState.lastOutcome = "failed"
			failureSignature := fmt.Sprintf("bundle=%d digest=%s reason=%s", bundle.BundleVersion, digest, activateErr.Error())
			if failureSignature != yaraState.lastFailureSignature {
				yaraState.lastFailureSignature = failureSignature
				yaraState.lastFailureCount = 1
				log.Printf("warning: failed to activate YARA bundle: %v", activateErr)
			} else {
				yaraState.lastFailureCount++
				if yaraState.lastFailureCount%10 == 0 {
					log.Printf("warning: repeated YARA activation failure suppressed: bundle_version=%d repeats=%d reason=%v", bundle.BundleVersion, yaraState.lastFailureCount-1, activateErr)
				}
			}
			return false
		}

		yaraState.lastFailureSignature = ""
		yaraState.lastFailureCount = 0

		mpID := bundle.ManagerPolicyID
		if mpID == "" {
			mpID = bundle.PolicyID
		}
		statusReport := &controlplane.YaraRolloutStatusReport{
			ManagerPolicyID: mpID,
			AgentID:         state.AgentID,
			AgentHostname:   state.Hostname,
			State:           activationState,
			BundleVersion:   bundle.BundleVersion,
			TotalRules:      len(bundle.Rules),
			LoadedRules:     loadedCount,
			FailedRules:     failedRulesList,
			ReportedAt:      time.Now().Unix(),
		}
		if reportErr := controlPlaneClient.ReportYaraRuleStatus(ctx, cfg.YaraRuleStatusPath, statusReport); reportErr != nil {
			log.Printf("warning: failed to report YARA rule status: %v", reportErr)
		}

		yaraState.lastAppliedVersion = bundle.BundleVersion
		yaraState.lastAppliedDigest = digest
		yaraState.lastAppliedCount = loadedCount
		yaraState.lastAppliedChecksums = append([]string(nil), bundle.ActiveChecksums...)
		sort.Strings(yaraState.lastAppliedChecksums)
		yaraState.lastAppliedSource = "runtime"
		yaraState.lastOutcome = activationState
		log.Printf("YARA bundle activated: policy_id=%s bundle_version=%d total_rules=%d loaded_rules=%d failed_rules=%d", bundle.PolicyID, bundle.BundleVersion, len(bundle.Rules), loadedCount, len(failedRulesList))

		state.LoadedRuleCount = loadedCount
		if err := identity.Save(cfg.StatePath, state); err != nil {
			log.Printf("warning: failed to save agent state with loaded rule count: %v", err)
		}

		return true
	}

	// Sync signed hash content bundle from xdr-defense.
	syncHashesBundle := func() (bool, int, string) {
		if !cfg.DetectionPrevention.Capabilities.Malware.HashDetection {
			hashesState.lastOutcome = "disabled"
			return false, hashesState.lastAppliedVersion, ""
		}

		bundle, err := controlPlaneClient.FetchSignedHashesBundle(ctx, cfg.PolicyID)
		if err != nil {
			hashesState.lastOutcome = "fetch_error"
			log.Printf("warning: failed to fetch hashes bundle: %v", err)
			return false, hashesState.lastAppliedVersion, err.Error()
		}
		bundleVersion := bundle.BundleVersion

		digest := bundleDigest(bundle)
		if shouldSkipApply(hashesState, bundle, digest) {
			hashesState.lastSkippedDuplicate++
			hashesState.lastOutcome = "unchanged"
			return false, bundleVersion, ""
		}

		publicKeyB64, err := resolveBundleVerificationKey("hashes")
		if err != nil {
			hashesState.lastOutcome = "key_error"
			log.Printf("warning: failed to resolve signing public key for hashes bundle: %v", err)
			return false, bundleVersion, err.Error()
		}

		if err := controlplane.ActivateSignedContentBundle(bundle, publicKeyB64, cfg.Rules.HashesFile, hashesMetadataPath); err != nil {
			hashesState.lastOutcome = "failed"
			log.Printf("warning: failed to activate hashes bundle: %v", err)
			return false, bundleVersion, err.Error()
		}

		hashesState.lastAppliedVersion = bundle.BundleVersion
		hashesState.lastAppliedDigest = digest
		hashesState.lastAppliedCount = len(bundle.Rules)
		hashesState.lastAppliedChecksums = append([]string(nil), bundle.ActiveChecksums...)
		sort.Strings(hashesState.lastAppliedChecksums)
		hashesState.lastAppliedSource = "runtime"
		hashesState.lastOutcome = "active"
		log.Printf("hashes bundle activated: policy_id=%s bundle_version=%d entries=%d", bundle.PolicyID, bundle.BundleVersion, len(bundle.Rules))
		return true, bundleVersion, ""
	}

	syncHashesOverlayBundle := func(forceApply bool) (bool, int, string) {
		if !cfg.DetectionPrevention.Capabilities.Malware.HashDetection {
			hashesOverlayState.lastOutcome = "disabled"
			return false, hashesOverlayState.lastAppliedVersion, ""
		}

		bundle, err := controlPlaneClient.FetchSignedHashesCustomOverlayBundle(ctx, cfg.PolicyID)
		if err != nil {
			hashesOverlayState.lastOutcome = "fetch_error"
			log.Printf("warning: failed to fetch hashes custom overlay bundle: %v", err)
			return false, hashesOverlayState.lastAppliedVersion, err.Error()
		}
		bundleVersion := bundle.BundleVersion

		digest := bundleDigest(bundle)
		if !forceApply && shouldSkipApply(hashesOverlayState, bundle, digest) {
			hashesOverlayState.lastSkippedDuplicate++
			hashesOverlayState.lastOutcome = "unchanged"
			return false, bundleVersion, ""
		}

		publicKeyB64, err := resolveBundleVerificationKey("hashes custom overlay")
		if err != nil {
			hashesOverlayState.lastOutcome = "key_error"
			log.Printf("warning: failed to resolve signing public key for hashes custom overlay bundle: %v", err)
			return false, bundleVersion, err.Error()
		}

		if err := controlplane.ActivateSignedHashesOverlayBundle(bundle, publicKeyB64, cfg.Rules.HashesFile, hashesOverlayMetadataPath); err != nil {
			hashesOverlayState.lastOutcome = "failed"
			log.Printf("warning: failed to activate hashes custom overlay bundle: %v", err)
			return false, bundleVersion, err.Error()
		}

		hashesOverlayState.lastAppliedVersion = bundle.BundleVersion
		hashesOverlayState.lastAppliedDigest = digest
		hashesOverlayState.lastAppliedCount = len(bundle.Rules)
		hashesOverlayState.lastAppliedChecksums = append([]string(nil), bundle.ActiveChecksums...)
		sort.Strings(hashesOverlayState.lastAppliedChecksums)
		hashesOverlayState.lastAppliedSource = "runtime"
		hashesOverlayState.lastOutcome = "active"
		log.Printf("hashes custom overlay bundle activated: policy_id=%s bundle_version=%d entries=%d force_apply=%t", bundle.PolicyID, bundle.BundleVersion, len(bundle.Rules), forceApply)
		return true, bundleVersion, ""
	}

	reportHashesRolloutStatus := func(fullBundleVersion, customBundleVersion int, fullErr, customErr string) {
		stateName := "active"
		switch {
		case hashesState.lastOutcome == "disabled" || hashesOverlayState.lastOutcome == "disabled":
			stateName = "disabled"
		case hashesState.lastOutcome == "fetch_error" || hashesOverlayState.lastOutcome == "fetch_error":
			stateName = "fetch_error"
		case hashesState.lastOutcome == "key_error" || hashesOverlayState.lastOutcome == "key_error":
			stateName = "key_error"
		case hashesState.lastOutcome == "failed" || hashesOverlayState.lastOutcome == "failed":
			stateName = "failed"
		case hashesState.lastOutcome == "unchanged" && hashesOverlayState.lastOutcome == "unchanged":
			stateName = "unchanged"
		case hashesState.lastOutcome == "active" || hashesOverlayState.lastOutcome == "active":
			stateName = "active"
		}

		errorText := ""
		if fullErr != "" && customErr != "" {
			errorText = "full: " + fullErr + "; custom: " + customErr
		} else if fullErr != "" {
			errorText = fullErr
		} else if customErr != "" {
			errorText = customErr
		}

		report := &controlplane.HashesRolloutStatusReport{
			AgentID:             state.AgentID,
			AgentHostname:       state.Hostname,
			PolicyID:            cfg.PolicyID,
			State:               stateName,
			FullBundleVersion:   fullBundleVersion,
			CustomBundleVersion: customBundleVersion,
			ReportedAt:          time.Now().Unix(),
			Error:               errorText,
		}
		if err := controlPlaneClient.ReportHashesRolloutStatus(ctx, report); err != nil {
			log.Printf("warning: failed to report hashes rollout status: %v", err)
		}
	}

	syncHashesContent := func() bool {
		fullChanged, fullBundleVersion, fullErr := syncHashesBundle()
		overlayChanged, customBundleVersion, customErr := syncHashesOverlayBundle(fullChanged)
		reportHashesRolloutStatus(fullBundleVersion, customBundleVersion, fullErr, customErr)
		return fullChanged || overlayChanged
	}

	// Sync signed behavioral rules bundle from xdr-defense.
	syncBehavioralBundle := func() bool {
		if !cfg.DetectionPrevention.Capabilities.Behavioral.Rules {
			behavioralState.lastOutcome = "disabled"
			return false
		}

		bundle, err := controlPlaneClient.FetchSignedBehavioralBundle(ctx, cfg.PolicyID)
		if err != nil {
			behavioralState.lastOutcome = "fetch_error"
			log.Printf("warning: failed to fetch behavioral bundle: %v", err)
			return false
		}

		digest := bundleDigest(bundle)
		if shouldSkipApply(behavioralState, bundle, digest) {
			behavioralState.lastSkippedDuplicate++
			behavioralState.lastOutcome = "unchanged"
			return false
		}

		publicKeyB64, err := resolveBundleVerificationKey("behavioral")
		if err != nil {
			behavioralState.lastOutcome = "key_error"
			log.Printf("warning: failed to resolve signing public key for behavioral bundle: %v", err)
			return false
		}

		if err := controlplane.ActivateSignedContentBundle(bundle, publicKeyB64, cfg.Rules.BehavioralDir, behavioralMetadataPath); err != nil {
			behavioralState.lastOutcome = "failed"
			log.Printf("warning: failed to activate behavioral bundle: %v", err)
			return false
		}

		behavioralState.lastAppliedVersion = bundle.BundleVersion
		behavioralState.lastAppliedDigest = digest
		behavioralState.lastAppliedCount = len(bundle.Rules)
		behavioralState.lastAppliedChecksums = append([]string(nil), bundle.ActiveChecksums...)
		sort.Strings(behavioralState.lastAppliedChecksums)
		behavioralState.lastAppliedSource = "runtime"
		behavioralState.lastOutcome = "active"
		log.Printf("behavioral bundle activated: policy_id=%s bundle_version=%d entries=%d", bundle.PolicyID, bundle.BundleVersion, len(bundle.Rules))
		return true
	}

	enrollTicker := time.NewTicker(cfg.EnrollInterval())
	defer enrollTicker.Stop()

	heartbeatTicker := time.NewTicker(cfg.HeartbeatInterval())
	defer heartbeatTicker.Stop()

	// commandPollTicker fires more frequently than heartbeatTicker so that
	// urgent commands (e.g. upgrades) are delivered within seconds rather
	// than waiting for the next full heartbeat cycle.
	commandPollTicker := time.NewTicker(cfg.CommandPollInterval())
	defer commandPollTicker.Stop()

	defensePostureTicker := time.NewTicker(cfg.DefensePosturePollInterval())
	defer defensePostureTicker.Stop()

	// Hash and behavioral bundles continue to poll on the existing cadence.
	hashesBundleTicker := time.NewTicker(cfg.YaraBundleSyncInterval())
	defer hashesBundleTicker.Stop()
	behavioralBundleTicker := time.NewTicker(cfg.YaraBundleSyncInterval())
	defer behavioralBundleTicker.Stop()

	for {
		if state.Enrolled {
			break
		}

		select {
		case <-ctx.Done():
			log.Printf("xdr-agent stopping")
			return ctx.Err()
		case <-enrollTicker.C:
			if err := enrollAttempt(); err != nil {
				log.Printf("enrollment attempt failed: %v", err)
			}
		}
	}

	if hbResp, err := heartbeatAttempt(); err != nil {
		log.Printf("initial heartbeat failed: %v", err)
	} else {
		handleHeartbeatCommands(hbResp)
	}

	_ = syncDefensePosture()

	// ── Event pipeline ──────────────────────────────────────────────────
	pipeline := events.NewPipeline(4096)
	telemetryPipeline := events.NewPipeline(4096)
	securityPipeline := events.NewPipeline(2048)
	logPipeline := events.NewPipeline(1024)

	pipeline.Subscribe(func(event events.Event) {
		if isSecurityClassifiedEvent(event) {
			securityPipeline.Emit(event)
			return
		}
		telemetryPipeline.Emit(event)
	})

	// ── Telemetry shipper ──────────────────────────────────────────────
	shipper := controlplane.NewShipper(controlplane.ShipperConfig{
		TelemetryURL:    cfg.TelemetryBaseURL(),
		TelemetryPath:   cfg.TelemetryEndpointPath(),
		AgentID:         state.AgentID,
		Interval:        cfg.TelemetryShipInterval(),
		BatchSize:       500,
		RequestTimeout:  cfg.RequestTimeout(),
		InsecureSkipTLS: cfg.InsecureSkipTLSVerify,
	})
	telemetryPipeline.Subscribe(shipper.Enqueue)

	securityShipper := controlplane.NewShipper(controlplane.ShipperConfig{
		TelemetryURL:    cfg.SecurityBaseURL(),
		TelemetryPath:   cfg.SecurityEndpointPath(),
		AgentID:         state.AgentID,
		Interval:        cfg.SecurityShipInterval(),
		BatchSize:       500,
		RequestTimeout:  cfg.RequestTimeout(),
		InsecureSkipTLS: cfg.InsecureSkipTLSVerify,
	})
	securityPipeline.Subscribe(securityShipper.Enqueue)

	logShipper := controlplane.NewShipper(controlplane.ShipperConfig{
		TelemetryURL:    cfg.LogsBaseURL(),
		TelemetryPath:   cfg.LogsEndpointPath(),
		AgentID:         state.AgentID,
		Interval:        cfg.LogsShipInterval(),
		BatchSize:       300,
		RequestTimeout:  cfg.RequestTimeout(),
		InsecureSkipTLS: cfg.InsecureSkipTLSVerify,
	})
	logPipeline.Subscribe(logShipper.Enqueue)

	agentLogger := agentlog.New(cfg.Logging.Level, state.AgentID, state.Hostname, logPipeline)

	go pipeline.Run(ctx)
	go telemetryPipeline.Run(ctx)
	go securityPipeline.Run(ctx)
	go shipper.Run(ctx)
	go securityShipper.Run(ctx)
	go logPipeline.Run(ctx)
	if cfg.Logging.Ship.Enabled {
		go logShipper.Run(ctx)
	}
	log.Printf("event pipeline and shipper started")
	agentLogger.Info("service", "detection/prevention runtime enabled", map[string]interface{}{
		"mode": cfg.DetectionPrevention.Mode,
	})

	detectionEngine, err = detection.NewEngine(cfg, pipeline)
	if err != nil {
		log.Printf("detection engine init failed: %v", err)
		agentLogger.Error("detection", "detection engine initialization failed", map[string]interface{}{"error": err.Error()})
	} else {
		detectionEngine.Start(ctx)
		agentLogger.Info("detection", "detection engine started", nil)
	}

	preventionManager := prevention.NewManager(cfg, pipeline)
	pipeline.Subscribe(preventionManager.Handle)
	agentLogger.Info("prevention", "prevention manager registered", map[string]interface{}{
		"enabled": cfg.DetectionPrevention.Capabilities.Prevention.Enabled,
	})

	if syncHashesContent() && detectionEngine != nil {
		detectionEngine.ReloadMalwareRules()
	}
	if syncBehavioralBundle() && detectionEngine != nil {
		detectionEngine.ReloadBehavioralRules()
	}

	// ── Telemetry collectors ────────────────────────────────────────────

	// Combined system metrics (memory + CPU in a single document)
	sysCollector := system.NewSystemCollector(pipeline, state.AgentID, state.Hostname, cfg.TelemetryInterval())
	if err := sysCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("system collector init failed: %v", err)
	} else if err := sysCollector.Start(ctx); err != nil {
		log.Printf("system collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", sysCollector.Name())
	}

	// Process monitoring (procfs polling)
	procCollector := process.NewProcessCollector(pipeline, state.AgentID, state.Hostname, cfg.TelemetryInterval())
	if err := procCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("process collector init failed: %v", err)
	} else if err := procCollector.Start(ctx); err != nil {
		log.Printf("process collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", procCollector.Name())
	}

	// Network connection tracking
	netCollector := network.NewNetworkCollector(pipeline, state.AgentID, state.Hostname, cfg.TelemetryInterval())
	if err := netCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("network collector init failed: %v", err)
	} else if err := netCollector.Start(ctx); err != nil {
		log.Printf("network collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", netCollector.Name())
	}

	// File Integrity Monitoring (inotify + SHA-256 rescan; uses default critical paths and BoltDB)
	fimCollector := file.NewFIMCollector(pipeline, state.AgentID, state.Hostname, nil, 0, "")
	if err := fimCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("fim collector init failed: %v", err)
	} else if err := fimCollector.Start(ctx); err != nil {
		log.Printf("fim collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", fimCollector.Name())
	}

	// DNS query/response monitoring (raw AF_PACKET socket; requires CAP_NET_RAW)
	dnsCollector := network.NewDNSCollector(pipeline, state.AgentID, state.Hostname)
	if err := dnsCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("dns collector init failed: %v", err)
	} else if err := dnsCollector.Start(ctx); err != nil {
		log.Printf("dns collector start failed (degraded — CAP_NET_RAW required): %v", err)
	} else {
		log.Printf("capability started: %s", dnsCollector.Name())
	}

	// User / session monitoring (utmp polling + auth log tailing)
	sessionCollector := session.NewSessionCollector(pipeline, state.AgentID, state.Hostname, 0)
	if err := sessionCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("session collector init failed: %v", err)
	} else if err := sessionCollector.Start(ctx); err != nil {
		log.Printf("session collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", sessionCollector.Name())
	}

	// ── Phase 2b: Critical gap telemetry ───────────────────────────────────────

	// Shared library / SO loading monitor (LD_PRELOAD, library hijacking)
	soCollector := library.NewSOCollector(pipeline, state.AgentID, state.Hostname, nil, 0)
	if err := soCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("library collector init failed: %v", err)
	} else if err := soCollector.Start(ctx); err != nil {
		log.Printf("library collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", soCollector.Name())
	}

	// Kernel module load/unload monitor (rootkit / LKRG detection)
	moduleCollector := kernel.NewModuleCollector(pipeline, state.AgentID, state.Hostname, 0)
	if err := moduleCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("kernel module collector init failed: %v", err)
	} else if err := moduleCollector.Start(ctx); err != nil {
		log.Printf("kernel module collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", moduleCollector.Name())
	}

	// TTY / terminal session monitor (interactive shell detection)
	ttyCollector := tty.NewTTYCollector(pipeline, state.AgentID, state.Hostname, 0)
	if err := ttyCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("tty collector init failed: %v", err)
	} else if err := ttyCollector.Start(ctx); err != nil {
		log.Printf("tty collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", ttyCollector.Name())
	}

	// Scheduled task / cron monitor (persistence via cron / systemd timers)
	schedCollector := scheduled.NewScheduledTaskCollector(pipeline, state.AgentID, state.Hostname, 0)
	if err := schedCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("scheduled collector init failed: %v", err)
	} else if err := schedCollector.Start(ctx); err != nil {
		log.Printf("scheduled collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", schedCollector.Name())
	}

	// Process injection monitor (ptrace attach + anonymous exec regions)
	injectionCollector := injection.NewInjectionCollector(pipeline, state.AgentID, state.Hostname, 0)
	if err := injectionCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("injection collector init failed: %v", err)
	} else if err := injectionCollector.Start(ctx); err != nil {
		log.Printf("injection collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", injectionCollector.Name())
	}

	// ── Phase 2c: High-value telemetry gap closure ────────────────────────────
	// NOTE: Environment variable capture and script content capture are integrated
	// directly into the process collector and require no separate registration.

	// File access monitor (credential harvesting detection: /etc/shadow, SSH keys)
	fileAccessCollector := file.NewFileAccessCollector(pipeline, state.AgentID, state.Hostname, nil)
	if err := fileAccessCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("file access collector init failed: %v", err)
	} else if err := fileAccessCollector.Start(ctx); err != nil {
		log.Printf("file access collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", fileAccessCollector.Name())
	}

	// IPC monitor (Unix domain sockets + named pipes)
	ipcCollector := ipc.NewIPCCollector(pipeline, state.AgentID, state.Hostname, nil, 0)
	if err := ipcCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("ipc collector init failed: %v", err)
	} else if err := ipcCollector.Start(ctx); err != nil {
		log.Printf("ipc collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", ipcCollector.Name())
	}

	for {
		select {
		case <-ctx.Done(): // If the context is canceled (e.g., on SIGTERM), log shutdown and exit.
			log.Printf("xdr-agent stopping")
			return ctx.Err()
		case <-heartbeatTicker.C: // On each tick, send heartbeat.
			if hbResp, err := heartbeatAttempt(); err != nil {
				log.Printf("heartbeat failed: %v", err)
			} else {
				handleHeartbeatCommands(hbResp)
				if syncHashesContent() && detectionEngine != nil {
					detectionEngine.ReloadMalwareRules()
				}
				logHeartbeatContentSummary()
			}
		case <-commandPollTicker.C: // Fast command poll — delivers upgrades within seconds.
			cmdResp, err := enroll.PollCommands(ctx, cfg, state, buildinfo.Version)
			if err != nil {
				log.Printf("command poll failed: %v", err)
			} else if len(cmdResp.PendingCommands) > 0 {
				handleHeartbeatCommands(cmdResp)
			}
		case <-defensePostureTicker.C:
			if syncDefensePosture() {
				if detectionEngine != nil {
					detectionEngine.UpdateDefensePosture(cfg.DetectionPrevention)
				}
				preventionManager.UpdateDefensePosture(cfg.DetectionPrevention)
			}
		case <-hashesBundleTicker.C:
			// Pick up updated hash bundles after MalwareBazaar sync completes.
			// The server endpoint now serves the cached snapshot (no index scan per
			// request), so this is cheap when the bundle version hasn't changed.
			if syncHashesContent() && detectionEngine != nil {
				detectionEngine.ReloadMalwareRules()
			}
		case <-behavioralBundleTicker.C:
			if syncBehavioralBundle() && detectionEngine != nil {
				detectionEngine.ReloadBehavioralRules()
			}
		}
	}
}

func isSecurityClassifiedEvent(event events.Event) bool {
	// Injection collector emits alert/intrusion_detection semantics for telemetry dashboards,
	// so keep telemetry.injection events on the telemetry topic.
	if event.Module == "telemetry.injection" {
		return false
	}

	if event.Kind == "alert" || event.Category == "intrusion_detection" {
		return true
	}

	for _, prefix := range []string{"detection.", "prevention.", "response."} {
		if strings.HasPrefix(event.Module, prefix) {
			return true
		}
	}

	return false
}
