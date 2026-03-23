package service

import (
	"context"
	"fmt"
	"log"
	"os"
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
				// If upgrade succeeded, systemd will restart us. If it failed,
				// we continue running and will retry on the next heartbeat cycle.
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

	syncDefensePosture := func() bool {
		fetchedPosture, postureErr := controlPlaneClient.FetchDefensePosture(ctx, cfg.PolicyID)
		if postureErr != nil {
			log.Printf("warning: Defense Posture fetch failed: %v", postureErr)
			return false
		}

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

	// Sync YARA rules bundle from xdr-defense with per-rule tracking.
	syncYaraBundle := func() bool {
		// Only fetch if YARA detection is enabled
		if !cfg.DetectionPrevention.Capabilities.Malware.YaraDetection {
			return false
		}

		bundle, err := controlPlaneClient.FetchSignedYaraBundle(ctx, cfg.PolicyID)
		if err != nil {
			log.Printf("warning: failed to fetch YARA bundle: %v", err)
			return false
		}

		// Get public key for signature verification
		publicKeyB64, err := controlplane.GetPublicKeyForPolicy(cfg.PolicyID)
		if err != nil {
			log.Printf("warning: failed to get signing public key: %v", err)
			return false
		}

		// Activate bundle with per-rule tracking
		rulesDir := "/etc/xdr-agent/rules/malware/yara"
		metadataPath := "/etc/xdr-agent/state/yara-bundle-metadata.json"
		failedRulesMap, activateErr := controlplane.ActivateBundleWithTracking(bundle, publicKeyB64, rulesDir, metadataPath)

		// Determine overall state: "acked" (all loaded) | "partial" (some failed) | "failed" (activation error)
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
			// Backward safety: if activation succeeded but status map is unexpectedly empty,
			// treat all bundle rules as loaded.
			loadedCount = len(bundle.Rules)
		}

		// Report per-rule status to control plane
		mpID := bundle.ManagerPolicyID
		if mpID == "" {
			mpID = bundle.PolicyID
		}

		statusReport := &controlplane.YaraRolloutStatusReport{
			ManagerPolicyID: mpID,
			AgentID:         state.AgentID,
			State:           activationState,
			TotalRules:      len(bundle.Rules),
			LoadedRules:     loadedCount,
			FailedRules:     failedRulesList,
			ReportedAt:      time.Now().Unix(),
		}

		if reportErr := controlPlaneClient.ReportYaraRuleStatus(ctx, cfg.YaraRuleStatusPath, statusReport); reportErr != nil {
			log.Printf("warning: failed to report YARA rule status: %v", reportErr)
		} else {
			log.Printf("YARA rule status reported: state=%s loaded=%d failed=%d", activationState, loadedCount, len(failedRulesList))
		}

		if activateErr != nil {
			log.Printf("warning: failed to activate YARA bundle: %v", activateErr)
			return false
		}

		log.Printf("YARA bundle activated: policy_id=%s bundle_version=%d total_rules=%d loaded_rules=%d", bundle.PolicyID, bundle.BundleVersion, len(bundle.Rules), loadedCount)

		// Update agent state with loaded rule count
		state.LoadedRuleCount = loadedCount
		if err := identity.Save(cfg.StatePath, state); err != nil {
			log.Printf("warning: failed to save agent state with loaded rule count: %v", err)
		}

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

	yaraBundleTicker := time.NewTicker(cfg.YaraBundleSyncInterval())
	defer yaraBundleTicker.Stop()

	yaraInventoryTicker := time.NewTicker(cfg.YaraInventoryCheckInterval())
	defer yaraInventoryTicker.Stop()

	// Periodic rule inventory check to detect degradation
	reportRuleInventory := func() bool {
		// Only report if YARA detection is enabled
		if !cfg.DetectionPrevention.Capabilities.Malware.YaraDetection {
			return false
		}

		rulesDir := "/etc/xdr-agent/rules/malware/yara"
		entries, err := os.ReadDir(rulesDir)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("warning: failed to check rule inventory: %v", err)
			return false
		}

		// Count actual rule files
		ruleCount := 0
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yar") {
				ruleCount++
			}
		}

		inventory := &controlplane.PeriodicRuleInventory{
			AgentID:         state.AgentID,
			LoadedRuleCount: ruleCount,
			FailedRules:     []controlplane.RuleActivationStatus{},
			CheckedAt:       time.Now().Unix(),
		}

		// Report inventory (non-fatal on error)
		if reportErr := controlPlaneClient.ReportRuleInventory(ctx, cfg.YaraRuleInventoryPath, inventory); reportErr != nil {
			log.Printf("warning: failed to report rule inventory: %v", reportErr)
		} else {
			log.Printf("rule inventory reported: count=%d", ruleCount)
			state.LastYaraInventoryAt = time.Now().UTC().Format(time.RFC3339)
			if err := identity.Save(cfg.StatePath, state); err != nil {
				log.Printf("warning: failed to save agent state after inventory report: %v", err)
			}
		}

		return true
	}

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

	detectionEngine, err := detection.NewEngine(cfg, pipeline)
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

	// Initial YARA sync on startup to avoid waiting for the first periodic tick.
	if syncYaraBundle() && detectionEngine != nil {
		detectionEngine.ReloadMalwareRules()
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
		case <-yaraBundleTicker.C:
			// Sync YARA rules frequently so delete/activate rollouts are applied quickly,
			// instead of waiting for the slower defense posture poll loop.
			if syncYaraBundle() && detectionEngine != nil {
				detectionEngine.ReloadMalwareRules()
			}
		case <-yaraInventoryTicker.C:
			reportRuleInventory()
		}
	}
}

func isSecurityClassifiedEvent(event events.Event) bool {
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
