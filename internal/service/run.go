package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"xdr-agent/internal/buildinfo"
	"xdr-agent/internal/capability"
	"xdr-agent/internal/config"
	"xdr-agent/internal/controlplane"
	"xdr-agent/internal/enroll"
	"xdr-agent/internal/events"
	"xdr-agent/internal/identity"
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

	// Ensure identity State from 'state_path' is initialized and load current state
	state, err := identity.Ensure(cfg.StatePath)
	if err != nil {
		return fmt.Errorf("initialize identity state: %w", err)
	}

	log.Printf("xdr-agent starting: agent_id=%s machine_id=%s hostname=%s", state.AgentID, state.MachineID, state.Hostname)

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

	enrollTicker := time.NewTicker(cfg.EnrollInterval())
	defer enrollTicker.Stop()

	heartbeatTicker := time.NewTicker(cfg.HeartbeatInterval())
	defer heartbeatTicker.Stop()

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

	// ── Event pipeline ──────────────────────────────────────────────────
	pipeline := events.NewPipeline(4096)

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
	pipeline.Subscribe(shipper.Enqueue)

	go pipeline.Run(ctx)
	go shipper.Run(ctx)
	log.Printf("event pipeline and shipper started")

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
		}
	}
}
