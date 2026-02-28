package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"xdr-agent/internal/buildinfo"
	"xdr-agent/internal/capability"
	"xdr-agent/internal/config"
	"xdr-agent/internal/controlplane"
	"xdr-agent/internal/enroll"
	"xdr-agent/internal/events"
	"xdr-agent/internal/identity"
	"xdr-agent/internal/telemetry/network"
	"xdr-agent/internal/telemetry/process"
	"xdr-agent/internal/telemetry/system"
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

	heartbeatAttempt := func() error {
		if err := enroll.Heartbeat(ctx, cfg, state, buildinfo.Version); err != nil {
			return err
		}

		log.Printf("heartbeat successful: agent_id=%s", state.AgentID)
		return nil
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

	if err := heartbeatAttempt(); err != nil {
		log.Printf("initial heartbeat failed: %v", err)
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

	// Memory (system metrics)
	memCollector := system.NewMemoryCollector(pipeline, state.AgentID, state.Hostname, cfg.TelemetryInterval())
	if err := memCollector.Init(capability.Dependencies{}); err != nil {
		log.Printf("memory collector init failed: %v", err)
	} else if err := memCollector.Start(ctx); err != nil {
		log.Printf("memory collector start failed: %v", err)
	} else {
		log.Printf("capability started: %s", memCollector.Name())
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

	for {
		select {
		case <-ctx.Done(): // If the context is canceled (e.g., on SIGTERM), log shutdown and exit.
			log.Printf("xdr-agent stopping")
			return ctx.Err()
		case <-heartbeatTicker.C: // On each tick, send heartbeat.
			if err := heartbeatAttempt(); err != nil {
				log.Printf("heartbeat failed: %v", err)
			}
		}
	}
}
