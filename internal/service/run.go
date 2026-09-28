package service

import (
	"context"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"sync"
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
	"xdr-agent/internal/platform/linux"
	"xdr-agent/internal/prevention"
	"xdr-agent/internal/telemetry/file"
	"xdr-agent/internal/telemetry/network"
	"xdr-agent/internal/telemetry/process"
	"xdr-agent/internal/upgrade"
)

// Run starts local protection before contacting Coordinator. An outage must not
// stop collection or make the installed release depend on a remote rule service.
func Run(ctx context.Context, configPath string, once bool, enrollmentToken string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	limitedCPUs, err := linux.LimitCPUs(cfg.MaxCPUCores)
	if err != nil {
		return fmt.Errorf("apply max_cpu_cores: %w", err)
	}
	if limitedCPUs == 0 {
		log.Printf("CPU limit: all available logical CPUs")
	} else {
		log.Printf("CPU limit: %d logical CPU(s)", limitedCPUs)
	}
	if cfg.TelemetryIntervalSeconds > 0 && cfg.TelemetryIntervalSeconds < 5 {
		log.Printf("telemetry scan interval raised from %d to 5 seconds", cfg.TelemetryIntervalSeconds)
	}
	if enrollmentToken != "" {
		cfg.EnrollmentToken = strings.TrimSpace(enrollmentToken)
	}
	state, err := identity.Ensure(cfg.StatePath)
	if err != nil {
		return fmt.Errorf("initialize identity: %w", err)
	}
	if once {
		return enrollAgent(ctx, cfg, &state)
	}

	pipeline := events.NewPipeline(4096)
	newShipper := func(base, path string, interval time.Duration, logSuccess bool) *controlplane.Shipper {
		return controlplane.NewShipper(controlplane.ShipperConfig{
			TelemetryURL: base, TelemetryPath: path, AgentID: state.AgentID,
			EnrollmentToken: cfg.EnrollmentToken, Interval: interval, BatchSize: 500,
			RequestTimeout: cfg.RequestTimeout(), InsecureSkipTLS: cfg.InsecureSkipTLSVerify,
			LogSuccess: logSuccess,
		})
	}
	telemetry := newShipper(cfg.TelemetryBaseURL(), cfg.TelemetryEndpointPath(), cfg.TelemetryShipInterval(), true)
	security := newShipper(cfg.SecurityBaseURL(), cfg.SecurityEndpointPath(), cfg.SecurityShipInterval(), true)
	logs := newShipper(cfg.LogsBaseURL(), cfg.LogsEndpointPath(), cfg.LogsShipInterval(), false)
	shippers := []*controlplane.Shipper{telemetry, security}
	pipeline.Subscribe(func(event events.Event) {
		if event.AgentID == "" {
			event.AgentID = state.AgentID
		}
		if event.Hostname == "" {
			event.Hostname = state.Hostname
		}
		if isSecurityClassifiedEvent(event) {
			security.Enqueue(event)
		} else {
			telemetry.Enqueue(event)
		}
	})

	// Keep dispatch and shipping alive until producers stop and buffered events drain.
	pipelineCtx, stopPipeline := context.WithCancel(context.Background())
	pipelineDone := make(chan struct{})
	go func() { defer close(pipelineDone); pipeline.Run(pipelineCtx) }()
	shipCtx, stopShipping := context.WithCancel(context.Background())
	var shipping sync.WaitGroup
	var startShipping sync.Once
	var restoreLogs = func() {}
	if cfg.Logging.Ship.Enabled {
		shippers = append(shippers, logs)
		writer := agentlog.NewWriter(cfg.Logging.Level, state.AgentID, state.Hostname, logs.Enqueue)
		original := log.Writer()
		log.SetOutput(io.MultiWriter(original, writer))
		restoreLogs = func() { log.SetOutput(original); writer.Close() }
	}
	defer func() {
		stopPipeline()
		<-pipelineDone
		restoreLogs()
		stopShipping()
		shipping.Wait()
		// One shared deadline bounds shutdown even if Coordinator is unreachable.
		flushCtx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout())
		defer cancel()
		for _, shipper := range shippers {
			if err := shipper.Flush(flushCtx); err != nil {
				log.Printf("final shipper flush failed: %v", err)
			}
		}
	}()
	onEnrolled := func() {
		startShipping.Do(func() {
			for _, shipper := range shippers {
				shipping.Add(1)
				go func(s *controlplane.Shipper) { defer shipping.Done(); s.Run(shipCtx) }(shipper)
			}
		})
	}

	log.Print("initializing local protection")
	engine, err := detection.NewEngine(cfg, pipeline)
	if err != nil {
		return fmt.Errorf("initialize YARA protection: %w", err)
	}
	defer engine.Close()
	if err := engine.Start(ctx); err != nil {
		log.Printf("warning: execution protection degraded: %v", err)
	}
	manager := prevention.NewManager(cfg, pipeline)
	pipeline.Subscribe(manager.Handle)

	collectors := []capability.Capability{
		process.NewProcessCollector(pipeline, state.AgentID, state.Hostname, cfg.TelemetryInterval()),
		file.NewFIMCollector(pipeline, state.AgentID, state.Hostname, nil, 0, filepath.Join(filepath.Dir(cfg.StatePath), "fim_baseline.db")),
		file.NewFileAccessCollector(pipeline, state.AgentID, state.Hostname, nil),
		network.NewNetworkCollector(pipeline, state.AgentID, state.Hostname, cfg.TelemetryInterval()),
		network.NewDNSCollector(pipeline, state.AgentID, state.Hostname),
	}
	started := make([]capability.Capability, 0, len(collectors))
	failed := map[string]string{}
	for _, collector := range collectors {
		err := collector.Init(capability.Dependencies{})
		if err == nil {
			err = collector.Start(ctx)
		}
		if err != nil {
			failed[collector.Name()] = "failed"
			_ = collector.Stop()
			log.Printf("warning: %s unavailable: %v", collector.Name(), err)
			continue
		}
		started = append(started, collector)
	}
	defer func() {
		for i := len(started) - 1; i >= 0; i-- {
			_ = started[i].Stop()
		}
	}()
	log.Printf("xdr-agent started: agent_id=%s version=%s collectors=%d", state.AgentID, buildinfo.Version, len(started))
	inventory := func() enroll.ProtectionInventory {
		bundle := engine.BundleInfo()
		health := make(map[string]string, len(collectors)+1)
		for name, status := range failed {
			health[name] = status
		}
		for _, collector := range started {
			health[collector.Name()] = collector.Health().String()
		}
		for name, status := range engine.Health() {
			health[name] = status
		}
		return enroll.ProtectionInventory{
			Source: bundle.Source, Version: bundle.Version, SHA256: bundle.SHA256,
			RuleCount: len(engine.Inventory()), Platform: "linux", Mode: string(cfg.DetectionPrevention.Mode), Health: health,
		}
	}
	return runFleet(ctx, cfg, &state, inventory, onEnrolled)
}

func enrollAgent(ctx context.Context, cfg config.Config, state *identity.State) error {
	response, err := enroll.Enroll(ctx, cfg, *state, buildinfo.Version)
	*state = identity.MarkEnrollment(*state, response.EnrollmentID, err)
	if saveErr := identity.Save(cfg.StatePath, *state); saveErr != nil {
		return saveErr
	}
	return err
}

// runFleet owns all mutable enrollment state; telemetry runs independently.
func runFleet(ctx context.Context, cfg config.Config, state *identity.State, inventory func() enroll.ProtectionInventory, onEnrolled func()) error {
	enrollment := time.NewTicker(cfg.EnrollInterval())
	heartbeat := time.NewTicker(cfg.HeartbeatInterval())
	commands := time.NewTicker(cfg.CommandPollInterval())
	defer enrollment.Stop()
	defer heartbeat.Stop()
	defer commands.Stop()
	upgrading := make(chan struct{}, 1)
	var upgrades sync.WaitGroup
	defer upgrades.Wait()
	handleCommands := func(response enroll.HeartbeatResponse) {
		for _, command := range response.PendingCommands {
			if !strings.HasPrefix(command, "upgrade:") {
				continue
			}
			version := strings.TrimPrefix(command, "upgrade:")
			if version == "" || version == buildinfo.Version {
				continue
			}
			select {
			case upgrading <- struct{}{}:
				upgrades.Add(1)
				go func(target string) {
					defer upgrades.Done()
					defer func() { <-upgrading }()
					if err := upgrade.Perform(ctx, target); err != nil {
						log.Printf("upgrade failed: %v", err)
					}
				}(version)
			default:
			}
		}
	}
	sendHeartbeat := func() {
		response, err := enroll.Heartbeat(ctx, cfg, *state, buildinfo.Version, inventory())
		if err != nil {
			log.Printf("heartbeat failed: %v", err)
			return
		}
		handleCommands(response)
	}
	tryEnrollment := func() {
		if err := enrollAgent(ctx, cfg, state); err != nil {
			log.Printf("enrollment failed: %v", err)
			return
		}
		onEnrolled()
		sendHeartbeat()
	}
	if state.Enrolled {
		onEnrolled()
		sendHeartbeat()
	} else {
		tryEnrollment()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-enrollment.C:
			if !state.Enrolled {
				tryEnrollment()
			}
		case <-heartbeat.C:
			if state.Enrolled {
				sendHeartbeat()
			}
		case <-commands.C:
			if !state.Enrolled {
				continue
			}
			response, err := enroll.PollCommands(ctx, cfg, *state, buildinfo.Version)
			if err != nil {
				log.Printf("command poll failed: %v", err)
			} else {
				handleCommands(response)
			}
		}
	}
}

func isSecurityClassifiedEvent(event events.Event) bool {
	return event.Kind == "alert" || event.Category == "intrusion_detection" ||
		strings.HasPrefix(event.Module, "detection.") || strings.HasPrefix(event.Module, "prevention.")
}
