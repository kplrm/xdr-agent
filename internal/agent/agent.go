// xdr-agent - Modular XDR endpoint security agent for Linux
// Copyright (C) 2026  Diego A. Guillen-Rosaperez
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Package agent provides the core XDR agent orchestrator that manages the lifecycle
// of all security capabilities, the event pipeline, and control-plane communication.
package agent

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"xdr-agent/internal/buildinfo"
	"xdr-agent/internal/capability"
	"xdr-agent/internal/config"
	"xdr-agent/internal/controlplane"
	"xdr-agent/internal/events"
	"xdr-agent/internal/identity"
)

// Agent is the central orchestrator for the XDR endpoint agent.
// It manages the control-plane client, event pipeline, and capability lifecycles.
type Agent struct {
	cfg          config.Config
	state        identity.State
	client       *controlplane.Client
	pipeline     *events.Pipeline
	buffer       *events.Buffer
	capabilities []capability.Capability
	mu           sync.Mutex
}

// Options configures how the Agent is created.
type Options struct {
	ConfigPath      string
	EnrollmentToken string
}

// New creates and initializes a new Agent. It loads configuration, ensures agent
// identity, and creates the control-plane client and event pipeline.
func New(opts Options) (*Agent, error) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, err
	}

	state, err := identity.Ensure(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("initialize identity state: %w", err)
	}

	// Enrollment token priority: CLI argument > persisted state
	token := state.EnrollmentToken
	if opts.EnrollmentToken != "" {
		token = opts.EnrollmentToken
		state.EnrollmentToken = token
	}

	client := controlplane.NewClient(controlplane.ClientConfig{
		BaseURL:         cfg.ControlPlaneURL,
		Token:           token,
		EnrollPath:      cfg.EnrollmentPath,
		HeartbeatPath:   cfg.HeartbeatPath,
		EventsPath:      cfg.EventsPath,
		Timeout:         cfg.RequestTimeout(),
		InsecureSkipTLS: cfg.InsecureSkipTLSVerify,
	})

	pipeline := events.NewPipeline(cfg.EventBufferSize)
	buffer := events.NewBuffer(cfg.EventBufferSize)

	return &Agent{
		cfg:      cfg,
		state:    state,
		client:   client,
		pipeline: pipeline,
		buffer:   buffer,
	}, nil
}

// Register adds a capability to the agent. Must be called before Run.
func (a *Agent) Register(cap capability.Capability) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.capabilities = append(a.capabilities, cap)
}

// Enroll enrolls the agent and persists the result.
//
// If retry is false, it performs a single enrollment attempt.
// If retry is true, it retries using the configured enrollment interval until
// enrollment succeeds or ctx is canceled.
func (a *Agent) Enroll(ctx context.Context, retry bool) error {
	log.Printf("xdr-agent starting: agent_id=%s machine_id=%s hostname=%s",
		a.state.AgentID, a.state.MachineID, a.state.Hostname)

	if a.state.Enrolled {
		log.Printf("already enrolled: enrollment_id=%s", a.state.EnrollmentID)
		return nil
	}

	if !retry {
		return a.enrollOnce(ctx)
	}

	if err := a.enrollOnce(ctx); err == nil {
		return nil
	} else {
		log.Printf("initial enrollment failed: %v", err)
	}

	ticker := time.NewTicker(a.cfg.EnrollInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := a.enrollOnce(ctx); err != nil {
				log.Printf("enrollment attempt failed: %v", err)
				continue
			}
			return nil
		}
	}
}

// Run starts the agent and blocks until ctx is canceled.
//
// Lifecycle:
//  1. Enroll with control plane (retry until successful)
//  2. Connect event pipeline: capabilities → buffer → shipper → control plane
//  3. Initialize and start all registered capabilities
//  4. Run heartbeat and event shipping loops
//  5. Graceful shutdown on context cancellation
func (a *Agent) Run(ctx context.Context) error {
	log.Printf("xdr-agent starting: agent_id=%s machine_id=%s hostname=%s",
		a.state.AgentID, a.state.MachineID, a.state.Hostname)

	// ── Step 1: Enroll with retries (or no-op if already enrolled) ──
	if err := a.Enroll(ctx, true); err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	// ── Step 2: Adds a new event handler to the pipeline’s subscriber list in a thread-safe way ──
	a.pipeline.Subscribe(func(e events.Event) {
		a.buffer.Add(e)
	})

	// ── Step 3: Start event pipeline dispatcher in background ──
	go a.pipeline.Run(ctx)

	// ── Step 4: Initialize and start capabilities ──
	deps := capability.Dependencies{
		EventPipeline: a.pipeline,
		Config:        a.cfg,
		Logger:        log.Default(),
	}

	for _, cap := range a.capabilities {
		if err := cap.Init(deps); err != nil {
			return fmt.Errorf("init capability %s: %w", cap.Name(), err)
		}
		log.Printf("capability initialized: %s", cap.Name())
	}

	for _, cap := range a.capabilities {
		if err := cap.Start(ctx); err != nil {
			return fmt.Errorf("start capability %s: %w", cap.Name(), err)
		}
		log.Printf("capability started: %s", cap.Name())
	}

	// ── Step 5: Run heartbeat and event shipping loops ──
	go a.heartbeatLoop(ctx)
	go a.shipLoop(ctx)

	log.Printf("xdr-agent running (%d capabilities)", len(a.capabilities))

	// ── Step 6: Block / waits until shutdown ──
	<-ctx.Done()

	// ── Step 7: Graceful shutdown ──
	log.Printf("xdr-agent shutting down, stopping %d capabilities", len(a.capabilities))
	for i := len(a.capabilities) - 1; i >= 0; i-- {
		cap := a.capabilities[i]
		if err := cap.Stop(); err != nil {
			log.Printf("error stopping capability %s: %v", cap.Name(), err)
		} else {
			log.Printf("capability stopped: %s", cap.Name())
		}
	}

	// Flush remaining events before shutting down
	a.shipOnce(context.Background())

	return ctx.Err()
}

// enrollOnce performs a single enrollment attempt and persists the result.
func (a *Agent) enrollOnce(ctx context.Context) error {
	resp, err := a.client.Enroll(ctx, a.state, a.cfg.PolicyID, a.cfg.Tags, buildinfo.Version)
	a.state = identity.MarkEnrollment(a.state, resp.EnrollmentID, err)
	if saveErr := identity.Save(a.cfg.StatePath, a.state); saveErr != nil {
		return fmt.Errorf("save state: %w", saveErr)
	}
	if err != nil {
		return err
	}

	log.Printf("enrollment successful: enrollment_id=%s message=%s", resp.EnrollmentID, resp.Message)
	return nil
}

// heartbeatLoop sends periodic heartbeats to the control plane.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.HeartbeatInterval())
	defer ticker.Stop()

	for {
		if err := a.client.Heartbeat(ctx, a.state, a.cfg.PolicyID, a.cfg.Tags, buildinfo.Version); err != nil {
			log.Printf("heartbeat failed: %v", err)
		} else {
			log.Printf("heartbeat successful: agent_id=%s", a.state.AgentID)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// shipLoop periodically flushes buffered events to the control plane.
func (a *Agent) shipLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.ShipInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.shipOnce(ctx)
		}
	}
}

// shipOnce flushes the buffer and ships events. On failure, re-buffers them.
func (a *Agent) shipOnce(ctx context.Context) {
	batch := a.buffer.Flush()
	if len(batch) == 0 {
		return
	}
	if err := a.client.ShipEvents(ctx, batch); err != nil {
		log.Printf("ship events failed (%d events): %v", len(batch), err)
		// Re-buffer events that failed to ship
		for _, e := range batch {
			a.buffer.Add(e)
		}
	}
}
