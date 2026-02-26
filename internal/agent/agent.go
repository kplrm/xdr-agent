// Package agent provides the core XDR agent orchestrator that manages the lifecycle
// of all security capabilities, the event pipeline, and control-plane communication.
package agent

import (
	"context"
	"fmt"
	"log"
	"sync"

	"xdr-agent/internal/capability"
)

// Agent is the central orchestrator for the XDR endpoint agent.
// It manages capability registration, lifecycle, and coordination.
type Agent struct {
	capabilities []capability.Capability
	mu           sync.Mutex
}

// New creates a new Agent instance.
func New() *Agent {
	return &Agent{}
}

// Register adds a capability to the agent. Must be called before Run.
func (a *Agent) Register(cap capability.Capability) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.capabilities = append(a.capabilities, cap)
}

// Run starts all registered capabilities and blocks until ctx is canceled.
//
// This is the main entry point for the long-running agent process.
// Lifecycle:
//  1. Load configuration
//  2. Ensure agent identity
//  3. Start event pipeline
//  4. Enroll with control plane
//  5. Initialize and start all registered capabilities
//  6. Run heartbeat + policy sync loop
//  7. Graceful shutdown on context cancellation
func (a *Agent) Run(ctx context.Context) error {
	// TODO: Load config, ensure identity, start pipeline, enroll
	deps := capability.Dependencies{
		// TODO: wire up real dependencies
	}

	// Initialize all capabilities
	for _, cap := range a.capabilities {
		if err := cap.Init(deps); err != nil {
			return fmt.Errorf("init capability %s: %w", cap.Name(), err)
		}
		log.Printf("capability initialized: %s", cap.Name())
	}

	// Start all capabilities
	for _, cap := range a.capabilities {
		if err := cap.Start(ctx); err != nil {
			return fmt.Errorf("start capability %s: %w", cap.Name(), err)
		}
		log.Printf("capability started: %s", cap.Name())
	}

	// Block until context is canceled (agent shutdown)
	<-ctx.Done()

	// Graceful shutdown: stop capabilities in reverse order
	log.Printf("xdr-agent shutting down, stopping %d capabilities", len(a.capabilities))
	for i := len(a.capabilities) - 1; i >= 0; i-- {
		cap := a.capabilities[i]
		if err := cap.Stop(); err != nil {
			log.Printf("error stopping capability %s: %v", cap.Name(), err)
		} else {
			log.Printf("capability stopped: %s", cap.Name())
		}
	}

	return ctx.Err()
}
