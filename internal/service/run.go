package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"xdr-agent/internal/buildinfo"
	"xdr-agent/internal/config"
	"xdr-agent/internal/enroll"
	"xdr-agent/internal/identity"
)

func Run(ctx context.Context, configPath string, once bool) error {
	// Load configuration from config.json
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// Ensure identity State from 'state_path' is initialized and load current state
	state, err := identity.Ensure(cfg.StatePath)
	if err != nil {
		return fmt.Errorf("initialize identity state: %w", err)
	}

	log.Printf("xdr-agent starting: agent_id=%s machine_id=%s hostname=%s", state.AgentID, state.MachineID, state.Hostname)

	attempt := func() error {
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

	if err := attempt(); err != nil {
		if once {
			return err
		}
		log.Printf("initial enrollment failed: %v", err)
	} else if once {
		return nil
	}

	// Creates a periodic timer that acts as the heartbeat for recurring enrollment attempts.
	ticker := time.NewTicker(cfg.EnrollInterval())
	defer ticker.Stop()

	// Main loop that continues until the context is canceled or the ticker fires.
	for {
		select {
		case <-ctx.Done():	// If the context is canceled (e.g., on SIGTERM), log shutdown and exit.
			log.Printf("xdr-agent stopping")
			return ctx.Err()
		case <-ticker.C:	// On each tick, attempt enrollment.
			if err := attempt(); err != nil {
				log.Printf("enrollment attempt failed: %v", err)
			}
		}
	}
}
