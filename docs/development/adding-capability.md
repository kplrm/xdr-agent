# Adding a New Capability

This guide explains how to add a new security capability to the XDR agent.

## Step 1: Create the package

Create a new package under the appropriate domain in `internal/`:

| Domain | Package Location | When to Use |
|---|---|---|
| Telemetry | `internal/telemetry/<name>/` | Collecting system events |
| Detection | `internal/detection/<name>/` | Analyzing events for threats |
| Prevention | `internal/prevention/<name>/` | Blocking threats in real-time |
| Response | `internal/response/` | Remote response actions |
| Compliance | `internal/compliance/` | Configuration checks |
| Cloud | `internal/cloud/<name>/` | Cloud/container monitoring |

## Step 2: Implement the Capability interface

```go
package mycapability

import (
    "context"
    "xdr-agent/internal/capability"
)

type MyCapability struct {
    deps   capability.Dependencies
    health capability.HealthStatus
}

func New() capability.Capability {
    return &MyCapability{health: capability.HealthStopped}
}

func (m *MyCapability) Name() string { return "domain.mycapability" }

func (m *MyCapability) Init(deps capability.Dependencies) error {
    m.deps = deps
    m.health = capability.HealthStarting
    // Initialize resources, load rules, etc.
    return nil
}

func (m *MyCapability) Start(ctx context.Context) error {
    m.health = capability.HealthRunning
    // Start goroutines, watchers, etc.
    // Emit events via: m.deps.EventPipeline
    return nil
}

func (m *MyCapability) Stop() error {
    m.health = capability.HealthStopped
    // Cleanup resources
    return nil
}

func (m *MyCapability) Health() capability.HealthStatus {
    return m.health
}
```

## Step 3: Register in the agent

Add your capability to the wiring section in `internal/service/run.go`:

```go
// Inside the Run() function, after the existing collectors:
myCollector := mycapability.New(pipeline, state.AgentID, state.Hostname)
if err := myCollector.Init(capability.Dependencies{}); err != nil {
    log.Printf("mycapability init failed: %v", err)
} else if err := myCollector.Start(ctx); err != nil {
    log.Printf("mycapability start failed: %v", err)
} else {
    log.Printf("capability started: %s", myCollector.Name())
}
```

## Step 4: Add configuration

Add a configuration section in `config.json`:

```json
{
  "capabilities": {
    "domain.mycapability": {
      "enabled": true,
      "custom_setting": "value"
    }
  }
}
```

## Step 5: Write tests

Add unit tests in your package and integration tests in `test/integration/`.

## Step 6: Document

Add documentation in `docs/capabilities/`.
