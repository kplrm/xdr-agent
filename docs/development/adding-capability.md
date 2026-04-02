# Adding a Capability

Use this guide when adding a new runtime capability to `xdr-agent`.

## Decide First

Before creating a package, decide whether the feature is actually one of these:

- telemetry collector
- detection engine logic
- prevention decision or enforcement logic
- control-plane sync logic

Do not create a new capability just because a feature exists conceptually on the roadmap.

## Design Rules

- Fit the current service model in `internal/service/run.go`.
- Reuse the shared event envelope from `internal/events/event.go`.
- Make posture interaction explicit if the feature is policy-controlled.
- Keep endpoint-side logic local and deterministic.

## Typical Steps

### 1. Create the package
Place it under the correct domain:

- `internal/telemetry/<name>`
- `internal/detection/<name>`
- `internal/prevention/<name>`

### 2. Define startup and runtime behavior
The agent currently mixes full capability-style modules and manager-style runtime components.

Match the existing pattern used by the neighboring package instead of forcing a new abstraction.

### 3. Emit events through the pipeline
Use the shared pipeline so the new component participates in the same shipping and downstream evaluation flow.

### 4. Add config and posture hooks only if needed
If the feature is toggleable, add:
- config defaults
- posture mapping in `internal/controlplane/defense_posture.go`
- runtime update handling in the relevant engine or manager

### 5. Wire it in `internal/service/run.go`
Keep orchestration changes explicit and easy to review.

### 6. Test the real boundary
At minimum, validate:
- startup behavior
- event emission
- posture update handling if applicable
- failure behavior when control plane or local artifacts are unavailable

## Anti-Patterns

- adding roadmap-only stubs with no runtime path
- creating a second event model instead of reusing the shared one
- duplicating feed curation logic that belongs in `xdr-defense`
- documenting fields or behavior before the runtime actually emits them