# Event Pipeline

The event pipeline is the handoff point between collection, detection, prevention, and shipping.

## What Exists Today

The implementation is intentionally simple:

- an in-memory buffered channel in `internal/events/pipeline.go`
- subscribers registered by runtime components
- compressed batch shipping in `internal/controlplane/shipper.go`
- requeue on shipping failure inside the shipper
- drop logging when the pipeline buffer is saturated

## Actual Flow

```text
collector or engine
  -> pipeline.Emit(event)
  -> subscriber callbacks
  -> shipper enqueue
  -> batch flush
  -> gzip HTTP POST to control plane
```

## Event Types in Practice

The current event model supports four broad kinds:

- `event`: raw telemetry or operational events
- `alert`: detection results
- `metric`: runtime measurements
- `state`: state changes when used by a component

Prevention actions are emitted as normal events with prevention-oriented metadata.

## Important Clarification

The current pipeline does not implement durable on-disk event buffering.

What it does instead:
- keeps an in-memory buffer
- drops events when the pipeline channel is full
- logs drop summaries in a rate-limited way
- requeues batches inside the shipper when HTTP delivery fails

That distinction matters for reliability planning and should stay explicit in all docs.

## Shipping Behavior

The shipper:
- batches events
- compresses requests with gzip
- retries failed requests with exponential backoff
- avoids retrying most non-429 client errors
- performs a final flush attempt on shutdown

## Documentation Boundary

This document describes the current mechanics only.
If durable buffering, WAL replay, or alternate transport fan-out are added later, document them as new features rather than implying they already exist.
