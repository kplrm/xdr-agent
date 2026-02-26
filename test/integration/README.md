# Integration Tests

This directory contains integration tests for the XDR agent capabilities.

## Running Tests

```bash
# Run all tests
go test ./...

# Run integration tests (requires root for fanotify, eBPF, etc.)
sudo go test -tags=integration ./test/integration/...

# Run specific capability test
sudo go test -tags=integration ./test/integration/telemetry/...
```

## Test Structure

- `telemetry/` — Tests for telemetry collectors
- `detection/` — Tests for detection engines
- `prevention/` — Tests for prevention modules
- `response/` — Tests for response actions
- `pipeline/` — Tests for event pipeline flow
