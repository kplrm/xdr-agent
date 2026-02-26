package controlplane

// Shipper sends batched events and alerts to the control plane for indexing
// and analysis in the XDR backend (OpenSearch).

// TODO: Implement event shipper
// - ShipEvents(ctx, events []Event) method on Client
// - Batch events for efficient transport
// - Compression (gzip)
// - Retry with exponential backoff
// - Integration with events.Buffer for offline resilience
