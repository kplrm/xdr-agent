package controlplane

import (
	"context"
	"fmt"
	"strings"

	"xdr-agent/internal/events"
)

// ShipEvents sends a batch of events to the control plane for indexing in OpenSearch.
// Returns nil on success. On failure, the caller should re-buffer the events for retry.
func (c *Client) ShipEvents(ctx context.Context, batch []events.Event) error {
	if len(batch) == 0 {
		return nil
	}

	respBody, status, err := c.doJSON(ctx, c.eventsPath, batch)
	if err != nil {
		return fmt.Errorf("ship events: %w", err)
	}

	if status < 200 || status >= 300 {
		return fmt.Errorf("ship events rejected: status=%d body=%s", status, strings.TrimSpace(string(respBody)))
	}

	return nil
}
