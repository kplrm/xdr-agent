package controlplane

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"xdr-agent/internal/events"
)

const (
	defaultShipInterval = 1 * time.Second
	defaultBatchSize    = 500
	maxRetries          = 3
	retryBaseDelay      = 2 * time.Second
)

// TelemetryBatch is the JSON payload shipped to the telemetry endpoint.
type TelemetryBatch struct {
	AgentID string         `json:"agent_id"`
	Events  []events.Event `json:"events"`
}

// ShipperConfig holds the settings needed by the Shipper.
type ShipperConfig struct {
	TelemetryURL    string        // base URL (falls back to control plane URL)
	TelemetryPath   string        // e.g. /api/v1/agents/telemetry
	AgentID         string        // enrolled agent identifier
	Interval        time.Duration // how often to flush (0 → 10 s)
	BatchSize       int           // max events per HTTP request (0 → 500)
	RequestTimeout  time.Duration // per-request timeout
	InsecureSkipTLS bool
}

// Shipper subscribes to the event pipeline and ships events to the
// configured telemetry endpoint in compressed batches.
type Shipper struct {
	cfg    ShipperConfig
	client *http.Client

	mu     sync.Mutex
	buffer []events.Event
	notify chan struct{} // signaled when new events are enqueued
}

// NewShipper creates a new event shipper.
func NewShipper(cfg ShipperConfig) *Shipper {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultShipInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 10 * time.Second
	}

	return &Shipper{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.RequestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipTLS},
			},
		},
		buffer: make([]events.Event, 0, cfg.BatchSize),
		notify: make(chan struct{}, 1),
	}
}

// Enqueue adds an event to the internal buffer. Intended to be used as
// a pipeline subscriber callback: pipeline.Subscribe(shipper.Enqueue)
func (s *Shipper) Enqueue(event events.Event) {
	s.mu.Lock()
	s.buffer = append(s.buffer, event)
	s.mu.Unlock()

	// Wake up the shipping loop (non-blocking).
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Run starts the shipping loop. It flushes immediately when events arrive
// (via the notify channel) or after the configured linger interval — whichever
// comes first. Blocks until ctx is canceled, then performs a final flush.
func (s *Shipper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush on shutdown
			s.flush(context.Background())
			return
		case <-s.notify:
			s.flush(ctx)
		case <-ticker.C:
			s.flush(ctx)
		}
	}
}

// flush drains the buffer and ships events in batches.
func (s *Shipper) flush(ctx context.Context) {
	s.mu.Lock()
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.buffer
	s.buffer = make([]events.Event, 0, s.cfg.BatchSize)
	s.mu.Unlock()

	// Ship in batch-sized chunks
	for i := 0; i < len(batch); i += s.cfg.BatchSize {
		end := i + s.cfg.BatchSize
		if end > len(batch) {
			end = len(batch)
		}
		chunk := batch[i:end]

		if err := s.ship(ctx, chunk); err != nil {
			log.Printf("shipper: failed to ship %d events: %v", len(chunk), err)
			// Re-enqueue failed events so they can be retried
			s.mu.Lock()
			s.buffer = append(chunk, s.buffer...)
			s.mu.Unlock()
			return // stop shipping this cycle; retry next tick
		}

		log.Printf("shipper: shipped %d events", len(chunk))
	}
}

// ship sends a single batch of events to the telemetry endpoint with gzip
// compression and retry logic.
func (s *Shipper) ship(ctx context.Context, batch []events.Event) error {
	payload := TelemetryBatch{
		AgentID: s.cfg.AgentID,
		Events:  batch,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telemetry batch: %w", err)
	}

	// Gzip compress the payload
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(jsonBody); err != nil {
		gz.Close()
		return fmt.Errorf("gzip telemetry batch: %w", err)
	}
	gz.Close()

	endpoint, err := joinTelemetryURL(s.cfg.TelemetryURL, s.cfg.TelemetryPath)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryBaseDelay * time.Duration(1<<(attempt-1))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(compressed.Bytes()))
		if err != nil {
			return fmt.Errorf("build telemetry request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("User-Agent", "xdr-agent")
		req.Header.Set("osd-xsrf", "true")

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("send telemetry request: %w", err)
			continue
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil // success
		}

		lastErr = fmt.Errorf("telemetry rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))

		// Don't retry on 4xx client errors (except 429)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			return lastErr
		}
	}

	return lastErr
}

// joinTelemetryURL builds the full URL from base + path.
func joinTelemetryURL(base, path string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return "", fmt.Errorf("invalid telemetry_url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid telemetry_url: expected absolute URL")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	return u.String(), nil
}
