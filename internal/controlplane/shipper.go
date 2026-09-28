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
	defaultShipInterval    = 30 * time.Second
	defaultBatchSize       = 500
	defaultMaxQueueBatches = 10
	defaultMinQueueEvents  = 1000
	maxRetries             = 3
	retryBaseDelay         = 2 * time.Second
	queueDropLogWindow     = 5 * time.Second
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
	EnrollmentToken string        // optional bearer token for control-plane auth
	Interval        time.Duration // how often to flush (0 → 30 s)
	BatchSize       int           // max events per HTTP request (0 → 500)
	MaxQueueEvents  int           // max in-memory queued events before dropping (0 → max(BatchSize*10, 1000))
	RequestTimeout  time.Duration // per-request timeout
	InsecureSkipTLS bool
	LogSuccess      bool // log successful nonempty batches; disable for the log shipper
}

// Shipper subscribes to the event pipeline and ships events to the
// configured telemetry endpoint in compressed batches.
type Shipper struct {
	cfg    ShipperConfig
	client *http.Client

	mu     sync.Mutex
	buffer []events.Event

	dropFrom    time.Time
	dropCount   int
	dropLastTyp string
}

// NewShipper creates a new event shipper.
func NewShipper(cfg ShipperConfig) *Shipper {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultShipInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.MaxQueueEvents <= 0 {
		cfg.MaxQueueEvents = cfg.BatchSize * defaultMaxQueueBatches
		if cfg.MaxQueueEvents < defaultMinQueueEvents {
			cfg.MaxQueueEvents = defaultMinQueueEvents
		}
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
	}
}

// Enqueue adds an event to the internal buffer. Intended to be used as
// a pipeline subscriber callback: pipeline.Subscribe(shipper.Enqueue)
func (s *Shipper) Enqueue(event events.Event) {
	if event.ID == "" {
		event.ID = events.NewID()
	}
	s.mu.Lock()
	if len(s.buffer) >= s.cfg.MaxQueueEvents {
		msg := s.recordDropLocked(event.Type, time.Now())
		s.mu.Unlock()
		if msg != "" {
			log.Print(msg)
		}
		return
	}
	s.buffer = append(s.buffer, event)
	s.mu.Unlock()

}

func (s *Shipper) recordDropLocked(eventType string, now time.Time) string {
	if s.dropFrom.IsZero() {
		s.dropFrom = now
		s.dropCount = 1
		s.dropLastTyp = eventType
		return fmt.Sprintf("shipper queue full (%d), dropping events (suppressing repeats for %s, latest type=%s)", s.cfg.MaxQueueEvents, queueDropLogWindow, eventType)
	}

	if now.Sub(s.dropFrom) < queueDropLogWindow {
		s.dropCount++
		s.dropLastTyp = eventType
		return ""
	}

	prevCount := s.dropCount
	prevType := s.dropLastTyp
	s.dropFrom = now
	s.dropCount = 1
	s.dropLastTyp = eventType

	return fmt.Sprintf(
		"shipper queue full (%d), dropped %d events in last %s (latest type=%s); continuing to drop (latest type=%s)",
		s.cfg.MaxQueueEvents,
		prevCount,
		queueDropLogWindow,
		prevType,
		eventType,
	)
}

// Run packs events on a fixed interval. Drain producers and call Flush after
// Run exits to ship the final batch during shutdown.
func (s *Shipper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Flush(ctx); err != nil && ctx.Err() == nil {
				log.Printf("shipper: %v", err)
			}
		}
	}
}

// Flush retains failed batches for retry and bounds the outage queue.
// The caller must not invoke Flush concurrently with Run.
func (s *Shipper) Flush(ctx context.Context) error {
	s.mu.Lock()
	batch := s.buffer
	s.buffer = make([]events.Event, 0, s.cfg.BatchSize)
	s.mu.Unlock()
	for i := 0; i < len(batch); i += s.cfg.BatchSize {
		end := i + s.cfg.BatchSize
		if end > len(batch) {
			end = len(batch)
		}
		if err := s.ship(ctx, batch[i:end]); err != nil {
			s.mu.Lock()
			pending := append(batch[i:], s.buffer...)
			dropped := len(pending) - s.cfg.MaxQueueEvents
			if dropped > 0 {
				pending = pending[:s.cfg.MaxQueueEvents]
			}
			s.buffer = pending
			s.mu.Unlock()
			if dropped > 0 {
				log.Printf("shipper: retry queue full, dropped %d newest events", dropped)
			}
			return err
		}
	}
	return nil
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
	if err := gz.Close(); err != nil {
		return err
	}

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
		if s.cfg.EnrollmentToken != "" {
			req.Header.Set("Authorization", "Bearer "+s.cfg.EnrollmentToken)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("send telemetry request: %w", err)
			continue
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if s.cfg.LogSuccess {
				log.Printf("shipped %d events to %s", len(batch), s.cfg.TelemetryPath)
			}
			return nil
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
