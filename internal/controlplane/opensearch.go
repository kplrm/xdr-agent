package controlplane

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"xdr-agent/internal/config"
	"xdr-agent/internal/events"
)

const (
	TelemetryStream = "xdr-agent-telemetry"
	SecurityStream  = "xdr-agent-security"
	LogsStream      = "xdr-agent-logs"
)

// NewOpenSearchShipper sends append-only bulk creates using separate, restricted
// OpenSearch credentials. It never forwards the Coordinator enrollment token.
func NewOpenSearchShipper(settings ShipperConfig, target config.OpenSearchConfig, stream string) (*Shipper, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if target.URL == "" {
		return nil, fmt.Errorf("opensearch.url is required")
	}
	if stream != TelemetryStream && stream != SecurityStream && stream != LogsStream {
		return nil, fmt.Errorf("unknown XDR data stream")
	}
	password := os.Getenv(target.PasswordVariable())
	if password == "" {
		return nil, fmt.Errorf("direct ingestion requires environment variable %s", target.PasswordVariable())
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if target.CAFile != "" {
		pem, err := os.ReadFile(target.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read OpenSearch CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("OpenSearch CA file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	settings.TelemetryURL, settings.TelemetryPath = target.URL, "/_bulk"
	settings.EnrollmentToken, settings.InsecureSkipTLS = "", false
	s := NewShipper(settings)
	s.client.Transport = transport
	// Do not send event contents to an unexpected redirect destination.
	s.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s.stream, s.username, s.password = stream, target.Username, password
	return s, nil
}

func (s *Shipper) shipOpenSearch(ctx context.Context, batch []events.Event) error {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	encoder := json.NewEncoder(gz)
	for _, event := range batch {
		if err := encoder.Encode(map[string]any{"create": map[string]string{
			"_index": s.stream, "_id": s.cfg.AgentID + ":" + event.ID,
		}}); err != nil {
			return err
		}
		event.AgentID = s.cfg.AgentID
		event.ID = "" // Identity belongs in bulk metadata, not the document body.
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	if err := gz.Close(); err != nil {
		return err
	}
	endpoint, err := joinTelemetryURL(s.cfg.TelemetryURL, "/_bulk")
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryBaseDelay * time.Duration(1<<(attempt-1))):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(compressed.Bytes()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("User-Agent", "xdr-agent")
		req.SetBasicAuth(s.username, s.password)
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("OpenSearch bulk transport: %w", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
			resp.Body.Close()
			lastErr = fmt.Errorf("OpenSearch bulk rejected: HTTP %d", resp.StatusCode)
			if resp.StatusCode < 500 && resp.StatusCode != 429 {
				return lastErr
			}
			continue
		}
		var result struct {
			Items []struct {
				Create struct {
					Status int `json:"status"`
					Error  struct {
						Type string `json:"type"`
					} `json:"error"`
				} `json:"create"`
			} `json:"items"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&result)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("decode OpenSearch bulk response: %w", err)
		}
		if len(result.Items) != len(batch) {
			return fmt.Errorf("incomplete OpenSearch bulk response: %d/%d items", len(result.Items), len(batch))
		}
		for _, item := range result.Items {
			action := item.Create
			if action.Status >= 200 && action.Status < 300 {
				continue
			}
			// A partial batch retry may include documents already created in this
			// backing index. Rollover is a deduplication boundary, as a date was before.
			if action.Status == 409 && action.Error.Type == "version_conflict_engine_exception" {
				continue
			}
			return fmt.Errorf("OpenSearch bulk item rejected: status=%d type=%s", action.Status, action.Error.Type)
		}
		if s.cfg.LogSuccess {
			log.Printf("shipped %d events to OpenSearch data stream %s", len(batch), s.stream)
		}
		return nil
	}
	return lastErr
}
