package controlplane

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"xdr-agent/internal/events"
)

func TestShipperBatchesRetriesAndPreservesIDs(t *testing.T) {
	batches := make(chan TelemetryBatch, 8)
	reject := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		defer gz.Close()
		var batch TelemetryBatch
		if err := json.NewDecoder(gz).Decode(&batch); err != nil {
			t.Error(err)
		}
		batches <- batch
		if reject {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	s := NewShipper(ShipperConfig{TelemetryURL: server.URL, TelemetryPath: "/fixture", AgentID: "agent", BatchSize: 2, MaxQueueEvents: 3, Interval: 50 * time.Millisecond})
	s.Enqueue(events.Event{Type: "one", Payload: map[string]interface{}{"process": map[string]interface{}{"pid": 42}}})
	s.Enqueue(events.Event{Type: "two"})
	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("expected rejection")
	}
	first := <-batches
	if !strings.HasPrefix(first.Events[0].ID, "agent:") || first.Events[0].ID == first.Events[1].ID {
		t.Fatal("missing unique IDs")
	}
	if first.Events[0].Payload["process"].(map[string]interface{})["pid"] != float64(42) {
		t.Fatal("batch delivery lost root detail fields")
	}
	reject = false
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	retried := <-batches
	if retried.Events[0].ID != first.Events[0].ID {
		t.Fatal("retry changed identity")
	}
	s.Enqueue(events.Event{Type: "three"})
	s.Enqueue(events.Event{Type: "four"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-batches:
		t.Fatal("flushed before interval")
	case <-time.After(15 * time.Millisecond):
	}
	select {
	case batch := <-batches:
		if len(batch.Events) != 2 {
			t.Fatal("not batched")
		}
	case <-time.After(time.Second):
		t.Fatal("periodic shipping did not run")
	}
	cancel()
	<-done
}
func TestShipperBoundsOutageQueue(t *testing.T) {
	s := NewShipper(ShipperConfig{MaxQueueEvents: 2})
	for i := 0; i < 10; i++ {
		s.Enqueue(events.Event{})
	}
	if len(s.buffer) != 2 {
		t.Fatal("queue not bounded")
	}
}

func TestShipperIntervalUpdateRetainsQueuedEvents(t *testing.T) {
	batches := make(chan TelemetryBatch, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		batches <- decodeShipperBatch(t, r)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	shipper := NewShipper(ShipperConfig{TelemetryURL: server.URL, AgentID: "agent", Interval: time.Hour})
	shipper.Enqueue(events.Event{ID: "queued-before-policy", Type: "process.start"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { shipper.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	shipper.SetInterval(20 * time.Millisecond)
	select {
	case batch := <-batches:
		if len(batch.Events) != 1 || batch.Events[0].ID != "agent:queued-before-policy" {
			t.Fatalf("policy update changed queued events: %+v", batch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new shipping interval did not take effect")
	}
}

func TestShipperDeduplicatesQueuedIDsWithoutCollapsingOccurrences(t *testing.T) {
	s := NewShipper(ShipperConfig{MaxQueueEvents: 3})
	first := events.Event{ID: "reading-1", Type: "file.access", Payload: map[string]interface{}{"path": "/etc/shadow"}}
	s.Enqueue(first)
	s.Enqueue(first)
	second := first
	second.ID = "reading-2"
	s.Enqueue(second)
	if len(s.buffer) != 2 || s.buffer[0].ID != "reading-1" || s.buffer[1].ID != "reading-2" {
		t.Fatalf("queued observations = %+v; same ID must deduplicate and distinct occurrences must remain", s.buffer)
	}
}

func TestShipperDeduplicatesInFlightIDs(t *testing.T) {
	batches := make(chan TelemetryBatch, 2)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		batches <- decodeShipperBatch(t, r)
		select {
		case <-release:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer unblock()
	s := NewShipper(ShipperConfig{TelemetryURL: server.URL, TelemetryPath: "/fixture", AgentID: "agent", BatchSize: 2, RequestTimeout: time.Second})
	first := events.Event{ID: "in-flight", Type: "dns.query"}
	s.Enqueue(first)
	flushed := make(chan error, 1)
	go func() { flushed <- s.Flush(context.Background()) }()
	select {
	case <-batches:
	case <-time.After(time.Second):
		t.Fatal("first request did not reach the server")
	}
	s.Enqueue(first) // The buffer has already been detached for delivery.
	second := first
	second.ID = "new-occurrence"
	s.Enqueue(second)
	unblock()
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := <-batches
	if len(next.Events) != 1 || next.Events[0].ID != "agent:"+second.ID {
		t.Fatalf("events received during an in-flight request = %+v", next.Events)
	}
	if len(s.pending) != 0 {
		t.Fatal("successfully delivered IDs remained pending")
	}
}

func TestShipperFailureAndAutomaticRetryKeepEventIDs(t *testing.T) {
	batches := make(chan TelemetryBatch, 3)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		batches <- decodeShipperBatch(t, r)
		switch attempts.Add(1) {
		case 1:
			w.WriteHeader(http.StatusBadRequest) // Retain for a subsequent Flush.
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable) // Retry within that Flush.
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	s := NewShipper(ShipperConfig{TelemetryURL: server.URL, TelemetryPath: "/fixture", AgentID: "agent", BatchSize: 2})
	event := events.Event{ID: "stable-reading", Type: "network.socket_observed"}
	s.Enqueue(event)
	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("expected first delivery to fail")
	}
	first := <-batches
	if s.buffer[0].ID != event.ID {
		t.Fatal("shipping mutated the retained event identity")
	}
	s.Enqueue(event) // A retained failure must still suppress another enqueue.
	other := event
	other.ID = "another-reading"
	s.Enqueue(other)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	failed, retried := <-batches, <-batches
	if len(first.Events) != 1 || len(failed.Events) != 2 || len(retried.Events) != 2 {
		t.Fatalf("unexpected batches: first=%+v failed=%+v retried=%+v", first, failed, retried)
	}
	if first.Events[0].ID != "agent:"+event.ID || failed.Events[0].ID != "agent:"+event.ID || retried.Events[0].ID != "agent:"+event.ID ||
		failed.Events[1].ID != "agent:"+other.ID || retried.Events[1].ID != "agent:"+other.ID {
		t.Fatalf("event identities changed across retained/automatic retries: %+v / %+v / %+v", first, failed, retried)
	}
	if len(s.buffer) != 0 || len(s.pending) != 0 {
		t.Fatal("successful retry did not clear retained events")
	}
}

func decodeShipperBatch(t *testing.T, r *http.Request) TelemetryBatch {
	t.Helper()
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Errorf("decode compressed batch: %v", err)
		return TelemetryBatch{}
	}
	defer gz.Close()
	var batch TelemetryBatch
	if err := json.NewDecoder(gz).Decode(&batch); err != nil {
		t.Errorf("decode telemetry batch: %v", err)
	}
	return batch
}
