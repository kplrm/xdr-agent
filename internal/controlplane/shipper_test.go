package controlplane

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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
		batches <- decodeShipperBatch(t, r)
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
	firstID := s.buffer[0].ID
	if firstID == "" || firstID == s.buffer[1].ID {
		t.Fatal("missing unique internal IDs")
	}
	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("expected rejection")
	}
	first := <-batches
	if s.buffer[0].ID != firstID {
		t.Fatal("delivery changed the retained internal ID")
	}
	if first.Events[0].Payload["process"].(map[string]interface{})["pid"] != float64(42) {
		t.Fatal("batch delivery lost root detail fields")
	}
	reject = false
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	retried := <-batches
	if !reflect.DeepEqual(retried, first) {
		t.Fatal("retry changed the buffered observation")
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
		if len(batch.Events) != 1 || batch.Events[0].Type != "process.start" {
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
	second.Type = "dns.answer"
	s.Enqueue(second)
	unblock()
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := <-batches
	if len(next.Events) != 1 || next.Events[0].Type != second.Type {
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
	other.Type = "network.socket_disappeared"
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
	if first.Events[0].Type != event.Type || failed.Events[1].Type != other.Type || !reflect.DeepEqual(failed, retried) {
		t.Fatalf("observations changed across retained/automatic retries: %+v / %+v / %+v", first, failed, retried)
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
	var wire struct {
		AgentID string            `json:"agent_id"`
		Events  []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(gz).Decode(&wire); err != nil {
		t.Errorf("decode telemetry batch: %v", err)
	}
	batch := TelemetryBatch{AgentID: wire.AgentID}
	for _, body := range wire.Events {
		var fields map[string]interface{}
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"id", "_id", "source.event.id"} {
			if _, exists := fields[field]; exists {
				t.Errorf("identity field %q was shipped", field)
			}
		}
		var event events.Event
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		batch.Events = append(batch.Events, event)
	}
	return batch
}
