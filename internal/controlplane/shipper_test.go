package controlplane

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	s.Enqueue(events.Event{Type: "one"})
	s.Enqueue(events.Event{Type: "two"})
	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("expected rejection")
	}
	first := <-batches
	if first.Events[0].ID == "" || first.Events[0].ID == first.Events[1].ID {
		t.Fatal("missing unique IDs")
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
