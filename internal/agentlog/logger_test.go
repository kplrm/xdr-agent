package agentlog

import (
	"testing"
	"xdr-agent/internal/events"
)

func TestRuntimeLogCapture(t *testing.T) {
	var captured []events.Event
	w := NewWriter("INFO", "agent", "host", func(e events.Event) { captured = append(captured, e) })
	w.Write([]byte("runtime started"))
	w.Write([]byte("warning: degraded"))
	w.Write([]byte("shipper: connection failed"))
	w.Close()
	if len(captured) != 2 {
		t.Fatalf("captured %d events", len(captured))
	}
	if captured[0].AgentID != "agent" || captured[1].Payload["log.level"] != "WARN" {
		t.Fatal("identity/severity missing")
	}
	w.Write([]byte("after close"))
}
