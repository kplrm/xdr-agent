package events

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestEventRootFieldsRoundTrip(t *testing.T) {
	for _, details := range []map[string]interface{}{
		nil,
		{"process": map[string]interface{}{"pid": 42}, "local": map[string]interface{}{"ip": "2001:db8::1", "port": 50000}},
		{"dns": map[string]interface{}{"question": map[string]interface{}{"name": "example.org"}}},
		{"file": map[string]interface{}{"path": "/etc/shadow"}, "event": map[string]interface{}{"action": "file-accessed"}},
		{"rule.id": "yara-rule", "process.pid": 42, "method": "yara"},
		{"message": "Agent started", "log.level": "INFO"},
	} {
		event := Event{ID: "reading", Timestamp: time.Now().UTC(), Module: "test", AgentID: "agent", Kind: "event", Payload: details}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]interface{}
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatal(err)
		}
		if _, wrapped := document["payload"]; wrapped {
			t.Fatalf("event details must be at the root: %s", encoded)
		}
		for _, field := range []string{"id", "_id"} {
			if _, exists := document[field]; exists {
				t.Fatalf("internal event identity was serialized: %s", encoded)
			}
		}
		for field := range details {
			if _, exists := document[field]; !exists {
				t.Fatalf("missing root field %q: %s", field, encoded)
			}
		}
		var decoded Event
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.ID != "" || decoded.AgentID != event.AgentID || !decoded.Timestamp.Equal(event.Timestamp) {
			t.Fatalf("envelope changed: %+v", decoded)
		}
		roundTrip, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		var restored map[string]interface{}
		if err := json.Unmarshal(roundTrip, &restored); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(document, restored) {
			t.Fatalf("root fields changed after decoding: %s", roundTrip)
		}
	}
}

func TestEventDetailsCannotOverrideEnvelope(t *testing.T) {
	for _, field := range envelopeFields {
		if _, err := json.Marshal(Event{Payload: map[string]interface{}{field: "override"}}); err == nil {
			t.Fatalf("detail field %q was allowed to override the envelope", field)
		}
	}
}

func TestOptionalSeverityJSON(t *testing.T) {
	for _, severity := range []*Severity{nil, SeverityInfo.Pointer(), SeverityHigh.Pointer()} {
		body, err := json.Marshal(Event{Severity: severity})
		if err != nil {
			t.Fatal(err)
		}
		var encoded map[string]interface{}
		if err := json.Unmarshal(body, &encoded); err != nil {
			t.Fatal(err)
		}
		value, present := encoded["event.severity"]
		if present != (severity != nil) || (present && value != float64(*severity)) {
			t.Fatalf("incorrect optional severity: %s", body)
		}
	}
}
