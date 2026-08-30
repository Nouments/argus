package transport

import (
	"testing"

	"github.com/Nouments/argus/apps/agent/internal/event"
)

func TestEventEnvelopeRoundTrip(t *testing.T) {
	ev := &event.Event{
		EventID:   "evt-1",
		Timestamp: "2026-08-30T00:00:00Z",
		SiteID:    "site-a",
		AgentID:   "agent-01",
		EventType: "auth.failure",
		Severity:  "high",
		Host:      "srv-01",
		Raw:       "root login",
	}

	msg := EventToEnvelope(ev)
	if msg == nil {
		t.Fatal("EventToEnvelope() returned nil")
	}
	if msg.EventId != ev.EventID {
		t.Fatalf("EventToEnvelope event_id mismatch: got %q want %q", msg.EventId, ev.EventID)
	}
	if msg.SiteId != ev.SiteID {
		t.Fatalf("EventToEnvelope site_id mismatch: got %q want %q", msg.SiteId, ev.SiteID)
	}

	roundTrip, err := EnvelopeToEvent(msg)
	if err != nil {
		t.Fatalf("EnvelopeToEvent() returned error: %v", err)
	}
	if roundTrip.EventID != ev.EventID || roundTrip.Raw != ev.Raw {
		t.Fatalf("EnvelopeToEvent() lost data: got %#v want %#v", roundTrip, ev)
	}
}

func TestProtoEnvelopeConversionRoundTrip(t *testing.T) {
	ev := &event.Event{
		EventID:   "evt-2",
		Timestamp: "2026-08-30T01:00:00Z",
		SiteID:    "site-b",
		AgentID:   "agent-02",
		EventType: "process.spawn",
		Severity:  "critical",
		Host:      "db-01",
		Raw:       "suspicious shell",
	}

	msg := EventToEnvelope(ev)
	proto := EventEnvelopeToProto(msg)
	if proto == nil {
		t.Fatal("EventEnvelopeToProto() returned nil")
	}
	if proto.GetEventId() != ev.EventID || proto.GetSiteId() != ev.SiteID {
		t.Fatalf("proto conversion mismatch: got %#v want %#v", proto, ev)
	}

	converted, err := ProtoEnvelopeToEvent(proto)
	if err != nil {
		t.Fatalf("ProtoEnvelopeToEvent() returned error: %v", err)
	}
	if converted.EventId != ev.EventID || converted.Raw != ev.Raw {
		t.Fatalf("ProtoEnvelopeToEvent() lost data: got %#v want %#v", converted, ev)
	}
}

func TestGatewayTargetFromURL(t *testing.T) {
	got, err := GatewayTargetFromURL("https://gateway.example.com:8443/ingest")
	if err != nil {
		t.Fatalf("GatewayTargetFromURL() error: %v", err)
	}
	if got != "gateway.example.com:8443" {
		t.Fatalf("GatewayTargetFromURL() = %q, want %q", got, "gateway.example.com:8443")
	}
}
