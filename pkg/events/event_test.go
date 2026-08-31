package events

import (
	"strings"
	"testing"
	"time"
)

func validEvent() Event {
	return Event{
		EventID:   "evt-1",
		Timestamp: "2026-08-30T12:00:00Z",
		SiteID:    "site-a",
		AgentID:   "agent-01",
		EventType: "auth.failure",
		Severity:  "medium",
		Host:      "srv-01",
		Raw:       "failed password",
	}
}

func TestEventValidateAcceptsCanonicalEvent(t *testing.T) {
	ev := validEvent()
	ev.SrcIP = "10.0.0.1"
	ev.DstIP = "2001:db8::1"
	ev.ReceivedAt = "2026-08-30T12:00:01Z"

	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
}

func TestEventValidateRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Event)
		wantErr string
	}{
		{
			name:    "missing event id",
			mutate:  func(ev *Event) { ev.EventID = "" },
			wantErr: "event_id",
		},
		{
			name:    "bad timestamp",
			mutate:  func(ev *Event) { ev.Timestamp = "tomorrow" },
			wantErr: "timestamp",
		},
		{
			name:    "bad event type",
			mutate:  func(ev *Event) { ev.EventType = "auth" },
			wantErr: "event_type",
		},
		{
			name:    "bad severity",
			mutate:  func(ev *Event) { ev.Severity = "urgent" },
			wantErr: "severity",
		},
		{
			name:    "bad source ip",
			mutate:  func(ev *Event) { ev.SrcIP = "10.0.0.999" },
			wantErr: "src_ip",
		},
		{
			name: "raw too large",
			mutate: func(ev *Event) {
				ev.Raw = strings.Repeat("x", DefaultMaxRawBytes+1)
			},
			wantErr: "raw exceeds",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := validEvent()
			tc.mutate(&ev)
			err := ev.Validate()
			if err == nil {
				t.Fatal("Validate() should return an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() error = %q, want containing %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestEventEnsureIntegrity(t *testing.T) {
	ev := validEvent()
	ev.EnsureIntegrity()

	if ev.IntegrityHash == "" {
		t.Fatal("EnsureIntegrity() should compute a hash")
	}
	if !strings.HasPrefix(ev.IntegrityHash, "sha256:") {
		t.Fatalf("IntegrityHash = %q, want sha256 prefix", ev.IntegrityHash)
	}

	first := ev.IntegrityHash
	ev.EnsureIntegrity()
	if ev.IntegrityHash != first {
		t.Fatal("EnsureIntegrity() should keep an existing hash")
	}
}

func TestFromJSONNormalizesAndValidates(t *testing.T) {
	data := []byte(`{"event_id":" evt-1 ","timestamp":"2026-08-30T12:00:00Z","site_id":"site-a","agent_id":"agent-01","event_type":"AUTH.FAILURE","severity":"HIGH","host":"srv-01","raw":" failed "}`)

	ev, err := FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON() error: %v", err)
	}
	if ev.EventID != "evt-1" {
		t.Fatalf("EventID = %q, want trimmed evt-1", ev.EventID)
	}
	if ev.EventType != "auth.failure" {
		t.Fatalf("EventType = %q, want auth.failure", ev.EventType)
	}
	if ev.Severity != "high" {
		t.Fatalf("Severity = %q, want high", ev.Severity)
	}
	if ev.IntegrityHash == "" {
		t.Fatal("FromJSON() should compute integrity")
	}
	if ev.Raw != " failed " {
		t.Fatalf("Raw = %q, want original spacing preserved", ev.Raw)
	}
}

func TestStampReceivedAt(t *testing.T) {
	ev := validEvent()
	now := time.Date(2026, 8, 30, 12, 1, 2, 0, time.FixedZone("UTC+3", 3*60*60))

	ev.StampReceivedAt(now)

	if ev.ReceivedAt != "2026-08-30T09:01:02Z" {
		t.Fatalf("ReceivedAt = %q, want UTC timestamp", ev.ReceivedAt)
	}
}
