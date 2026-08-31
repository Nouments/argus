package alerting

import (
	"context"
	"testing"
	"time"

	"github.com/Nouments/argus/pkg/events"
)

func alertEvent() events.Event {
	return events.Event{
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

func TestNewAlertBuildsValidAlert(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 1, 2, 0, time.UTC)
	alert := NewAlert("ARGUS-AUTH-001", "Brute force SSH", "high", "site-a|10.0.0.1", 10, alertEvent(), now)

	if err := alert.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if alert.AlertID == "" {
		t.Fatal("NewAlert() should compute an alert id")
	}
	if alert.Status != StatusOpen {
		t.Fatalf("Status = %q, want open", alert.Status)
	}
	if alert.CreatedAt != "2026-08-30T12:01:02Z" {
		t.Fatalf("CreatedAt = %q, want deterministic timestamp", alert.CreatedAt)
	}
}

func TestManagerSaveAndListAlerts(t *testing.T) {
	manager := NewManager()
	alert := NewAlert("ARGUS-AUTH-001", "Brute force SSH", "high", "site-a|10.0.0.1", 10, alertEvent(), time.Now())

	if err := manager.SaveAlert(context.Background(), alert); err != nil {
		t.Fatalf("SaveAlert() error: %v", err)
	}
	got := manager.ListAlerts()
	if len(got) != 1 {
		t.Fatalf("ListAlerts() len = %d, want 1", len(got))
	}
	got[0].RuleID = "mutated"
	if manager.ListAlerts()[0].RuleID == "mutated" {
		t.Fatal("ListAlerts() should return a copy")
	}
}

func TestManagerRejectsInvalidAlert(t *testing.T) {
	manager := NewManager()
	alert := NewAlert("ARGUS-AUTH-001", "Brute force SSH", "high", "group", 1, alertEvent(), time.Now())
	alert.Severity = "urgent"

	if err := manager.SaveAlert(context.Background(), alert); err == nil {
		t.Fatal("SaveAlert() should reject invalid alert")
	}
}
