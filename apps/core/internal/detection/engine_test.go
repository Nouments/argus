package detection

import (
	"context"
	"testing"
	"time"

	"github.com/Nouments/argus/apps/core/internal/alerting"
	"github.com/Nouments/argus/apps/core/internal/rules"
	"github.com/Nouments/argus/pkg/events"
)

func detectionEvent(id string, ts time.Time) events.Event {
	return events.Event{
		EventID:   id,
		Timestamp: ts.UTC().Format(time.RFC3339),
		SiteID:    "site-a",
		AgentID:   "agent-01",
		EventType: "auth.failure",
		Severity:  "medium",
		Host:      "srv-01",
		User:      "admin",
		SrcIP:     "10.0.0.1",
		Raw:       "failed password",
	}
}

func thresholdRule() rules.Rule {
	return rules.Rule{
		ID:       "ARGUS-AUTH-001",
		Name:     "Brute force SSH",
		Severity: "high",
		Match: rules.Match{
			EventType: "auth.failure",
		},
		GroupBy: []string{"site_id", "src_ip", "user"},
		Threshold: rules.Threshold{
			Count:  3,
			Window: time.Minute,
		},
	}
}

func TestEngineCreatesAlertAtThreshold(t *testing.T) {
	manager := alerting.NewManager()
	engine, err := NewEngine([]rules.Rule{thresholdRule()}, manager)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	engine.now = func() time.Time {
		return time.Date(2026, 8, 30, 12, 1, 0, 0, time.UTC)
	}

	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		alerts, err := engine.Process(context.Background(), detectionEvent("evt-pre", base.Add(time.Duration(i)*time.Second)))
		if err != nil {
			t.Fatalf("Process() pre-threshold error: %v", err)
		}
		if len(alerts) != 0 {
			t.Fatalf("Process() produced %d alerts before threshold, want 0", len(alerts))
		}
	}

	alerts, err := engine.Process(context.Background(), detectionEvent("evt-hit", base.Add(2*time.Second)))
	if err != nil {
		t.Fatalf("Process() threshold error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("Process() alerts = %d, want 1", len(alerts))
	}
	if alerts[0].RuleID != "ARGUS-AUTH-001" {
		t.Fatalf("alert RuleID = %q, want ARGUS-AUTH-001", alerts[0].RuleID)
	}
	if alerts[0].Count != 3 {
		t.Fatalf("alert Count = %d, want 3", alerts[0].Count)
	}
	if got := manager.ListAlerts(); len(got) != 1 {
		t.Fatalf("manager alerts = %d, want 1", len(got))
	}
}

func TestEngineKeepsGroupsSeparate(t *testing.T) {
	engine, err := NewEngine([]rules.Rule{thresholdRule()}, nil)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	engine.now = func() time.Time {
		return time.Date(2026, 8, 30, 12, 1, 0, 0, time.UTC)
	}

	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		ev := detectionEvent("evt-a", base.Add(time.Duration(i)*time.Second))
		ev.SrcIP = "10.0.0.1"
		if _, err := engine.Process(context.Background(), ev); err != nil {
			t.Fatalf("Process() group A error: %v", err)
		}
	}

	ev := detectionEvent("evt-b", base.Add(2*time.Second))
	ev.SrcIP = "10.0.0.2"
	alerts, err := engine.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process() group B error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("Process() alerts = %d, want 0 for separate group", len(alerts))
	}
}

func TestEngineExpiresOldEvents(t *testing.T) {
	engine, err := NewEngine([]rules.Rule{thresholdRule()}, nil)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	engine.now = func() time.Time {
		return time.Date(2026, 8, 30, 12, 10, 0, 0, time.UTC)
	}

	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	if _, err := engine.Process(context.Background(), detectionEvent("evt-old-1", base)); err != nil {
		t.Fatalf("Process() old 1 error: %v", err)
	}
	if _, err := engine.Process(context.Background(), detectionEvent("evt-old-2", base.Add(time.Second))); err != nil {
		t.Fatalf("Process() old 2 error: %v", err)
	}

	alerts, err := engine.Process(context.Background(), detectionEvent("evt-new", base.Add(2*time.Minute)))
	if err != nil {
		t.Fatalf("Process() new error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("Process() alerts = %d, want 0 after window expiration", len(alerts))
	}
}

func TestNewEngineRejectsInvalidRule(t *testing.T) {
	rule := thresholdRule()
	rule.ID = ""
	if _, err := NewEngine([]rules.Rule{rule}, nil); err == nil {
		t.Fatal("NewEngine() should reject invalid rules")
	}
}
