package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/Nouments/argus/pkg/events"
)

func ruleEvent() events.Event {
	return events.Event{
		EventID:   "evt-1",
		Timestamp: "2026-08-30T12:00:00Z",
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

func validRule() Rule {
	return Rule{
		ID:       "ARGUS-AUTH-001",
		Name:     "Brute force SSH",
		Severity: "high",
		Match: Match{
			EventType: "auth.failure",
		},
		GroupBy: []string{"site_id", "src_ip", "user"},
		Threshold: Threshold{
			Count:  10,
			Window: time.Minute,
		},
		Actions: []string{"create_alert"},
	}
}

func TestRuleValidateAcceptsValidRule(t *testing.T) {
	if err := validRule().Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
}

func TestRuleValidateRejectsInvalidRule(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Rule)
		wantErr string
	}{
		{name: "missing id", mutate: func(r *Rule) { r.ID = "" }, wantErr: "id"},
		{name: "missing name", mutate: func(r *Rule) { r.Name = "" }, wantErr: "name"},
		{name: "bad severity", mutate: func(r *Rule) { r.Severity = "urgent" }, wantErr: "severity"},
		{name: "bad count", mutate: func(r *Rule) { r.Threshold.Count = 0 }, wantErr: "count"},
		{name: "bad window", mutate: func(r *Rule) { r.Threshold.Window = 0 }, wantErr: "window"},
		{name: "bad group field", mutate: func(r *Rule) { r.GroupBy = []string{"unknown"} }, wantErr: "group_by"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := validRule()
			tc.mutate(&rule)
			err := rule.Validate()
			if err == nil {
				t.Fatal("Validate() should return an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() error = %q, want containing %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestRuleMatches(t *testing.T) {
	rule := validRule()
	if !rule.Matches(ruleEvent()) {
		t.Fatal("Matches() should accept matching event")
	}

	ev := ruleEvent()
	ev.EventType = "network.scan"
	if rule.Matches(ev) {
		t.Fatal("Matches() should reject non-matching event type")
	}

	rule.Match.EventType = "auth.*"
	if !rule.Matches(ruleEvent()) {
		t.Fatal("Matches() should support domain wildcard")
	}
}

func TestRuleGroupKey(t *testing.T) {
	got := validRule().GroupKey(ruleEvent())
	want := "site_id=site-a|src_ip=10.0.0.1|user=admin"
	if got != want {
		t.Fatalf("GroupKey() = %q, want %q", got, want)
	}
}
