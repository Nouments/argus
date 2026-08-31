package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadRulesFromFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "rules.yaml")
	content := `- id: R1
  name: Test rule
  severity: high
  match:
    event_type: auth.failure
  group_by: [site_id, src_ip]
  threshold:
    count: 3
    window: 1m
  actions: [create_alert]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
	rules, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFromFile error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.ID != "R1" || r.Name != "Test rule" || r.Severity != "high" {
		t.Fatalf("unexpected rule fields: %+v", r)
	}
	if r.Threshold.Count != 3 {
		t.Fatalf("unexpected threshold count: %d", r.Threshold.Count)
	}
	if r.Threshold.Window != time.Minute {
		t.Fatalf("unexpected threshold window: %v", r.Threshold.Window)
	}
}
