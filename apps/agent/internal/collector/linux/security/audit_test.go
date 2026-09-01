package security

import (
    "testing"
    "time"

    "github.com/Nouments/argus/apps/agent/internal/event"
)

func TestAuditCollectorProducesValidEvent(t *testing.T) {
    runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
        return "type=SYSCALL msg=audit(0): test", nil
    }
    c := NewAuditCollector()
    b, err := c.Collect()
    if err != nil {
        t.Fatalf("Collect() error: %v", err)
    }
    ev, err := event.FromJSON(b)
    if err != nil {
        t.Fatalf("FromJSON() error: %v", err)
    }
    if ev.EventType != "security.audit" {
        t.Fatalf("event type = %q, want security.audit", ev.EventType)
    }
}
