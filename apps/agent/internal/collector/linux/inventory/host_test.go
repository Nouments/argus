package inventory

import (
    "testing"
    "time"

    "github.com/Nouments/argus/apps/agent/internal/event"
)

func TestHostCollectorProducesValidEvent(t *testing.T) {
    runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
        return "Linux test 5.10", nil
    }
    c := NewHostCollector()
    b, err := c.Collect()
    if err != nil {
        t.Fatalf("Collect() error: %v", err)
    }
    ev, err := event.FromJSON(b)
    if err != nil {
        t.Fatalf("FromJSON() error: %v", err)
    }
    if ev.EventType != "inventory.host" {
        t.Fatalf("event type = %q, want inventory.host", ev.EventType)
    }
}
