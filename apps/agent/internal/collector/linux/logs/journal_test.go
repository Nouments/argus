package logs

import (
    "testing"
    "time"

    "github.com/Nouments/argus/apps/agent/internal/event"
)

func TestJournalCollectorProducesValidEvent(t *testing.T) {
    runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
        return "Aug 30 12:00:00 host app[1]: journal entry", nil
    }
    c := NewJournalCollector()
    b, err := c.Collect()
    if err != nil {
        t.Fatalf("Collect() error: %v", err)
    }
    ev, err := event.FromJSON(b)
    if err != nil {
        t.Fatalf("FromJSON() error: %v", err)
    }
    if ev.EventType != "logs.journal" {
        t.Fatalf("event type = %q, want logs.journal", ev.EventType)
    }
}
