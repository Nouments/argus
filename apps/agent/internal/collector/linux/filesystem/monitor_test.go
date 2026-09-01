package filesystem

import (
	"testing"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/event"
)

func TestFilesystemCollectorProducesValidEvent(t *testing.T) {
	runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
		return "/etc/passwd\n/var/log/syslog", nil
	}
	c := NewFilesystemCollector()
	b, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	ev, err := event.FromJSON(b)
	if err != nil {
		t.Fatalf("FromJSON() error: %v", err)
	}
	if ev.EventType != "inventory.filesystem" {
		t.Fatalf("event type = %q, want inventory.filesystem", ev.EventType)
	}
}
