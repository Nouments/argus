package network

import (
	"testing"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/event"
)

func TestNetworkCollectorProducesValidEvent(t *testing.T) {
	runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
		return "tcp 0 0 127.0.0.1:80 0.0.0.0:* LISTEN", nil
	}
	c := NewNetworkCollector()
	b, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	ev, err := event.FromJSON(b)
	if err != nil {
		t.Fatalf("FromJSON() error: %v", err)
	}
	if ev.EventType != "inventory.network" {
		t.Fatalf("event type = %q, want inventory.network", ev.EventType)
	}
}
