//go:build !windows

package eventlog

import (
	"encoding/json"
	"github.com/Nouments/argus/apps/agent/internal/event"
	"testing"
)

func TestEventLogCollector_Placeholder(t *testing.T) {
	c := NewEventLogCollector()
	b, err := c.Collect()
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	var ev event.Event
	if err := json.Unmarshal(b, &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.EventType == "" {
		t.Fatalf("event_type empty")
	}
}
