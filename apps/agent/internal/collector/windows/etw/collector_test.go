//go:build !windows

package etw

import (
	"encoding/json"
	"github.com/Nouments/argus/apps/agent/internal/event"
	"testing"
)

func TestETWCollector_Placeholder(t *testing.T) {
	c := NewETWCollector()
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
