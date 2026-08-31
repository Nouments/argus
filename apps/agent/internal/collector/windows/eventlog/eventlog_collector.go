//go:build !windows
package eventlog

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/collector"
	"github.com/Nouments/argus/apps/agent/internal/event"
	"github.com/Nouments/argus/apps/agent/internal/host"
)

type eventLogCollector struct{}

func (e *eventLogCollector) Name() string { return "windows-eventlog" }

func (e *eventLogCollector) Collect() ([]byte, error) {
	// placeholder generic collector returns a canonical event with sample message
	meta, _ := host.GetMetadata()
	hostname := "unknown"
	if meta != nil {
		hostname = meta.Hostname
	}
	site := os.Getenv("ARGUS_SITE_ID")
	if site == "" {
		site = os.Getenv("SITE_ID")
	}
	if site == "" {
		site = "site-a"
	}
	agent := os.Getenv("ARGUS_AGENT_ID")
	if agent == "" {
		agent = os.Getenv("AGENT_ID")
	}
	if agent == "" {
		agent = "agent-01"
	}
	ev := event.Event{
		EventID:   fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SiteID:    site,
		AgentID:   agent,
		EventType: "windows.eventlog.sample",
		Severity:  "low",
		Host:      hostname,
		Raw:       "sample windows eventlog placeholder",
	}
	if ev.Integrity == "" {
		ev.Integrity = ev.ComputeIntegrity()
	}
	return json.Marshal(ev)
}

func NewEventLogCollector() collector.Collector { return &eventLogCollector{} }
