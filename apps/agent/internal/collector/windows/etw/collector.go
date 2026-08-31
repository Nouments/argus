//go:build !windows
package etw

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/collector"
	"github.com/Nouments/argus/apps/agent/internal/event"
	"github.com/Nouments/argus/apps/agent/internal/host"
)

// Placeholder: ETW collector.
type etwCollector struct{}

func (e *etwCollector) Name() string { return "windows-etw" }

func (e *etwCollector) Collect() ([]byte, error) {
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
		EventType: "windows.etw.sample",
		Severity:  "low",
		Host:      hostname,
		Raw:       "etw placeholder",
	}
	if ev.Integrity == "" {
		ev.Integrity = ev.ComputeIntegrity()
	}
	return json.Marshal(ev)
}

func NewETWCollector() collector.Collector { return &etwCollector{} }
