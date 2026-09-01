package logs

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/collector"
	"github.com/Nouments/argus/apps/agent/internal/event"
	"github.com/Nouments/argus/apps/agent/internal/host"
)

type syslogCollector struct{}

func (s *syslogCollector) Name() string { return "linux-syslog" }

func (s *syslogCollector) Collect() ([]byte, error) {
	// try common syslog locations
	var out string
	if b, err := runCmd(5*time.Second, "tail", "-n", "200", "/var/log/syslog"); err == nil {
		out = b
	} else if b, err := runCmd(5*time.Second, "tail", "-n", "200", "/var/log/messages"); err == nil {
		out = b
	} else {
		out = fmt.Sprintf("syslog read error: %v", "no readable syslog found")
	}
	if len(out) > 200000 {
		out = out[:200000]
	}

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

	payload := map[string]any{"source": "linux.syslog", "tail": out}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	ev := event.Event{
		EventID:   fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SiteID:    site,
		AgentID:   agent,
		EventType: "logs.syslog",
		Severity:  "low",
		Host:      hostname,
		Raw:       string(b),
	}
	if ev.Integrity == "" {
		ev.Integrity = ev.ComputeIntegrity()
	}
	return json.Marshal(ev)
}

// syslog reuses package-level runCmd declared in journal.go

func NewSyslogCollector() collector.Collector { return &syslogCollector{} }
