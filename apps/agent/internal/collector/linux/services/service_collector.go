package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/collector"
	"github.com/Nouments/argus/apps/agent/internal/event"
	"github.com/Nouments/argus/apps/agent/internal/host"
)

type servicesCollector struct{}

func (s *servicesCollector) Name() string { return "linux-services" }

func (s *servicesCollector) Collect() ([]byte, error) {
	// try systemctl to list running services (mockable runCmd)
	out, err := runCmd(5*time.Second, "systemctl", "list-units", "--type=service", "--state=running", "--no-legend")
	var raw string
	if err != nil {
		raw = fmt.Sprintf("error: %v", err)
	} else {
		raw = string(out)
	}
	if len(raw) > 100000 {
		raw = raw[:100000]
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

	ev := event.Event{
		EventID:   fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SiteID:    site,
		AgentID:   agent,
		EventType: "inventory.services",
		Severity:  "low",
		Host:      hostname,
		Raw:       raw,
	}
	if ev.Integrity == "" {
		ev.Integrity = ev.ComputeIntegrity()
	}
	return json.Marshal(ev)
}

func NewServicesCollector() collector.Collector { return &servicesCollector{} }

// runCmd is a package-level variable so tests can override it.
var runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
