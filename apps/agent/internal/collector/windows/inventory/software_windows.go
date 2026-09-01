//go:build windows

package inventory

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

type winSoftwareCollector struct{}

func (w *winSoftwareCollector) Name() string { return "windows-software" }

func (w *winSoftwareCollector) Collect() ([]byte, error) {
	// use PowerShell to list installed programs
	out, err := runCmd(10*time.Second, "powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Depth 1")
	raw := ""
	if err != nil {
		raw = fmt.Sprintf("list software failed: %v", err)
	} else {
		raw = out
	}
	if len(raw) > 200000 {
		raw = raw[:200000]
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

	payload := map[string]any{"source": "windows.software", "software": raw}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ev := event.Event{
		EventID:   fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SiteID:    site,
		AgentID:   agent,
		EventType: "inventory.software",
		Severity:  "low",
		Host:      hostname,
		Raw:       string(b),
	}
	if ev.Integrity == "" {
		ev.Integrity = ev.ComputeIntegrity()
	}
	return json.Marshal(ev)
}

var runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func NewSoftwareCollector() collector.Collector { return &winSoftwareCollector{} }
