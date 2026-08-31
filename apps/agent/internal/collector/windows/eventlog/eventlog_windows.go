//go:build windows
package eventlog

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

type winEventLogCollector struct{}

func (w *winEventLogCollector) Name() string { return "windows-eventlog-wevtutil" }

func (w *winEventLogCollector) Collect() ([]byte, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    cmd := exec.CommandContext(ctx, "wevtutil", "qe", "Security", "/c:50", "/f:text")
    out, err := cmd.Output()
    raw := ""
    if err != nil {
        raw = fmt.Sprintf("wevtutil query failed: %v", err)
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
        EventType: "windows.eventlog",
        Severity:  "low",
        Host:      hostname,
        Raw:       raw,
    }
    if ev.Integrity == "" {
        ev.Integrity = ev.ComputeIntegrity()
    }
    return json.Marshal(ev)
}

func NewEventLogCollector() collector.Collector { return &winEventLogCollector{} }
