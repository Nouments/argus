//go:build windows
package etw

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

type etwWinCollector struct{}

func (e *etwWinCollector) Name() string { return "windows-etw" }

func (e *etwWinCollector) Collect() ([]byte, error) {
    out, err := runCmd(3*time.Second, "wevtutil", "el")
    raw := ""
    if err != nil {
        raw = fmt.Sprintf("wevtutil list channels failed: %v", err)
    } else {
        raw = out
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
        EventType: "windows.etw",
        Severity:  "low",
        Host:      hostname,
        Raw:       raw,
    }
    if ev.Integrity == "" {
        ev.Integrity = ev.ComputeIntegrity()
    }
    return json.Marshal(ev)
}

func NewETWCollector() collector.Collector { return &etwWinCollector{} }

// runCmd is a package-level variable so tests can override it.
var runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    cmd := exec.CommandContext(ctx, name, args...)
    out, err := cmd.CombinedOutput()
    return string(out), err
}
