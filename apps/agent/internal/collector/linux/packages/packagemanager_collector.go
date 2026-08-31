package packages

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

type packageCollector struct{}

func (p *packageCollector) Name() string { return "linux-packages" }

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    cmd := exec.CommandContext(ctx, name, args...)
    out, err := cmd.CombinedOutput()
    return string(out), err
}

func (p *packageCollector) Collect() ([]byte, error) {
    results := map[string]string{}
    // check common package managers
    if out, err := runCmd(10*time.Second, "dpkg-query", "-W", "-f=${Package}@${Version}\\n"); err == nil {
        results["dpkg"] = out
    }
    if out, err := runCmd(10*time.Second, "rpm", "-qa", "--qf", "%{NAME}@%{VERSION}-%{RELEASE}\\n"); err == nil {
        results["rpm"] = out
    }
    if out, err := runCmd(10*time.Second, "pacman", "-Q"); err == nil {
        results["pacman"] = out
    }
    if out, err := runCmd(10*time.Second, "apk", "info", "-v"); err == nil {
        results["apk"] = out
    }
    if out, err := runCmd(10*time.Second, "snap", "list"); err == nil {
        results["snap"] = out
    }
    if out, err := runCmd(10*time.Second, "flatpak", "list", "--app"); err == nil {
        results["flatpak"] = out
    }
    if out, err := runCmd(10*time.Second, "dnf", "list", "installed"); err == nil {
        results["dnf"] = out
    }
    if out, err := runCmd(10*time.Second, "yum", "list", "installed"); err == nil {
        results["yum"] = out
    }
    if out, err := runCmd(10*time.Second, "brew", "list", "--versions"); err == nil {
        results["brew"] = out
    }
    // flatten into raw string and truncate
    combined := ""
    for k, v := range results {
        combined += fmt.Sprintf("--- %s ---\n%s\n", k, v)
    }
    if len(combined) > 100000 {
        combined = combined[:100000]
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
        EventType: "inventory.packages",
        Severity:  "low",
        Host:      hostname,
        Raw:       combined,
    }
    if ev.Integrity == "" {
        ev.Integrity = ev.ComputeIntegrity()
    }
    return json.Marshal(ev)
}

func NewPackageCollector() collector.Collector { return &packageCollector{} }
