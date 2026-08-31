package packages

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "os/exec"
    "strings"
    "time"

    "github.com/Nouments/argus/apps/agent/internal/collector"
    "github.com/Nouments/argus/apps/agent/internal/event"
    "github.com/Nouments/argus/apps/agent/internal/host"
)

type packageCollector struct{}

func (p *packageCollector) Name() string { return "linux-packages" }

var runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
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
    // parse into structured packages
    pkgs := parsePackageOutputs(results)

    payloadObj := map[string]any{"source": "linux.packages", "packages": pkgs}
    b, err := json.Marshal(payloadObj)
    if err != nil {
        return nil, err
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
        Raw:       string(b),
    }
    ev.Integrity = ev.ComputeIntegrity()
    return json.Marshal(ev)
}

// Package represents a discovered package record.
type Package struct {
    Name    string `json:"name"`
    Version string `json:"version"`
    Source  string `json:"source"`
}

// parsePackageOutputs attempts to extract package name/version pairs from
// the raw outputs of various package manager commands.
func parsePackageOutputs(results map[string]string) []Package {
    pkgs := make([]Package, 0)
    for src, out := range results {
        lines := splitLines(out)
        for _, l := range lines {
            if l == "" {
                continue
            }
            var name, ver string
            switch src {
            case "dpkg":
                // format: name@version
                if i := strings.Index(l, "@"); i >= 0 {
                    name = l[:i]
                    ver = l[i+1:]
                }
            case "rpm":
                if i := strings.Index(l, "@"); i >= 0 {
                    name = l[:i]
                    ver = l[i+1:]
                }
            case "pacman":
                parts := strings.Fields(l)
                if len(parts) >= 2 {
                    name = parts[0]
                    ver = parts[1]
                }
            case "apk":
                if i := strings.LastIndex(l, "-"); i >= 0 {
                    name = l[:i]
                    ver = l[i+1:]
                }
            case "dnf", "yum":
                parts := strings.Fields(l)
                if len(parts) >= 2 {
                    n := parts[0]
                    if j := strings.LastIndex(n, "."); j >= 0 {
                        name = n[:j]
                    } else {
                        name = n
                    }
                    ver = parts[1]
                }
            case "brew":
                parts := strings.Fields(l)
                if len(parts) >= 2 {
                    name = parts[0]
                    ver = parts[1]
                }
            case "snap":
                parts := strings.Fields(l)
                if len(parts) >= 2 && parts[0] != "Name" {
                    name = parts[0]
                    ver = parts[1]
                }
            case "flatpak":
                parts := strings.Fields(l)
                if len(parts) >= 2 {
                    name = parts[0]
                    ver = parts[1]
                }
            default:
                name = l
                ver = ""
            }
            if name == "" {
                continue
            }
            pkgs = append(pkgs, Package{Name: name, Version: ver, Source: src})
        }
    }
    return pkgs
}

func splitLines(s string) []string { return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") }

func NewPackageCollector() collector.Collector { return &packageCollector{} }
