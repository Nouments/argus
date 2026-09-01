//go:build windows

package filesystem

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

type winFSCollector struct{}

func (w *winFSCollector) Name() string { return "windows-filesystem" }

func (w *winFSCollector) Collect() ([]byte, error) {
	// list recently modified files in C:\Windows and C:\Users
	out, err := runCmd(10*time.Second, "powershell", "-Command", "Get-ChildItem -Path C:\\Windows,C:\\Users -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Select-Object FullName | ConvertTo-Json -Depth 1")
	raw := ""
	if err != nil {
		raw = fmt.Sprintf("find recent files failed: %v", err)
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

	payload := map[string]any{"source": "windows.filesystem", "recent": raw}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ev := event.Event{
		EventID:   fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SiteID:    site,
		AgentID:   agent,
		EventType: "inventory.filesystem",
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

func NewFilesystemCollector() collector.Collector { return &winFSCollector{} }
