package filesystem

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/collector"
	"github.com/Nouments/argus/apps/agent/internal/event"
	"github.com/Nouments/argus/apps/agent/internal/host"
)

type fsCollector struct{}

func (f *fsCollector) Name() string { return "linux-filesystem" }

func (f *fsCollector) Collect() ([]byte, error) {
	// Find files modified in the last 24 hours under /etc and /var/log
	out, err := runCmd(10*time.Second, "bash", "-lc", "find /etc /var/log -type f -mtime -1 2>/dev/null | head -n 100")
	if err != nil {
		out = fmt.Sprintf("find error: %v", err)
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

	payload := map[string]any{"source": "linux.filesystem", "recent": out}
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
	cmd := exec.Command(name, args...)
	b, err := cmd.CombinedOutput()
	return string(b), err
}

func NewFilesystemCollector() collector.Collector { return &fsCollector{} }
