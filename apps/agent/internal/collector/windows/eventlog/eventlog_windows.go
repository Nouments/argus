//go:build windows

package eventlog

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

type winEventLogCollector struct{}

func (w *winEventLogCollector) Name() string { return "windows-eventlog-wevtutil" }

func (w *winEventLogCollector) Collect() ([]byte, error) {
	out, err := runCmd(5*time.Second, "wevtutil", "qe", "Security", "/c:50", "/f:text")
	raw := ""
	if err != nil {
		raw = fmt.Sprintf("wevtutil query failed: %v", err)
	} else {
		// normalize into records separated by blank lines
		s := strings.ReplaceAll(out, "\r\n", "\n")
		parts := strings.Split(s, "\n\n")
		records := make([]map[string]string, 0, len(parts))
		for _, p := range parts {
			if strings.TrimSpace(p) == "" {
				continue
			}
			records = append(records, map[string]string{"raw": p})
		}
		payloadObj := map[string]any{"source": "windows.eventlog", "records": records}
		if b, err := json.Marshal(payloadObj); err == nil {
			raw = string(b)
		} else {
			raw = out
		}
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

// runCmd is a package-level variable so tests can override it.
var runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
