package security

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

type auditCollector struct{}

func (a *auditCollector) Name() string { return "linux-audit" }

func (a *auditCollector) Collect() ([]byte, error) {
	out, err := runCmd(5*time.Second, "ausearch", "-ts", "today")
	if err != nil {
		// fallback to auditctl -l
		if o2, err2 := runCmd(3*time.Second, "auditctl", "-l"); err2 == nil {
			out = o2
		} else {
			out = fmt.Sprintf("audit read error: %v", err)
		}
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

	payload := map[string]any{"source": "linux.audit", "audit": out}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ev := event.Event{
		EventID:   fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SiteID:    site,
		AgentID:   agent,
		EventType: "security.audit",
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

func NewAuditCollector() collector.Collector { return &auditCollector{} }
