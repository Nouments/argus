package logs

import (
	"testing"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/event"
)

func TestSyslogCollectorProducesValidEvent(t *testing.T) {
	// mock runCmd to return a small syslog fragment
	runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
		return "Aug 30 12:00:00 host app[123]: test message", nil
	}
	c := NewSyslogCollector()
	b, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	ev, err := event.FromJSON(b)
	if err != nil {
		t.Fatalf("FromJSON() error: %v", err)
	}
	if ev.EventType != "logs.syslog" {
		t.Fatalf("event type = %q, want logs.syslog", ev.EventType)
	}
}

// additional test for ParseSyslogLine if helper exists
func TestParseSyslogLine(t *testing.T) {
	entry, err := ParseSyslogLine("Aug 21 12:34:56 host sshd[123]: Failed password for invalid user root from 1.2.3.4")
	if err != nil {
		t.Fatalf("ParseSyslogLine returned error: %v", err)
	}
	if entry.Host != "host" {
		t.Fatalf("ParseSyslogLine host = %q, want %q", entry.Host, "host")
	}
	if entry.Program != "sshd" {
		t.Fatalf("ParseSyslogLine program = %q, want %q", entry.Program, "sshd")
	}
	if entry.Message == "" {
		t.Fatal("ParseSyslogLine message should not be empty")
	}
}
