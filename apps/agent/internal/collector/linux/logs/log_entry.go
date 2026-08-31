package logs

import (
	"fmt"
	"strings"
	"time"
)

// LogEntry represents a normalized Linux log line.
type LogEntry struct {
	Timestamp time.Time
	Host      string
	Program   string
	PID       int
	Message   string
	Raw       string
}

// ParseSyslogLine parses a minimal RFC3339-like syslog style line.
func ParseSyslogLine(line string) (LogEntry, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return LogEntry{}, fmt.Errorf("empty log line")
	}

	parts := strings.Fields(trimmed)
	if len(parts) < 6 {
		return LogEntry{}, fmt.Errorf("log line too short: %q", trimmed)
	}

	entry := LogEntry{
		Raw:     trimmed,
		Host:    parts[3],
		Program: strings.TrimSuffix(parts[4], ":"),
		Message: strings.TrimSpace(strings.Join(parts[5:], " ")),
	}
	if strings.Contains(entry.Program, "[") && strings.Contains(entry.Program, "]") {
		entry.Program = strings.Split(entry.Program, "[")[0]
	}
	entry.Timestamp = time.Now().UTC()
	return entry, nil
}
