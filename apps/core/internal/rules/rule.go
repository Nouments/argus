package rules

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Nouments/argus/pkg/events"
)

type Rule struct {
	ID        string
	Name      string
	Severity  string
	Match     Match
	GroupBy   []string
	Threshold Threshold
	Actions   []string
}

type Match struct {
	EventType string
	Severity  string
	AgentID   string
	SiteID    string
	Host      string
	User      string
	SrcIP     string
	DstIP     string
}

type Threshold struct {
	Count  int
	Window time.Duration
}

func (r Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return errors.New("rule id is required")
	}
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("rule name is required")
	}
	if !events.ValidSeverity(r.Severity) {
		return fmt.Errorf("rule severity %q is invalid", r.Severity)
	}
	if strings.TrimSpace(r.Match.EventType) == "" {
		return errors.New("match event_type is required")
	}
	if r.Match.Severity != "" && !events.ValidSeverity(r.Match.Severity) {
		return fmt.Errorf("match severity %q is invalid", r.Match.Severity)
	}
	if r.Threshold.Count <= 0 {
		return errors.New("threshold count must be greater than zero")
	}
	if r.Threshold.Window <= 0 {
		return errors.New("threshold window must be greater than zero")
	}
	for _, field := range r.GroupBy {
		if !validGroupField(field) {
			return fmt.Errorf("unsupported group_by field %q", field)
		}
	}
	return nil
}

func (r Rule) Matches(ev events.Event) bool {
	ev.Normalize()
	return matchPattern(r.Match.EventType, ev.EventType) &&
		matchPattern(r.Match.Severity, ev.Severity) &&
		matchPattern(r.Match.AgentID, ev.AgentID) &&
		matchPattern(r.Match.SiteID, ev.SiteID) &&
		matchPattern(r.Match.Host, ev.Host) &&
		matchPattern(r.Match.User, ev.User) &&
		matchPattern(r.Match.SrcIP, ev.SrcIP) &&
		matchPattern(r.Match.DstIP, ev.DstIP)
}

func (r Rule) GroupKey(ev events.Event) string {
	if len(r.GroupBy) == 0 {
		return r.ID
	}
	parts := make([]string, 0, len(r.GroupBy))
	for _, field := range r.GroupBy {
		parts = append(parts, field+"="+fieldValue(field, ev))
	}
	return strings.Join(parts, "|")
}

func matchPattern(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" || pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == value
}

func fieldValue(field string, ev events.Event) string {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "event_id":
		return ev.EventID
	case "site_id":
		return ev.SiteID
	case "agent_id":
		return ev.AgentID
	case "event_type":
		return ev.EventType
	case "severity":
		return ev.Severity
	case "host":
		return ev.Host
	case "user":
		return ev.User
	case "src_ip":
		return ev.SrcIP
	case "dst_ip":
		return ev.DstIP
	default:
		return ""
	}
}

func validGroupField(field string) bool {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "event_id", "site_id", "agent_id", "event_type", "severity", "host", "user", "src_ip", "dst_ip":
		return true
	default:
		return false
	}
}
