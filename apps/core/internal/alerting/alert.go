package alerting

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Nouments/argus/pkg/events"
)

const (
	StatusOpen     = "open"
	StatusResolved = "resolved"
)

type Alert struct {
	AlertID   string `json:"alert_id"`
	RuleID    string `json:"rule_id"`
	RuleName  string `json:"rule_name"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	EventID   string `json:"event_id"`
	SiteID    string `json:"site_id"`
	AgentID   string `json:"agent_id"`
	Host      string `json:"host"`
	EventType string `json:"event_type"`
	GroupKey  string `json:"group_key"`
	Count     int    `json:"count"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

type Manager struct {
	mu     sync.RWMutex
	alerts []Alert
}

func NewManager() *Manager {
	return &Manager{}
}

func NewAlert(ruleID, ruleName, severity, groupKey string, count int, ev events.Event, now time.Time) Alert {
	if now.IsZero() {
		now = time.Now()
	}
	alert := Alert{
		RuleID:    ruleID,
		RuleName:  ruleName,
		Severity:  severity,
		Status:    StatusOpen,
		EventID:   ev.EventID,
		SiteID:    ev.SiteID,
		AgentID:   ev.AgentID,
		Host:      ev.Host,
		EventType: ev.EventType,
		GroupKey:  groupKey,
		Count:     count,
		Message:   fmt.Sprintf("%s matched %d event(s)", ruleName, count),
		CreatedAt: now.UTC().Format(time.RFC3339),
	}
	alert.AlertID = alert.computeID()
	return alert
}

func (a Alert) Validate() error {
	if a.AlertID == "" {
		return errors.New("alert_id is required")
	}
	if a.RuleID == "" {
		return errors.New("rule_id is required")
	}
	if !events.ValidSeverity(a.Severity) {
		return fmt.Errorf("severity %q is invalid", a.Severity)
	}
	if a.Status != StatusOpen && a.Status != StatusResolved {
		return fmt.Errorf("status %q is invalid", a.Status)
	}
	if a.EventID == "" {
		return errors.New("event_id is required")
	}
	if a.SiteID == "" {
		return errors.New("site_id is required")
	}
	if a.AgentID == "" {
		return errors.New("agent_id is required")
	}
	if a.Host == "" {
		return errors.New("host is required")
	}
	if a.EventType == "" {
		return errors.New("event_type is required")
	}
	if a.CreatedAt == "" {
		return errors.New("created_at is required")
	}
	if _, err := time.Parse(time.RFC3339, a.CreatedAt); err != nil {
		return fmt.Errorf("created_at must be RFC3339: %w", err)
	}
	return nil
}

func (m *Manager) SaveAlert(ctx context.Context, alert Alert) error {
	if m == nil {
		return errors.New("alert manager is nil")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := alert.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, alert)
	return nil
}

func (m *Manager) ListAlerts() []Alert {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Alert, len(m.alerts))
	copy(out, m.alerts)
	return out
}

func (a Alert) computeID() string {
	h := sha256.New()
	_, _ = h.Write([]byte(a.RuleID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(a.GroupKey))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(a.EventID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(a.CreatedAt))
	return "alt-" + hex.EncodeToString(h.Sum(nil))[:24]
}
