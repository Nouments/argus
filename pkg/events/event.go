package events

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

const DefaultMaxRawBytes = 1024 * 1024

var eventTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Event is the canonical security event exchanged inside Argus.
type Event struct {
	EventID       string            `json:"event_id"`
	Timestamp     string            `json:"timestamp"`
	SiteID        string            `json:"site_id"`
	AgentID       string            `json:"agent_id"`
	EventType     string            `json:"event_type"`
	Severity      string            `json:"severity"`
	Host          string            `json:"host"`
	User          string            `json:"user,omitempty"`
	SrcIP         string            `json:"src_ip,omitempty"`
	DstIP         string            `json:"dst_ip,omitempty"`
	Raw           string            `json:"raw"`
	Normalized    map[string]any    `json:"normalized,omitempty"`
	Enrichment    map[string]any    `json:"enrichment,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	IntegrityHash string            `json:"integrity_hash,omitempty"`
	ReceivedAt    string            `json:"received_at,omitempty"`
}

// Normalize trims noisy input and canonicalizes fields that drive routing.
func (e *Event) Normalize() {
	if e == nil {
		return
	}
	e.EventID = strings.TrimSpace(e.EventID)
	e.Timestamp = strings.TrimSpace(e.Timestamp)
	e.SiteID = strings.TrimSpace(e.SiteID)
	e.AgentID = strings.TrimSpace(e.AgentID)
	e.EventType = strings.ToLower(strings.TrimSpace(e.EventType))
	e.Severity = strings.ToLower(strings.TrimSpace(e.Severity))
	e.Host = strings.TrimSpace(e.Host)
	e.User = strings.TrimSpace(e.User)
	e.SrcIP = strings.TrimSpace(e.SrcIP)
	e.DstIP = strings.TrimSpace(e.DstIP)
	e.IntegrityHash = strings.TrimSpace(e.IntegrityHash)
	e.ReceivedAt = strings.TrimSpace(e.ReceivedAt)
}

// Validate checks the minimal schema required before storage or detection.
func (e *Event) Validate() error {
	if e == nil {
		return errors.New("event is nil")
	}
	e.Normalize()
	if e.EventID == "" {
		return errors.New("event_id is required")
	}
	if e.Timestamp == "" {
		return errors.New("timestamp is required")
	}
	if _, err := time.Parse(time.RFC3339, e.Timestamp); err != nil {
		return fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	if e.SiteID == "" {
		return errors.New("site_id is required")
	}
	if e.AgentID == "" {
		return errors.New("agent_id is required")
	}
	if !eventTypePattern.MatchString(e.EventType) {
		return fmt.Errorf("event_type %q must match domain.action format", e.EventType)
	}
	if !ValidSeverity(e.Severity) {
		return fmt.Errorf("severity %q is invalid", e.Severity)
	}
	if e.Host == "" {
		return errors.New("host is required")
	}
	if strings.TrimSpace(e.Raw) == "" {
		return errors.New("raw is required")
	}
	if len(e.Raw) > DefaultMaxRawBytes {
		return fmt.Errorf("raw exceeds %d bytes", DefaultMaxRawBytes)
	}
	if err := validateOptionalIP("src_ip", e.SrcIP); err != nil {
		return err
	}
	if err := validateOptionalIP("dst_ip", e.DstIP); err != nil {
		return err
	}
	if e.ReceivedAt != "" {
		if _, err := time.Parse(time.RFC3339, e.ReceivedAt); err != nil {
			return fmt.Errorf("received_at must be RFC3339: %w", err)
		}
	}
	return nil
}

func ValidSeverity(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func validateOptionalIP(field, value string) error {
	if value == "" {
		return nil
	}
	if _, err := netip.ParseAddr(value); err != nil {
		return fmt.Errorf("%s must be a valid IP address: %w", field, err)
	}
	return nil
}

// ComputeIntegrity returns a deterministic SHA-256 integrity marker for the event.
func (e *Event) ComputeIntegrity() string {
	if e == nil {
		return ""
	}
	h := sha256.New()
	_, _ = h.Write([]byte(e.EventID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(e.Timestamp))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(e.SiteID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(e.AgentID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(e.Raw))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// EnsureIntegrity computes the integrity hash when the producer did not send one.
func (e *Event) EnsureIntegrity() {
	if e == nil {
		return
	}
	e.Normalize()
	if e.IntegrityHash == "" {
		e.IntegrityHash = e.ComputeIntegrity()
	}
}

func (e *Event) StampReceivedAt(now time.Time) {
	if e == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	e.ReceivedAt = now.UTC().Format(time.RFC3339)
}

func FromJSON(data []byte) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, err
	}
	ev.EnsureIntegrity()
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	return &ev, nil
}
