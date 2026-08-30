package event

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Event represents a minimal canonical event used by the MVP
type Event struct {
	EventID   string `json:"event_id"`
	Timestamp string `json:"timestamp"`
	SiteID    string `json:"site_id"`
	AgentID   string `json:"agent_id"`
	EventType string `json:"event_type"`
	Severity  string `json:"severity"`
	Host      string `json:"host"`
	User      string `json:"user,omitempty"`
	SrcIP     string `json:"src_ip,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	Raw       string `json:"raw"`
	Integrity string `json:"integrity_hash,omitempty"`
}

// Validate checks required fields and timestamp format.
func (e *Event) Validate() error {
	if strings.TrimSpace(e.EventID) == "" || strings.TrimSpace(e.Timestamp) == "" || strings.TrimSpace(e.SiteID) == "" || strings.TrimSpace(e.EventType) == "" || strings.TrimSpace(e.Severity) == "" || strings.TrimSpace(e.Host) == "" || strings.TrimSpace(e.AgentID) == "" || strings.TrimSpace(e.Raw) == "" {
		return errors.New("missing required field")
	}
	if _, err := time.Parse(time.RFC3339, e.Timestamp); err != nil {
		return errors.New("invalid timestamp")
	}
	switch strings.ToLower(strings.TrimSpace(e.Severity)) {
	case "low", "medium", "high", "critical":
		return nil
	default:
		return fmt.Errorf("invalid severity: %q", e.Severity)
	}
}

// ComputeIntegrity computes sha256 over event_id + raw
func (e *Event) ComputeIntegrity() string {
	h := sha256.New()
	h.Write([]byte(e.EventID))
	h.Write([]byte(e.Raw))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// FromJSON decodes JSON into Event and computes integrity if missing
func FromJSON(b []byte) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(b, &ev); err != nil {
		return nil, err
	}
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	if ev.Integrity == "" {
		ev.Integrity = ev.ComputeIntegrity()
	}
	return &ev, nil
}
