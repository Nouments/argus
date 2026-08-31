package services

import (
	"encoding/json"
	"testing"
	"time"
)

func TestServicesCollector_WithMockedRunCmd(t *testing.T) {
	orig := runCmd
	defer func() { runCmd = orig }()

	// simulate systemctl output
	runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
		return "sshd.service sshd.service loaded active running OpenSSH Daemon\nnginx.service nginx.service loaded active running A high performance web server\n", nil
	}

	s := &servicesCollector{}
	b, err := s.Collect()
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	var ev map[string]interface{}
	if err := json.Unmarshal(b, &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev["event_type"] != "inventory.services" {
		t.Fatalf("unexpected event_type: %v", ev["event_type"])
	}
}
