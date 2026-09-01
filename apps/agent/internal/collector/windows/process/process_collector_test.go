package process

import (
	"encoding/json"
	"testing"
)

func TestProcessCollector(t *testing.T) {
	c := NewProcessCollectorWindows()
	b, err := c.Collect()
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["source"] != "windows.process" {
		t.Fatalf("unexpected source: %v", m["source"])
	}
	if _, ok := m["process_count"]; !ok {
		t.Fatalf("process_count missing")
	}
}
