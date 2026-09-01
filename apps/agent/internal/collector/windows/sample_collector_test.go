package windows

import (
	"encoding/json"
	"testing"
)

func TestSampleCollector(t *testing.T) {
	c := NewSampleCollector()
	b, err := c.Collect()
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["message"] != "windows sample collector" {
		t.Fatalf("unexpected message: %v", m["message"])
	}
	if m["source"] != "windows" {
		t.Fatalf("unexpected source: %v", m["source"])
	}
}
