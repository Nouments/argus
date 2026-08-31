package network

import (
    "encoding/json"
    "testing"
)

func TestNetworkCollector(t *testing.T) {
    c := NewNetworkCollector()
    b, err := c.Collect()
    if err != nil {
        t.Fatalf("collect failed: %v", err)
    }
    var m map[string]interface{}
    if err := json.Unmarshal(b, &m); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if m["source"] != "windows.network" {
        t.Fatalf("unexpected source: %v", m["source"])
    }
    if _, ok := m["connections"]; !ok {
        t.Fatalf("connections field missing")
    }
}
