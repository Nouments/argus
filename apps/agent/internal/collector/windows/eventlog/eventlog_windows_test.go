//go:build windows
package eventlog

import (
    "encoding/json"
    "testing"
    "time"
)

func TestEventLogCollector_WithMockedRunCmd(t *testing.T) {
    orig := runCmd
    defer func() { runCmd = orig }()

    runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
        return "Record1\nRecord2\n", nil
    }

    w := &winEventLogCollector{}
    b, err := w.Collect()
    if err != nil {
        t.Fatalf("collect failed: %v", err)
    }
    var ev map[string]interface{}
    if err := json.Unmarshal(b, &ev); err != nil {
        t.Fatalf("unmarshal event: %v", err)
    }
    if ev["event_type"] != "windows.eventlog" {
        t.Fatalf("unexpected event_type: %v", ev["event_type"])
    }
}
