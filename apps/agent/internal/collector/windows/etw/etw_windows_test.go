//go:build windows
package etw

import (
    "encoding/json"
    "testing"
    "time"
)

func TestETWCollector_WithMockedRunCmd(t *testing.T) {
    orig := runCmd
    defer func() { runCmd = orig }()

    runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
        return "Application\nSecurity\nSystem\n", nil
    }

    e := &etwWinCollector{}
    b, err := e.Collect()
    if err != nil {
        t.Fatalf("collect failed: %v", err)
    }
    var ev map[string]interface{}
    if err := json.Unmarshal(b, &ev); err != nil {
        t.Fatalf("unmarshal event: %v", err)
    }
    if ev["event_type"] != "windows.etw" {
        t.Fatalf("unexpected event_type: %v", ev["event_type"])
    }
}
