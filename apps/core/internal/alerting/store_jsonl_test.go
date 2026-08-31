package alerting

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJSONLAlertStore_SaveAlert(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "alerts.jsonl")
	store, err := NewJSONLAlertStore(path)
	if err != nil {
		t.Fatalf("NewJSONLAlertStore: %v", err)
	}
	defer store.Close()

	alert := NewAlert("R1", "rname", "high", "gk", 5, alertEvent(), time.Now())
	if err := store.SaveAlert(context.Background(), alert); err != nil {
		t.Fatalf("SaveAlert error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !strings.Contains(string(data), alert.AlertID) {
		t.Fatalf("expected file to contain alert id %s", alert.AlertID)
	}
}
