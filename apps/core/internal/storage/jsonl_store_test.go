package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nouments/argus/pkg/events"
)

func storageValidEvent(id string) events.Event {
	return events.Event{
		EventID:   id,
		Timestamp: "2026-08-30T12:00:00Z",
		SiteID:    "site-a",
		AgentID:   "agent-01",
		EventType: "auth.failure",
		Severity:  "medium",
		Host:      "srv-01",
		Raw:       "failed password",
	}
}

func TestJSONLStoreSaveEventWritesOneLine(t *testing.T) {
	oldNow := timeNow
	timeNow = func() time.Time {
		return time.Date(2026, 8, 30, 12, 1, 2, 0, time.UTC)
	}
	defer func() { timeNow = oldNow }()

	path := filepath.Join(t.TempDir(), "events", "events.jsonl")
	store, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.SaveEvent(context.Background(), storageValidEvent("evt-1")); err != nil {
		t.Fatalf("SaveEvent() error: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatal("expected one JSONL row")
	}
	var got events.Event
	if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if got.EventID != "evt-1" {
		t.Fatalf("EventID = %q, want evt-1", got.EventID)
	}
	if got.IntegrityHash == "" {
		t.Fatal("SaveEvent() should compute integrity")
	}
	if got.ReceivedAt != "2026-08-30T12:01:02Z" {
		t.Fatalf("ReceivedAt = %q, want deterministic received timestamp", got.ReceivedAt)
	}
	if scanner.Scan() {
		t.Fatal("expected exactly one JSONL row")
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("Scanner error: %v", err)
	}
}

func TestJSONLStoreRejectsInvalidEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	store, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	ev := storageValidEvent("evt-2")
	ev.Severity = "urgent"
	if err := store.SaveEvent(context.Background(), ev); err == nil {
		t.Fatal("SaveEvent() should reject invalid events")
	}
}

func TestJSONLStoreHonorsCanceledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	store, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.SaveEvent(ctx, storageValidEvent("evt-3")); err == nil {
		t.Fatal("SaveEvent() should return context error")
	}
}
