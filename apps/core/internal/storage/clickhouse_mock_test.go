package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMockClickHouseWriter_WriteEvents(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "ch_mock.txt")
	w, err := NewMockClickHouseWriter(path)
	if err != nil {
		t.Fatalf("NewMockClickHouseWriter: %v", err)
	}
	defer w.Close()

	rows := [][]byte{[]byte("row1"), []byte("row2")}
	if err := w.WriteEvents(context.Background(), rows); err != nil {
		t.Fatalf("WriteEvents: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "row1") || !strings.Contains(s, "row2") {
		t.Fatalf("unexpected file contents: %s", s)
	}
}
