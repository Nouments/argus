package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// MockClickHouseWriter writes rows to a local file to simulate ClickHouse ingestion.
type MockClickHouseWriter struct {
	mu   sync.Mutex
	file *os.File
	path string
}

func NewMockClickHouseWriter(path string) (*MockClickHouseWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	return &MockClickHouseWriter{file: f, path: path}, nil
}

func (m *MockClickHouseWriter) WriteEvents(ctx context.Context, rows [][]byte) error {
	if m == nil || m.file == nil {
		return fmt.Errorf("writer closed")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rows {
		if _, err := m.file.Write(append(r, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockClickHouseWriter) Close() error {
	if m == nil || m.file == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.file.Close()
	m.file = nil
	return err
}

func (m *MockClickHouseWriter) Path() string {
	if m == nil {
		return ""
	}
	return m.path
}
