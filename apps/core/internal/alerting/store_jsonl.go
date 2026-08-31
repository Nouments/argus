package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"time"
)

// JSONLAlertStore persists alerts as one JSON object per line.
type JSONLAlertStore struct {
	mu   sync.Mutex
	file *os.File
	path string
}

func NewJSONLAlertStore(path string) (*JSONLAlertStore, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	return &JSONLAlertStore{file: f, path: path}, nil
}

func (s *JSONLAlertStore) SaveAlert(ctx context.Context, a Alert) error {
	if s == nil || s.file == nil {
		return errors.New("alert store is closed")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := a.Validate(); err != nil {
		return err
	}
	if a.CreatedAt == "" {
		a.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	payload, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write alert: %w", err)
	}
	return nil
}

func (s *JSONLAlertStore) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *JSONLAlertStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}
