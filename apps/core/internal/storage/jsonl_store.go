package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Nouments/argus/pkg/events"
)

type JSONLStore struct {
	mu   sync.Mutex
	file *os.File
	path string
}

func NewJSONLStore(path string) (*JSONLStore, error) {
	if path == "" {
		return nil, errors.New("jsonl store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open jsonl store: %w", err)
	}
	return &JSONLStore{file: file, path: path}, nil
}

func (s *JSONLStore) SaveEvent(ctx context.Context, ev events.Event) error {
	if s == nil || s.file == nil {
		return errors.New("jsonl store is closed")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	ev.EnsureIntegrity()
	if ev.ReceivedAt == "" {
		ev.StampReceivedAt(timeNow())
	}
	if err := ev.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

func (s *JSONLStore) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *JSONLStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}
