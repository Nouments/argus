package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// AppendJSONLine appends a JSON-encoded value as a newline to file
func AppendJSONLine(dir, filename string, v interface{}) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, filename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// ClickHouseWriteMock appends an event JSON to a local mock file (simulates writing to ClickHouse)
func ClickHouseWriteMock(dir, filename string, data []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	fpath := filepath.Join(dir, filename)
	f, err := os.OpenFile(fpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}
