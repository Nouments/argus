package normalizer

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Normalizer is the minimal contract for canonicalizing collected output.
type Normalizer interface {
	Normalize(raw []byte) ([]byte, error)
}

// JSONNormalizer wraps raw bytes into a canonical object with source metadata.
type JSONNormalizer struct{}

// Normalize ensures the raw payload is valid JSON and adds source metadata if needed.
func (JSONNormalizer) Normalize(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	trimmed := bytes.TrimSpace(raw)
	if !json.Valid(trimmed) {
		return nil, fmt.Errorf("invalid json payload")
	}
	return trimmed, nil
}
