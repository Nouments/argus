package process

import (
	"encoding/json"
	"fmt"

	"github.com/Nouments/argus/apps/agent/internal/collector"
)

type processCollector struct{}

func (p *processCollector) Name() string { return "windows-process" }

func (p *processCollector) Collect() ([]byte, error) {
	payload := map[string]any{"source": "windows.process", "process_count": 42}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal process: %w", err)
	}
	return b, nil
}

func NewProcessCollector() collector.Collector { return &processCollector{} }
