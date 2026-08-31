package windows

import (
	"encoding/json"
	"fmt"

	"github.com/Nouments/argus/apps/agent/internal/collector"
)

// sampleCollector is a minimal Windows collector used as a placeholder for real implementations.
type sampleCollector struct{}

func (s *sampleCollector) Name() string { return "windows-sample" }

func (s *sampleCollector) Collect() ([]byte, error) {
	payload := map[string]string{"message": "windows sample collector", "source": "windows"}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal sample: %w", err)
	}
	return b, nil
}

// NewSampleCollector returns a new sample collector instance.
func NewSampleCollector() collector.Collector { return &sampleCollector{} }
