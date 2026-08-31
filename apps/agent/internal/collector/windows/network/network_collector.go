package network

import (
	"encoding/json"
	"fmt"

	"github.com/Nouments/argus/apps/agent/internal/collector"
)

type networkCollector struct{}

func (n *networkCollector) Name() string { return "windows-network" }

func (n *networkCollector) Collect() ([]byte, error) {
	payload := map[string]any{"source": "windows.network", "connections": 3}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal network: %w", err)
	}
	return b, nil
}

func NewNetworkCollector() collector.Collector { return &networkCollector{} }
