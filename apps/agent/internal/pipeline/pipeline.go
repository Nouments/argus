package pipeline

import (
	"fmt"
	"sync"

	"github.com/Nouments/argus/apps/agent/internal/collector"
	"github.com/Nouments/argus/apps/agent/internal/normalizer"
)

// Payload is the normalized output passed to the buffer side.
type Payload struct {
	Source string
	Raw    []byte
}

// Pipeline coordinates collectors, normalizers, and output writing.
type Pipeline struct {
	mu       sync.RWMutex
	registry *collector.Registry
	normal   normalizer.Normalizer
}

// Normalizer is the interface used by the pipeline.
type Normalizer interface {
	Normalize(raw []byte) ([]byte, error)
}

// New creates a minimal pipeline with a registry and a normalizer.
func New(registry *collector.Registry, n Normalizer) *Pipeline {
	if registry == nil {
		registry = collector.NewRegistry()
	}
	return &Pipeline{registry: registry, normal: n}
}

// Register adds a collector to the registry.
func (p *Pipeline) Register(c collector.Collector) error {
	if p == nil || p.registry == nil {
		return fmt.Errorf("pipeline has no registry")
	}
	return p.registry.Register(c)
}

// Process runs all registered collectors, normalizes payloads, and returns them.
func (p *Pipeline) Process() ([]Payload, error) {
	if p == nil || p.registry == nil {
		return nil, fmt.Errorf("pipeline has no registry")
	}
	items := make([]Payload, 0, p.registry.Len())
	for _, name := range p.registry.Names() {
		c, ok := p.registry.Get(name)
		if !ok || c == nil {
			continue
		}
		raw, err := c.Collect()
		if err != nil {
			return nil, fmt.Errorf("collect %s: %w", name, err)
		}
		if p.normal == nil {
			items = append(items, Payload{Source: name, Raw: raw})
			continue
		}
		norm, err := p.normal.Normalize(raw)
		if err != nil {
			return nil, fmt.Errorf("normalize %s: %w", name, err)
		}
		items = append(items, Payload{Source: name, Raw: norm})
	}
	return items, nil
}
