package collector

import (
	"fmt"
	"sync"
)

// Collector is the minimal interface expected by the registry and pipeline.
type Collector interface {
	Name() string
	Collect() ([]byte, error)
}

// Registry keeps track of available collectors with a simple thread-safe registration map.
type Registry struct {
	mu         sync.RWMutex
	collectors map[string]Collector
}

// NewRegistry creates a new collector registry.
func NewRegistry() *Registry {
	return &Registry{collectors: make(map[string]Collector)}
}

// Register adds a collector under a unique name.
func (r *Registry) Register(c Collector) error {
	if c == nil {
		return fmt.Errorf("collector cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.collectors[c.Name()]; exists {
		return fmt.Errorf("collector already registered: %s", c.Name())
	}
	r.collectors[c.Name()] = c
	return nil
}

// Get returns a collector by name.
func (r *Registry) Get(name string) (Collector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.collectors[name]
	return c, ok
}

// Names returns registered collector names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.collectors))
	for name := range r.collectors {
		out = append(out, name)
	}
	return out
}

// Len returns the number of registered collectors.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.collectors)
}
