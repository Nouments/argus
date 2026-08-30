package transport

import (
	"sync"
)

// Transport is the minimal abstraction for sending event envelopes to a remote gateway.
type Transport interface {
	Send(*EventEnvelope) error
}

// InMemoryTransport is a local transport implementation used for tests and local orchestration.
type InMemoryTransport struct {
	mu     sync.Mutex
	items  []*EventEnvelope
	closed bool
}

// Send stores the event envelope in memory for later inspection.
func (t *InMemoryTransport) Send(msg *EventEnvelope) error {
	if msg == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.items = append(t.items, msg)
	return nil
}

// Len returns the number of buffered envelope entries.
func (t *InMemoryTransport) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.items)
}

// Items returns a copy of current envelopes.
func (t *InMemoryTransport) Items() []*EventEnvelope {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*EventEnvelope, len(t.items))
	copy(out, t.items)
	return out
}

// Close marks the in-memory transport as closed.
func (t *InMemoryTransport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
}
