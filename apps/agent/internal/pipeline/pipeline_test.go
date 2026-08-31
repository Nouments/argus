package pipeline

import (
	"fmt"
	"testing"

	"github.com/Nouments/argus/apps/agent/internal/collector"
	"github.com/Nouments/argus/apps/agent/internal/normalizer"
)

type testCollector struct {
	name    string
	payload []byte
}

func (c testCollector) Name() string             { return c.name }
func (c testCollector) Collect() ([]byte, error) { return c.payload, nil }

func TestPipelineProcess(t *testing.T) {
	r := collector.NewRegistry()
	if err := r.Register(testCollector{name: "syslog", payload: []byte(`{"message":"ok"}`)}); err != nil {
		t.Fatalf("register syslog: %v", err)
	}
	if err := r.Register(testCollector{name: "process", payload: []byte(`{"pid":1}`)}); err != nil {
		t.Fatalf("register process: %v", err)
	}

	p := New(r, normalizer.JSONNormalizer{})
	items, err := p.Process()
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("Process returned %d items, want 2", len(items))
	}
	for _, item := range items {
		if len(item.Raw) == 0 {
			t.Fatal("normalized payload should not be empty")
		}
		fmt.Sprint(item.Source)
	}
}
