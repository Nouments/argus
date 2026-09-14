package storage

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentpb "github.com/Nouments/argus/proto/agent"
)

func TestReplayer_DrainsDLQToMockWriter(t *testing.T) {
	tmp, err := ioutil.TempDir("", "replayer-test-")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	mockPath := filepath.Join(tmp, "mock.log")
	w, err := NewMockClickHouseWriter(mockPath)
	if err != nil {
		t.Fatalf("new mock writer: %v", err)
	}
	defer w.Close()

	dlqPath := filepath.Join(tmp, "dlq.db")
	dlq, err := OpenDLQ(dlqPath)
	if err != nil {
		t.Fatalf("open dlq: %v", err)
	}
	defer dlq.Close()

	// append an envelope
	env := &agentpb.EventEnvelope{EventId: "e1", SiteId: "s1", AgentId: "a1", Raw: "{}", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := dlq.Append(env); err != nil {
		t.Fatalf("dlq append: %v", err)
	}

	replayer := NewReplayer(w, dlq, 50)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		if err := replayer.Start(ctx); err != nil {
			// Stop only logs
		}
	}()

	// wait for replayer to process
	time.Sleep(500 * time.Millisecond)

	// ensure DLQ is empty
	key, e, err := dlq.Next()
	if err != nil {
		t.Fatalf("dlq next: %v", err)
	}
	if key != nil || e != nil {
		t.Fatalf("expected dlq empty, got key=%v ev=%v", key, e)
	}

	// ensure mock file has content
	data, err := ioutil.ReadFile(mockPath)
	if err != nil {
		t.Fatalf("read mock: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("mock writer file empty")
	}
}
