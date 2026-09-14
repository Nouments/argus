package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

type Replayer struct {
	writer ClickHouseWriter
	dlq    *DLQStore
	pollMs int
}

func NewReplayer(writer ClickHouseWriter, dlq *DLQStore, pollMs int) *Replayer {
	if pollMs <= 0 {
		pollMs = 1000
	}
	return &Replayer{writer: writer, dlq: dlq, pollMs: pollMs}
}

func (r *Replayer) Start(ctx context.Context) error {
	if r.writer == nil || r.dlq == nil {
		return fmt.Errorf("replayer requires writer and dlq")
	}
	poll := time.Duration(r.pollMs) * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		key, ev, err := r.dlq.Next()
		if err != nil {
			log.Printf("replayer: dlq next error: %v", err)
			time.Sleep(poll)
			continue
		}
		if key == nil || ev == nil {
			time.Sleep(poll)
			continue
		}
		// prepare row payload (JSON of envelope)
		b, _ := json.Marshal(ev)
		rows := [][]byte{b}
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := r.writer.WriteEvents(tctx, rows); err != nil {
			log.Printf("replayer: write failed: %v", err)
			cancel()
			time.Sleep(poll)
			continue
		}
		cancel()
		if err := r.dlq.DeleteWithMetric(key); err != nil {
			log.Printf("replayer: failed to delete dlq key: %v", err)
		}
	}
}
