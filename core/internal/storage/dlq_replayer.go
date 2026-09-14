package storage

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Replayer drains DLQ entries and attempts to re-insert them into ClickHouse.
type Replayer struct {
	writer     *ClickHouseWriter
	dlq        *DLQStore
	pollMillis int
}

// NewReplayer constructs a Replayer. pollMillis defaults to 1000ms if <=0.
func NewReplayer(w *ClickHouseWriter, dlq *DLQStore, pollMillis int) *Replayer {
	if pollMillis <= 0 {
		pollMillis = 1000
	}
	return &Replayer{writer: w, dlq: dlq, pollMillis: pollMillis}
}

// Start begins draining the DLQ until context is cancelled.
func (r *Replayer) Start(ctx context.Context) error {
	if r.dlq == nil || r.writer == nil {
		return fmt.Errorf("replayer requires writer and dlq")
	}
	poll := time.Duration(r.pollMillis) * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		key, ev, err := r.dlq.Next()
		if err != nil {
			log.Printf("dlq replayer: next error: %v", err)
			time.Sleep(poll)
			continue
		}
		if key == nil || ev == nil {
			// nothing to do
			time.Sleep(poll)
			continue
		}
		// attempt insert using writer (writer has its own retries)
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = r.writer.InsertEvent(tctx, ev)
		cancel()
		if err != nil {
			log.Printf("dlq replayer: insert failed, will retry later: %v", err)
			// backoff a bit before retrying same entry
			time.Sleep(poll)
			continue
		}
		// success: remove from DLQ
		if derr := r.dlq.Delete(key); derr != nil {
			log.Printf("dlq replayer: failed to delete key after success: %v", derr)
		}
	}
}
