package ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/Nouments/argus/core/internal/storage"
	agentpb "github.com/Nouments/argus/proto/agent"
)

// Consumer subscribes to NATS subject and writes events to ClickHouse via writer.
type Consumer struct {
	nc        *nats.Conn
	subj      string
	writer    *storage.ClickHouseWriter
	msgCh     chan []byte
	workers   int
	bufSize   int
	wg        sync.WaitGroup
	stopOnce  sync.Once
	batchSize int
	flushMs   int
}

// NewConsumer dials NATS and prepares ClickHouse writer. Concurrency and buffer size
// can be configured with ARGUS_INGEST_CONC and ARGUS_INGEST_BUF.
func NewConsumer() (*Consumer, error) {
	url := os.Getenv("ARGUS_NATS_URL")
	if url == "" {
		url = nats.DefaultURL
	}
	subj := os.Getenv("ARGUS_NATS_SUBJECT")
	if subj == "" {
		subj = "events"
	}
	nc, err := nats.Connect(url, nats.MaxReconnects(10), nats.ReconnectWait(2*time.Second))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	w, err := storage.NewClickHouseWriter()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("clickhouse init: %w", err)
	}
	// concurrency default: number of CPU cores
	conc := runtime.NumCPU()
	if v := os.Getenv("ARGUS_INGEST_CONC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			conc = n
		}
	}
	buf := 1000
	if v := os.Getenv("ARGUS_INGEST_BUF"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			buf = n
		}
	}
	// batching defaults
	bsz := 50
	if v := os.Getenv("ARGUS_CH_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			bsz = n
		}
	}
	flushMs := 200
	if v := os.Getenv("ARGUS_CH_BATCH_FLUSH_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			flushMs = n
		}
	}
	return &Consumer{nc: nc, subj: subj, writer: w, msgCh: make(chan []byte, buf), workers: conc, bufSize: buf, batchSize: bsz, flushMs: flushMs}, nil
}

// Start subscribes and runs workers until context cancelled.
func (c *Consumer) Start(ctx context.Context) error {
	// spawn workers
	for i := 0; i < c.workers; i++ {
		c.wg.Add(1)
		go func(id int) {
			defer c.wg.Done()
			batch := make([]*agentpb.EventEnvelope, 0, c.batchSize)
			flushDur := time.Duration(c.flushMs) * time.Millisecond
			timer := time.NewTimer(flushDur)
			defer timer.Stop()
		loop:
			for {
				select {
				case b, ok := <-c.msgCh:
					if !ok {
						break loop
					}
					var ev agentpb.EventEnvelope
					if err := json.Unmarshal(b, &ev); err != nil {
						if err2 := proto.Unmarshal(b, &ev); err2 != nil {
							log.Printf("ingest: failed to decode message json=%v proto=%v", err, err2)
							continue
						}
					}
					batch = append(batch, &ev)
					if len(batch) >= c.batchSize {
						tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
						if err := c.writer.InsertEvents(tctx, batch); err != nil {
							log.Printf("ingest: batch insert failed: %v", err)
						}
						cancel()
						batch = batch[:0]
						if !timer.Stop() {
							select {
							case <-timer.C:
							default:
							}
						}
						timer.Reset(flushDur)
					}
				case <-timer.C:
					if len(batch) > 0 {
						tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
						if err := c.writer.InsertEvents(tctx, batch); err != nil {
							log.Printf("ingest: batch insert failed: %v", err)
						}
						cancel()
						batch = batch[:0]
					}
					timer.Reset(flushDur)
				}
			}
			// flush remaining
			if len(batch) > 0 {
				tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				if err := c.writer.InsertEvents(tctx, batch); err != nil {
					log.Printf("ingest: final batch insert failed: %v", err)
				}
				cancel()
			}
		}(i)
	}

	// async subscription handler pushes raw bytes into channel
	sub, err := c.nc.Subscribe(c.subj, func(m *nats.Msg) {
		select {
		case c.msgCh <- m.Data:
		default:
			// channel full, drop and log
			log.Printf("ingest: dropping message, buffer full")
		}
	})
	if err != nil {
		return err
	}

	// wait for context cancel
	<-ctx.Done()
	// initiate shutdown
	c.stopOnce.Do(func() {
		_ = sub.Unsubscribe()
		// close channel then wait for workers
		close(c.msgCh)
	})
	c.wg.Wait()
	c.nc.Close()
	return nil
}
