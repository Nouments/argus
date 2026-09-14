package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	agentpb "github.com/Nouments/argus/proto/agent"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/encoding/protojson"
)

// realClickHouseWriter implements ClickHouseWriter and supports Close().
type realClickHouseWriter struct {
	conn        clickhouse.Conn
	pubConn     *nats.Conn
	postSubject string
	dlqSubject  string
	dlq         *DLQStore
}

// NewClickHouseWriter opens a ClickHouse connection using env vars and optional NATS publisher.
func NewClickHouseWriter() (*realClickHouseWriter, error) {
	addr := os.Getenv("CLICKHOUSE_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9000"
	}
	db := os.Getenv("CLICKHOUSE_DB")
	if db == "" {
		db = "default"
	}
	user := os.Getenv("CLICKHOUSE_USER")
	pass := os.Getenv("CLICKHOUSE_PASS")

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr:            []string{addr},
		Auth:            clickhouse.Auth{Database: db, Username: user, Password: pass},
		DialTimeout:     5 * time.Second,
		ConnMaxLifetime: 60 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}
	rand.Seed(time.Now().UnixNano())
	w := &realClickHouseWriter{conn: conn}
	// optional NATS publisher
	natsURL := os.Getenv("ARGUS_NATS_PUBLISH_URL")
	if natsURL == "" {
		natsURL = os.Getenv("ARGUS_NATS_URL")
	}
	if natsURL != "" {
		nc, err := nats.Connect(natsURL, nats.MaxReconnects(5), nats.ReconnectWait(2*time.Second))
		if err == nil {
			w.pubConn = nc
			w.postSubject = os.Getenv("ARGUS_CH_POST_SUBJECT")
			if w.postSubject == "" {
				w.postSubject = "events.post"
			}
			w.dlqSubject = os.Getenv("ARGUS_CH_DLQ_SUBJECT")
			if w.dlqSubject == "" {
				w.dlqSubject = "events.dlq"
			}
		}
	}
	// optional DLQ store
	dlqPath := os.Getenv("ARGUS_DLQ_PATH")
	if dlqPath == "" {
		dlqPath = "data/dlq.db"
	}
	if dlq, err := OpenDLQ(dlqPath); err == nil {
		w.dlq = dlq
	}
	return w, nil
}

func (w *realClickHouseWriter) Close() error {
	if w.pubConn != nil {
		w.pubConn.Close()
	}
	if w.conn != nil {
		_ = w.conn.Close()
	}
	return nil
}

// WriteEvents writes rows (each row is JSON of an EventEnvelope). It will try retries and on permanent failure append to DLQ.
func (w *realClickHouseWriter) WriteEvents(ctx context.Context, rows [][]byte) error {
	if len(rows) == 0 {
		return nil
	}
	q := `INSERT INTO events (event_id, site_id, agent_id, raw, ts) VALUES (?, ?, ?, ?, ?)`
	maxRetries := 3
	if v := os.Getenv("ARGUS_CH_RETRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			maxRetries = n
		}
	}
	baseMs := 500.0
	if v := os.Getenv("ARGUS_CH_BACKOFF_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			baseMs = float64(n)
		}
	}
	// If multiple rows, try batch insert using ClickHouse native batch API.
	if len(rows) > 1 {
		// attempt batch with retries
		var lastErr error
		for attempt := 0; ; attempt++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			start := time.Now()
			batch, err := w.conn.PrepareBatch(ctx, "INSERT INTO events (event_id, site_id, agent_id, raw, ts) VALUES (?, ?, ?, ?, ?)")
			if err != nil {
				lastErr = err
				CHWriteFailures.WithLabelValues("prepare_batch_error").Inc()
			} else {
				// append rows
				for _, r := range rows {
					var parsed map[string]interface{}
					_ = json.Unmarshal(r, &parsed)
					var eventID, siteID, agentID string
					if v, ok := parsed["event_id"]; ok {
						if s, ok2 := v.(string); ok2 {
							eventID = s
						}
					}
					if v, ok := parsed["site_id"]; ok {
						if s, ok2 := v.(string); ok2 {
							siteID = s
						}
					}
					if v, ok := parsed["agent_id"]; ok {
						if s, ok2 := v.(string); ok2 {
							agentID = s
						}
					}
					ts := time.Now()
					if err := batch.Append(eventID, siteID, agentID, string(r), ts); err != nil {
						lastErr = err
						CHWriteFailures.WithLabelValues("batch_append_error").Inc()
						break
					}
				}
				// send batch
				if err := batch.Send(); err != nil {
					lastErr = err
					CHWriteFailures.WithLabelValues("batch_send_error").Inc()
				} else {
					CHWriteSuccess.WithLabelValues("batch").Inc()
					CHWriteDuration.Observe(time.Since(start).Seconds())
					return nil
				}
			}
			if attempt >= maxRetries {
				// on permanent failure, append all rows to DLQ
				for _, r := range rows {
					if w.pubConn != nil {
						if b, merr := json.Marshal(json.RawMessage(r)); merr == nil {
							_ = w.pubConn.Publish(w.dlqSubject, b)
						}
					}
					var env agentpb.EventEnvelope
					if err := protojson.Unmarshal(r, &env); err == nil {
						if w.dlq != nil {
							_ = w.dlq.AppendWithMetric(&env)
						}
					} else {
						if w.dlq != nil {
							_ = w.dlq.AppendWithMetric(&agentpb.EventEnvelope{Raw: string(r)})
						}
					}
				}
				return lastErr
			}
			// backoff with jitter
			backoff := baseMs * math.Pow(2, float64(attempt))
			if backoff > 10000 {
				backoff = 10000
			}
			jitter := rand.Float64() * (backoff / 2)
			wait := time.Duration(backoff+jitter) * time.Millisecond
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	// fallback to per-row insert for single row
	for _, r := range rows {
		var parsed map[string]interface{}
		var eventID, siteID, agentID string
		_ = json.Unmarshal(r, &parsed)
		if v, ok := parsed["event_id"]; ok {
			if s, ok2 := v.(string); ok2 {
				eventID = s
			}
		}
		if v, ok := parsed["site_id"]; ok {
			if s, ok2 := v.(string); ok2 {
				siteID = s
			}
		}
		if v, ok := parsed["agent_id"]; ok {
			if s, ok2 := v.(string); ok2 {
				agentID = s
			}
		}
		ts := time.Now()
		var lastErr error
		for attempt := 0; ; attempt++ {
			start := time.Now()
			if err := w.conn.Exec(ctx, q, eventID, siteID, agentID, string(r), ts); err == nil {
				if w.pubConn != nil {
					notif := map[string]string{"event_id": eventID, "site_id": siteID, "agent_id": agentID}
					if b, merr := json.Marshal(notif); merr == nil {
						_ = w.pubConn.Publish(w.postSubject, b)
					}
				}
				lastErr = nil
				CHWriteSuccess.WithLabelValues("ok").Inc()
				CHWriteDuration.Observe(time.Since(start).Seconds())
				break
			} else {
				lastErr = err
				CHWriteFailures.WithLabelValues("exec_error").Inc()
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt >= maxRetries {
				if w.pubConn != nil {
					if b, merr := json.Marshal(json.RawMessage(r)); merr == nil {
						_ = w.pubConn.Publish(w.dlqSubject, b)
					}
				}
				var env agentpb.EventEnvelope
				if err := protojson.Unmarshal(r, &env); err == nil {
					if w.dlq != nil {
						_ = w.dlq.AppendWithMetric(&env)
					}
				} else {
					if w.dlq != nil {
						_ = w.dlq.AppendWithMetric(&agentpb.EventEnvelope{Raw: string(r)})
					}
				}
				return lastErr
			}
			backoff := baseMs * math.Pow(2, float64(attempt))
			if backoff > 10000 {
				backoff = 10000
			}
			jitter := rand.Float64() * (backoff / 2)
			wait := time.Duration(backoff+jitter) * time.Millisecond
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
