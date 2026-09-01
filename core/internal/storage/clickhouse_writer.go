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
)

// ClickHouseWriter is a minimal wrapper to write events into ClickHouse.
type ClickHouseWriter struct {
	conn        clickhouse.Conn
	pubConn     *nats.Conn
	postSubject string
	dlqSubject  string
	dlq         *DLQStore
}

// NewClickHouseWriter opens a connection using env vars: CLICKHOUSE_ADDR (host:port), CLICKHOUSE_DB, CLICKHOUSE_USER, CLICKHOUSE_PASS
func NewClickHouseWriter() (*ClickHouseWriter, error) {
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
	// ping
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}
	// seed jitter
	rand.Seed(time.Now().UnixNano())
	w := &ClickHouseWriter{conn: conn}
	// optional NATS publisher
	natsURL := os.Getenv("ARGUS_NATS_PUBLISH_URL")
	if natsURL == "" {
		natsURL = os.Getenv("ARGUS_NATS_URL")
	}
	if natsURL != "" {
		nc, err := nats.Connect(natsURL, nats.MaxReconnects(5), nats.ReconnectWait(2*time.Second))
		if err != nil {
			// log but don't fail writer creation; publishing is optional
		} else {
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
	// optional DLQ persistent store
	dlqPath := os.Getenv("ARGUS_DLQ_PATH")
	if dlqPath == "" {
		dlqPath = "data/dlq.db"
	}
	if dlq, err := OpenDLQ(dlqPath); err == nil {
		w.dlq = dlq
	}
	return w, nil
}

// InsertEvent stores a single EventEnvelope into a simple `events` table.
// Table schema expected: (event_id String, site_id String, agent_id String, raw String, ts DateTime64)
func (w *ClickHouseWriter) InsertEvent(ctx context.Context, e *agentpb.EventEnvelope) error {
	if e == nil {
		return fmt.Errorf("nil event")
	}
	q := `INSERT INTO events (event_id, site_id, agent_id, raw, ts) VALUES (?, ?, ?, ?, ?)`
	ts := time.Now()
	// retry configuration via env
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
	for attempt := 0; ; attempt++ {
		err := w.conn.Exec(ctx, q, e.GetEventId(), e.GetSiteId(), e.GetAgentId(), e.GetRaw(), ts)
		if err == nil {
			// publish post-write notification if configured
			if w.pubConn != nil {
				// best-effort: marshal minimal notification
				notif := map[string]string{"event_id": e.GetEventId(), "site_id": e.GetSiteId(), "agent_id": e.GetAgentId()}
				if b, merr := json.Marshal(notif); merr == nil {
					_ = w.pubConn.Publish(w.postSubject, b)
				}
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt >= maxRetries {
			// publish to DLQ if configured
			if w.pubConn != nil {
				if b, merr := json.Marshal(e); merr == nil {
					_ = w.pubConn.Publish(w.dlqSubject, b)
				}
			}
			return err
		}
		// exponential backoff with jitter
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

// InsertEvents inserts multiple events. This implementation calls Exec for each
// event sequentially (safe fallback when no native bulk API is used).
func (w *ClickHouseWriter) InsertEvents(ctx context.Context, events []*agentpb.EventEnvelope) error {
	if len(events) == 0 {
		return nil
	}
	// reuse InsertEvent retry logic per event
	for _, e := range events {
		if e == nil {
			continue
		}
		if err := w.InsertEvent(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// Close closes underlying connections (ClickHouse and optional NATS).
func (w *ClickHouseWriter) Close() error {
	if w.pubConn != nil {
		w.pubConn.Close()
	}
	// clickhouse.Conn has Close in some versions; attempt best-effort
	if w.conn != nil {
		_ = w.conn.Close()
	}
	return nil
}

// QueryEvents is a read-path stub to separate read vs write responsibilities.
// Implement as needed for querying ClickHouse; returns not implemented for now.
func (w *ClickHouseWriter) QueryEvents(ctx context.Context, siteID string, limit int) ([]*agentpb.EventEnvelope, error) {
	return nil, fmt.Errorf("QueryEvents not implemented")
}
