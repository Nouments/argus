package storage

import (
	"context"
	"fmt"
	"os"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	agentpb "github.com/Nouments/argus/proto/agent"
)

// ClickHouseWriter is a minimal wrapper to write events into ClickHouse.
type ClickHouseWriter struct {
	conn clickhouse.Conn
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
	return &ClickHouseWriter{conn: conn}, nil
}

// InsertEvent stores a single EventEnvelope into a simple `events` table.
// Table schema expected: (event_id String, site_id String, agent_id String, raw String, ts DateTime64)
func (w *ClickHouseWriter) InsertEvent(ctx context.Context, e *agentpb.EventEnvelope) error {
	if e == nil {
		return fmt.Errorf("nil event")
	}
	// best-effort insert
	q := `INSERT INTO events (event_id, site_id, agent_id, raw, ts) VALUES (?, ?, ?, ?, ?)`
	ts := time.Now()
	return w.conn.Exec(ctx, q, e.GetEventId(), e.GetSiteId(), e.GetAgentId(), e.GetRaw(), ts)
}

// InsertEvents inserts multiple events. This implementation calls Exec for each
// event sequentially (safe fallback when no native bulk API is used).
func (w *ClickHouseWriter) InsertEvents(ctx context.Context, events []*agentpb.EventEnvelope) error {
	if len(events) == 0 {
		return nil
	}
	q := `INSERT INTO events (event_id, site_id, agent_id, raw, ts) VALUES (?, ?, ?, ?, ?)`
	for _, e := range events {
		if e == nil {
			continue
		}
		ts := time.Now()
		if err := w.conn.Exec(ctx, q, e.GetEventId(), e.GetSiteId(), e.GetAgentId(), e.GetRaw(), ts); err != nil {
			return err
		}
	}
	return nil
}
