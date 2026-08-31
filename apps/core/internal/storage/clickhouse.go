package storage

import "context"

// ClickHouseWriter defines the minimal interface used to write event rows to ClickHouse.
type ClickHouseWriter interface {
	// WriteEvents writes multiple pre-encoded rows (ClickHouse TSV/JSON each as []byte).
	WriteEvents(ctx context.Context, rows [][]byte) error
}
