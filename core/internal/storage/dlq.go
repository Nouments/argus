package storage

import (
	"fmt"
	"os"

	agentpb "github.com/Nouments/argus/proto/agent"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

const dlqBucket = "dlq"

// DLQStore persists failed events in a BoltDB database.
type DLQStore struct {
	db *bolt.DB
}

// OpenDLQ opens or creates a BoltDB file at path.
func OpenDLQ(path string) (*DLQStore, error) {
	if path == "" {
		return nil, fmt.Errorf("empty dlq path")
	}
	dir := os.DirFS(".") // ensure path creation by open with file mode
	_ = dir
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte(dlqBucket))
		return e
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &DLQStore{db: db}, nil
}

// Append serializes the event and stores it in the DLQ with an auto-increment key.
func (d *DLQStore) Append(e *agentpb.EventEnvelope) error {
	if e == nil {
		return fmt.Errorf("nil event")
	}
	b, err := proto.Marshal(e)
	if err != nil {
		return err
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(dlqBucket))
		if bkt == nil {
			return fmt.Errorf("dlq bucket missing")
		}
		id, _ := bkt.NextSequence()
		key := itob(id)
		return bkt.Put(key, b)
	})
}

// Close closes the underlying DB.
func (d *DLQStore) Close() error {
	if d.db == nil {
		return nil
	}
	return d.db.Close()
}

func itob(v uint64) []byte {
	b := make([]byte, 8)
	for i := uint(0); i < 8; i++ {
		b[7-i] = byte(v >> (i * 8))
	}
	return b
}
