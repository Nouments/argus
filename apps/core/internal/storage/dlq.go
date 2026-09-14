package storage

import (
	"fmt"
	"os"
	"path/filepath"

	agentpb "github.com/Nouments/argus/proto/agent"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

const dlqBucket = "dlq"

type DLQStore struct {
	db *bolt.DB
}

func OpenDLQ(path string) (*DLQStore, error) {
	if path == "" {
		return nil, fmt.Errorf("empty dlq path")
	}
	// ensure parent directory exists
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte(dlqBucket))
		return e
	}); err != nil {
		db.Close()
		return nil, err
	}
	// set initial DLQ size metric
	ds := &DLQStore{db: db}
	ds.updateDLQGauge()
	return &DLQStore{db: db}, nil
}

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

// wrap Append to update gauge (bolt update will call this function after commit)
func (d *DLQStore) AppendWithMetric(e *agentpb.EventEnvelope) error {
	if err := d.Append(e); err != nil {
		return err
	}
	d.updateDLQGauge()
	return nil
}

func (d *DLQStore) updateDLQGauge() {
	if d == nil || d.db == nil {
		return
	}
	var count int
	_ = d.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(dlqBucket))
		if bkt == nil {
			return nil
		}
		c := bkt.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			count++
		}
		return nil
	})
	DLQSize.Set(float64(count))
}

func (d *DLQStore) Next() ([]byte, *agentpb.EventEnvelope, error) {
	var key []byte
	var ev *agentpb.EventEnvelope
	err := d.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(dlqBucket))
		if bkt == nil {
			return fmt.Errorf("dlq bucket missing")
		}
		c := bkt.Cursor()
		k, v := c.First()
		if k == nil {
			return nil
		}
		key = make([]byte, len(k))
		copy(key, k)
		eb := make([]byte, len(v))
		copy(eb, v)
		var e agentpb.EventEnvelope
		if err := proto.Unmarshal(eb, &e); err != nil {
			return err
		}
		ev = &e
		return nil
	})
	return key, ev, err
}

func (d *DLQStore) Delete(key []byte) error {
	if key == nil {
		return fmt.Errorf("nil key")
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(dlqBucket))
		if bkt == nil {
			return fmt.Errorf("dlq bucket missing")
		}
		return bkt.Delete(key)
	})
}

func (d *DLQStore) DeleteWithMetric(key []byte) error {
	if err := d.Delete(key); err != nil {
		return err
	}
	d.updateDLQGauge()
	return nil
}

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
