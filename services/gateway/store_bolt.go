package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var dbMu sync.Mutex
var db *bolt.DB

func dbPath() (string, error) {
	dir := os.Getenv("ARGUS_DATA_DIR")
	if dir == "" {
		dir = "./data_gateway"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "argus.db"), nil
}

func openDB() (*bolt.DB, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	if db != nil {
		return db, nil
	}
	path, err := dbPath()
	if err != nil {
		return nil, err
	}
	d, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	db = d
	// ensure buckets
	_ = db.Update(func(tx *bolt.Tx) error {
		buckets := []string{"enroll", "machines", "revoked", "audit"}
		for _, b := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				return fmt.Errorf("create bucket %s: %w", b, err)
			}
		}
		return nil
	})
	// try migrating existing JSON files if present
	dir := filepath.Dir(path)
	_ = migrateJSONFiles(dir)
	return db, nil
}

func migrateJSONFiles(dir string) error {
	// mapping of file -> bucket
	files := map[string]string{
		"enroll.json":   "enroll",
		"machines.json": "machines",
		"revoked.json":  "revoked",
	}
	for fname, bucket := range files {
		p := filepath.Join(dir, fname)
		if _, err := os.Stat(p); err == nil {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			// try to unmarshal into generic map
			var anyv any
			if err := json.Unmarshal(b, &anyv); err != nil {
				return err
			}
			// save into bucket
			if err := saveBucketData(bucket, anyv); err != nil {
				return err
			}
			// rename original file to .bak
			_ = os.Rename(p, p+".bak")
		}
	}
	// migrate audit.log lines into audit bucket
	auditPath := filepath.Join(dir, "audit.log")
	if fi, err := os.Stat(auditPath); err == nil && !fi.IsDir() {
		f, err := os.Open(auditPath)
		if err == nil {
			defer f.Close()
			rdr := bufio.NewReader(f)
			d, _ := openDB()
			_ = d.Update(func(tx *bolt.Tx) error {
				bt := tx.Bucket([]byte("audit"))
				if bt == nil {
					return fmt.Errorf("audit bucket missing")
				}
				for {
					line, err := rdr.ReadString('\n')
					if err != nil && err != io.EOF {
						return err
					}
					line = strings.TrimSpace(line)
					if line != "" {
						var e any
						if err := json.Unmarshal([]byte(line), &e); err == nil {
							key := fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
							_ = bt.Put([]byte(key), []byte(line))
						}
					}
					if err == io.EOF {
						break
					}
				}
				return nil
			})
			// rename audit.log
			_ = os.Rename(auditPath, auditPath+".bak")
		}
	}
	return nil
}

func saveBucketData(bucket string, v any) error {
	d, err := openDB()
	if err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return d.Update(func(tx *bolt.Tx) error {
		bt := tx.Bucket([]byte(bucket))
		if bt == nil {
			return fmt.Errorf("bucket %s missing", bucket)
		}
		return bt.Put([]byte("data"), b)
	})
}

func loadBucketData(bucket string, v any) error {
	d, err := openDB()
	if err != nil {
		return err
	}
	return d.View(func(tx *bolt.Tx) error {
		bt := tx.Bucket([]byte(bucket))
		if bt == nil {
			return fmt.Errorf("bucket %s missing", bucket)
		}
		b := bt.Get([]byte("data"))
		if b == nil {
			return nil
		}
		return json.Unmarshal(b, v)
	})
}

// appendAudit writes a JSON-line audit event into the "audit" bucket with a unique key.
func appendAudit(eventType string, payload any) error {
	d, err := openDB()
	if err != nil {
		return err
	}
	entry := map[string]any{"ts": time.Now().Unix(), "event": eventType, "payload": payload}
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return d.Update(func(tx *bolt.Tx) error {
		bt := tx.Bucket([]byte("audit"))
		if bt == nil {
			return fmt.Errorf("audit bucket missing")
		}
		key := fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
		return bt.Put([]byte(key), b)
	})
}

// CloseDB should be called on shutdown (best-effort).
func CloseDB() error {
	dbMu.Lock()
	defer dbMu.Unlock()
	if db == nil {
		return nil
	}
	err := db.Close()
	db = nil
	return err
}
