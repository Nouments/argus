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
	"time"

	bolt "go.etcd.io/bbolt"
)

// MigrateJSONFiles imports enroll.json, machines.json, revoked.json and audit.log
// from the given directory into the BoltDB (dir/argus.db) and renames originals to .bak.
func MigrateJSONFiles(dir string) error {
	path := filepath.Join(dir, "argus.db")
	d, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}
	defer d.Close()
	// ensure buckets
	_ = d.Update(func(tx *bolt.Tx) error {
		buckets := []string{"enroll", "machines", "revoked", "audit"}
		for _, b := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				return fmt.Errorf("create bucket %s: %w", b, err)
			}
		}
		return nil
	})

	files := map[string]string{"enroll.json": "enroll", "machines.json": "machines", "revoked.json": "revoked"}
	for fname, bucket := range files {
		p := filepath.Join(dir, fname)
		if _, err := os.Stat(p); err == nil {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			var anyv any
			if err := json.Unmarshal(b, &anyv); err != nil {
				return err
			}
			if err := d.Update(func(tx *bolt.Tx) error {
				bt := tx.Bucket([]byte(bucket))
				if bt == nil {
					return fmt.Errorf("bucket %s missing", bucket)
				}
				b2, _ := json.Marshal(anyv)
				return bt.Put([]byte("data"), b2)
			}); err != nil {
				return err
			}
			if err := os.Rename(p, p+".bak"); err != nil {
				return err
			}
		}
	}
	// migrate audit.log
	auditPath := filepath.Join(dir, "audit.log")
	if fi, err := os.Stat(auditPath); err == nil && !fi.IsDir() {
		f, err := os.Open(auditPath)
		if err != nil {
			return err
		}
		defer f.Close()
		rdr := bufio.NewReader(f)
		if err := d.Update(func(tx *bolt.Tx) error {
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
					key := fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
					if err := bt.Put([]byte(key), []byte(line)); err != nil {
						return err
					}
				}
				if err == io.EOF {
					break
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if err := os.Rename(auditPath, auditPath+".bak"); err != nil {
			return err
		}
	}
	return nil
}
