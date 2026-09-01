package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

func dbPath() string {
	if dir := os.Getenv("ARGUS_DATA_DIR"); dir != "" {
		return filepath.Join(dir, "argus.db")
	}
	return "./data_gateway/argus.db"
}

func listBuckets(db *bolt.DB) error {
	return db.View(func(tx *bolt.Tx) error {
		fmt.Println("buckets:")
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			fmt.Printf(" - %s\n", string(name))
			return nil
		})
	})
}

func dumpBucket(db *bolt.DB, bucket string, out string) error {
	return db.View(func(tx *bolt.Tx) error {
		bt := tx.Bucket([]byte(bucket))
		if bt == nil {
			return fmt.Errorf("bucket %s not found", bucket)
		}
		// if out empty, print to stdout
		var f *os.File
		var err error
		if out == "" {
			f = os.Stdout
		} else {
			f, err = os.Create(out)
			if err != nil {
				return err
			}
			defer f.Close()
		}
		// if bucket has key "data", unmarshal and pretty print
		if v := bt.Get([]byte("data")); v != nil {
			var anyv any
			if err := json.Unmarshal(v, &anyv); err == nil {
				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				return enc.Encode(anyv)
			}
		}
		// otherwise iterate keys
		c := bt.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// print key and value raw
			fmt.Fprintf(f, "KEY=%s\n", string(k))
			fmt.Fprintln(f, string(v))
		}
		return nil
	})
}

func main() {
	list := flag.Bool("list", false, "List buckets in DB")
	dump := flag.String("dump", "", "Bucket to dump")
	out := flag.String("out", "", "Output file for dump (defaults to stdout)")
	dbp := flag.String("db", "", "Path to bolt DB (default from ARGUS_DATA_DIR)")
	migrate := flag.String("migrate", "", "Path to data dir containing enroll.json/machines.json/revoked.json/audit.log to import into DB")
	flag.Parse()

	path := *dbp
	if path == "" {
		path = dbPath()
	}
	d, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer d.Close()

	if *migrate != "" {
		// perform migration similar to gateway store
		files := map[string]string{"enroll.json": "enroll", "machines.json": "machines", "revoked.json": "revoked"}
		for fname, bucket := range files {
			p := filepath.Join(*migrate, fname)
			if _, err := os.Stat(p); err == nil {
				b, err := os.ReadFile(p)
				if err != nil {
					log.Fatalf("read %s: %v", p, err)
				}
				var anyv any
				if err := json.Unmarshal(b, &anyv); err != nil {
					log.Fatalf("unmarshal %s: %v", p, err)
				}
				err = d.Update(func(tx *bolt.Tx) error {
					bt := tx.Bucket([]byte(bucket))
					if bt == nil {
						return fmt.Errorf("bucket %s missing", bucket)
					}
					b2, _ := json.Marshal(anyv)
					return bt.Put([]byte("data"), b2)
				})
				if err != nil {
					log.Fatalf("save to bucket %s: %v", bucket, err)
				}
				_ = os.Rename(p, p+".bak")
				fmt.Printf("migrated %s -> bucket %s\n", p, bucket)
			}
		}
		// migrate audit.log lines
		auditPath := filepath.Join(*migrate, "audit.log")
		if fi, err := os.Stat(auditPath); err == nil && !fi.IsDir() {
			f, err := os.Open(auditPath)
			if err != nil {
				log.Fatalf("open audit: %v", err)
			}
			defer f.Close()
			rdr := bufio.NewReader(f)
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
						key := fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
						_ = bt.Put([]byte(key), []byte(line))
					}
					if err == io.EOF {
						break
					}
				}
				return nil
			})
			_ = os.Rename(auditPath, auditPath+".bak")
			fmt.Printf("migrated %s -> bucket audit\n", auditPath)
		}
		return
	}

	if *list {
		if err := listBuckets(d); err != nil {
			log.Fatalf("list: %v", err)
		}
		return
	}
	if *dump != "" {
		if err := dumpBucket(d, *dump, *out); err != nil {
			log.Fatalf("dump: %v", err)
		}
		return
	}
	flag.Usage()
}
