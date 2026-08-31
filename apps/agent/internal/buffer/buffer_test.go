package buffer

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	filename := "buf.enc"
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	data1 := []byte("hello world")
	data2 := []byte("another event")
	if err := WriteEncryptedAppend(dir, filename, key, data1); err != nil {
		t.Fatalf("write1: %v", err)
	}
	if err := WriteEncryptedAppend(dir, filename, key, data2); err != nil {
		t.Fatalf("write2: %v", err)
	}
	path := filepath.Join(dir, filename)
	got, err := ReadAndDecryptAll(path, key)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(got))
	}
	if string(got[0]) != string(data1) || string(got[1]) != string(data2) {
		t.Fatalf("decrypted mismatch")
	}
	// ensure file exists with restricted perms
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("file perms too open: %v", info.Mode())
	}
}
