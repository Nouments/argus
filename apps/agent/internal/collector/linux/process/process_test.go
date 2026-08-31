package process

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotFromDir(t *testing.T) {
	dir := t.TempDir()
	pid1 := filepath.Join(dir, "1")
	if err := os.Mkdir(pid1, 0o755); err != nil {
		t.Fatalf("mkdir pid1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pid1, "status"), []byte("Name:\tinit\nPID:\t1\nPPID:\t0\nState:\tS (sleeping)\nVmRSS:\t2048\n"), 0o600); err != nil {
		t.Fatalf("write status 1: %v", err)
	}
	pid2 := filepath.Join(dir, "2")
	if err := os.Mkdir(pid2, 0o755); err != nil {
		t.Fatalf("mkdir pid2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pid2, "status"), []byte("Name:\tsshd\nPID:\t2\nPPID:\t1\nState:\tR (running)\nVmRSS:\t4096\n"), 0o600); err != nil {
		t.Fatalf("write status 2: %v", err)
	}

	procs, err := SnapshotFromDir(dir)
	if err != nil {
		t.Fatalf("SnapshotFromDir returned error: %v", err)
	}
	if len(procs) != 2 {
		t.Fatalf("SnapshotFromDir returned %d processes, want 2", len(procs))
	}
	if procs[0].Name == "" || procs[1].Name == "" {
		t.Fatal("process name cannot be empty")
	}
}
