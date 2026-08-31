package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessSnapshot is a minimal read of the Linux /proc process status.
type ProcessSnapshot struct {
	PID   int
	Name  string
	PPID  int
	State string
	VmRSS int
}

// SnapshotFromDir reads process status files under a proc-like directory.
func SnapshotFromDir(root string) ([]ProcessSnapshot, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	out := make([]ProcessSnapshot, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() == false {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		statusPath := filepath.Join(root, entry.Name(), "status")
		status, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		proc, err := parseStatusFile(pid, status)
		if err != nil {
			continue
		}
		out = append(out, proc)
	}
	return out, nil
}

func parseStatusFile(pid int, data []byte) (ProcessSnapshot, error) {
	proc := ProcessSnapshot{PID: pid}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			proc.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		}
		if strings.HasPrefix(line, "PPID:") {
			v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPID:")))
			if err == nil {
				proc.PPID = v
			}
		}
		if strings.HasPrefix(line, "State:") {
			proc.State = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
		}
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.Atoi(fields[1])
				if err == nil {
					proc.VmRSS = v
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return ProcessSnapshot{}, err
	}
	if proc.Name == "" {
		return ProcessSnapshot{}, fmt.Errorf("missing process name")
	}
	return proc, nil
}
