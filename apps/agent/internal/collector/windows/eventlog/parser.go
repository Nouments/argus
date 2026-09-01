package eventlog

import (
	"bufio"
	"regexp"
	"strings"
)

var kvLineRe = regexp.MustCompile(`^\s*([^:]+):\s*(.*)$`)

// parseWinRecord parses a single wevtutil text record into a map of fields.
// It extracts key: value lines and always includes the original raw under "raw".
func parseWinRecord(block string) map[string]string {
	out := map[string]string{"raw": strings.TrimSpace(block)}
	scanner := bufio.NewScanner(strings.NewReader(block))
	for scanner.Scan() {
		line := scanner.Text()
		m := kvLineRe.FindStringSubmatch(line)
		if len(m) == 3 {
			key := strings.ToLower(strings.TrimSpace(m[1]))
			key = strings.ReplaceAll(key, " ", "_")
			val := strings.TrimSpace(m[2])
			// If a key already exists, append with a separator so we don't lose data
			if prev, ok := out[key]; ok {
				out[key] = prev + " | " + val
			} else {
				out[key] = val
			}
		}
	}
	return out
}
