package normalizer

import (
	"encoding/json"
	"time"
)

// NormalizeWindows ensures collected Windows payloads are wrapped into the canonical event shape.
func NormalizeWindows(raw []byte) ([]byte, error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	if _, ok := obj["event_id"]; !ok {
		obj["event_id"] = fmtEventIDWin()
	}
	if _, ok := obj["timestamp"]; !ok {
		obj["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	}
	return json.Marshal(obj)
}

func fmtEventIDWin() string {
	return "evt-" + time.Now().UTC().Format("20060102T150405.000000000Z")
}
