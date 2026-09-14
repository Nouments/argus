package normalizer

import (
	"encoding/json"
	"time"
)

// NormalizeLinux ensures collected Linux payloads are wrapped into the canonical event shape.
func NormalizeLinux(raw []byte) ([]byte, error) {
	// best-effort: if raw already valid JSON, attach minimal metadata
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	if _, ok := obj["event_id"]; !ok {
		obj["event_id"] = fmtEventIDLin()
	}
	if _, ok := obj["timestamp"]; !ok {
		obj["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	}
	return json.Marshal(obj)
}

func fmtEventIDLin() string {
	return "evt-" + time.Now().UTC().Format("20060102T150405.000000000Z")
}
