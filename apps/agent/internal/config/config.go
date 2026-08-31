package config

import (
	"fmt"
	"strings"
)

func ExportPathByOS(osName string) string {
	if strings.EqualFold(osName, "windows") {
		return `C:\ProgramData\Argus\config\agent.yaml`
	}
	return "/etc/argus/config/agent.yaml"
}

func FilesystemPath(paths string) ([]string, error) {
	if strings.TrimSpace(paths) == "" {
		return nil, fmt.Errorf("paths cannot be empty")
	}

	parts := strings.FieldsFunc(paths, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})
	if len(parts) == 0 {
		return nil, fmt.Errorf("no valid filesystem paths parsed")
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid filesystem paths parsed")
	}
	return out, nil
}
