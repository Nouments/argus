package config

import (
	"strings"
)


func ExportPathByOS(Os string) string {
	if strings.ToLower(Os) == "windows"{
		return `C:\ProgramData\Argus\config\agent.yaml`
	}
	return `/etc/argus/config/agent.yaml`
}


