package main

import (
	"fmt"

	"github.com/Nouments/argus/apps/agent/internal/config"
)

func main() {
	path := config.ExportPathByOS("linux")
	fmt.Println(path)
}