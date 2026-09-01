package main

import (
	"flag"
	"fmt"
	"log"

	gw "github.com/Nouments/argus/services/gateway"
)

func main() {
	dir := flag.String("dir", "", "data dir to migrate into DB (contains enroll.json etc.)")
	flag.Parse()
	if *dir == "" {
		log.Fatal("--dir required")
	}
	if err := gw.MigrateJSONFiles(*dir); err != nil {
		log.Fatalf("migrate failed: %v", err)
	}
	fmt.Println("migration completed")
}
