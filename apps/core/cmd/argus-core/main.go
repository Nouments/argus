package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Nouments/argus/apps/core/internal/alerting"
	"github.com/Nouments/argus/apps/core/internal/detection"
	"github.com/Nouments/argus/apps/core/internal/ingestion"
	"github.com/Nouments/argus/apps/core/internal/rules"
	"github.com/Nouments/argus/apps/core/internal/storage"
)

func main() {
	grpcAddr := flag.String("grpc-addr", envOrDefault("ARGUS_CORE_GRPC_ADDR", ":8443"), "gRPC listen address")
	dataDir := flag.String("data-dir", envOrDefault("ARGUS_CORE_DATA_DIR", "./data/core"), "core data directory")
	eventStorePath := flag.String("event-store", strings.TrimSpace(os.Getenv("ARGUS_EVENT_STORE")), "JSONL event store path")
	certPath := flag.String("cert", strings.TrimSpace(os.Getenv("ARGUS_CORE_CERT")), "TLS certificate path")
	keyPath := flag.String("key", strings.TrimSpace(os.Getenv("ARGUS_CORE_KEY")), "TLS key path")
	caPath := flag.String("ca", strings.TrimSpace(os.Getenv("ARGUS_CORE_CA")), "mTLS CA certificate path")
	bearerToken := flag.String("gateway-token", strings.TrimSpace(os.Getenv("ARGUS_GATEWAY_TOKEN")), "optional bearer token required for ingestion")
	flag.Parse()

	if strings.TrimSpace(*eventStorePath) == "" {
		*eventStorePath = filepath.Join(*dataDir, "events.jsonl")
	}

	store, err := storage.NewJSONLStore(*eventStorePath)
	if err != nil {
		log.Fatalf("configure event store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Printf("close event store: %v", err)
		}
	}()

	alertManager := alerting.NewManager()
	detector, err := detection.NewEngine(defaultRules(), alertManager)
	if err != nil {
		log.Fatalf("configure detection: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("argus-core listening on %s, event_store=%s", *grpcAddr, store.Path())
	err = ingestion.RunGRPCServer(ctx, ingestion.Config{
		Addr:        *grpcAddr,
		CertPath:    *certPath,
		KeyPath:     *keyPath,
		CAPath:      *caPath,
		BearerToken: *bearerToken,
		Store:       store,
		Processors:  []ingestion.EventProcessor{detector},
	})
	if err != nil {
		log.Fatalf("argus-core stopped: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func defaultRules() []rules.Rule {
	return []rules.Rule{
		{
			ID:       "ARGUS-AUTH-001",
			Name:     "Brute force authentication",
			Severity: "high",
			Match: rules.Match{
				EventType: "auth.failure",
			},
			GroupBy: []string{"site_id", "src_ip", "user"},
			Threshold: rules.Threshold{
				Count:  10,
				Window: time.Minute,
			},
			Actions: []string{"create_alert"},
		},
	}
}
