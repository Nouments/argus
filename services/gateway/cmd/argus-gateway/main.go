package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Nouments/argus/services/gateway"
)

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func main() {
	httpAddr := envOrDefault("ARGUS_GATEWAY_HTTP_ADDR", ":8080")
	grpcAddr := envOrDefault("ARGUS_GATEWAY_GRPC_ADDR", ":8443")
	certPath := strings.TrimSpace(os.Getenv("ARGUS_GATEWAY_CERT"))
	keyPath := strings.TrimSpace(os.Getenv("ARGUS_GATEWAY_KEY"))
	caPath := strings.TrimSpace(os.Getenv("ARGUS_GATEWAY_CA"))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() {
		log.Printf("gateway HTTP listening on %s", httpAddr)
		errCh <- gateway.StartHTTPServer(httpAddr)
	}()
	go func() {
		log.Printf("gateway gRPC listening on %s", grpcAddr)
		errCh <- gateway.RunGRPCServer(grpcAddr, certPath, keyPath, caPath)
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("gateway shutdown requested")
			return
		case err := <-errCh:
			if err == nil || err == http.ErrServerClosed {
				log.Println("gateway server stopped cleanly")
				return
			}
			log.Printf("gateway exited: %v", err)
			return
		}
	}
}
