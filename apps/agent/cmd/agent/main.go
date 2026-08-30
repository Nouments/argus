package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/auth"
	"github.com/Nouments/argus/apps/agent/internal/buffer"
	"github.com/Nouments/argus/apps/agent/internal/event"
	"github.com/Nouments/argus/apps/agent/internal/storage"
	"github.com/Nouments/argus/apps/agent/internal/transport"
)

var (
	gatewayURL = flag.String("gateway", "http://localhost:8443/ingest", "gateway ingest URL")
	certPath   = flag.String("cert", "", "client cert path")
	keyPath    = flag.String("key", "", "client key path")
	caPath     = flag.String("ca", "", "CA cert path")
)

func resolveDataDir() string {
	if dir := strings.TrimSpace(os.Getenv("ARGUS_DATA_DIR")); dir != "" {
		return dir
	}
	if dir := strings.TrimSpace(os.Getenv("BUFFER_DIR")); dir != "" {
		return dir
	}
	return "./data"
}

func resolveVaultSecretPath() string {
	if path := strings.TrimSpace(os.Getenv("VAULT_SECRET_PATH")); path != "" {
		return path
	}
	return "secret/data/siem/buffer"
}

func resolveSiteID() string {
	if siteID := strings.TrimSpace(os.Getenv("ARGUS_SITE_ID")); siteID != "" {
		return siteID
	}
	if siteID := strings.TrimSpace(os.Getenv("SITE_ID")); siteID != "" {
		return siteID
	}
	return "site-a"
}

func resolveAgentID() string {
	if agentID := strings.TrimSpace(os.Getenv("ARGUS_AGENT_ID")); agentID != "" {
		return agentID
	}
	if agentID := strings.TrimSpace(os.Getenv("AGENT_ID")); agentID != "" {
		return agentID
	}
	return "agent-01"
}

func resolveGatewayURL() (string, error) {
	if rawURL := strings.TrimSpace(os.Getenv("ARGUS_GATEWAY_URL")); rawURL != "" {
		return normalizeGatewayURL(rawURL)
	}
	if rawURL := strings.TrimSpace(os.Getenv("GATEWAY_URL")); rawURL != "" {
		return normalizeGatewayURL(rawURL)
	}
	return normalizeGatewayURL(*gatewayURL)
}

func normalizeGatewayURL(rawURL string) (string, error) {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid gateway URL: %q", rawURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("gateway URL must use http or https: %q", rawURL)
	}
	return parsed.String(), nil
}

func main() {
	flag.Parse()

	gateway, err := resolveGatewayURL()
	if err != nil {
		log.Fatalf("gateway config: %v", err)
	}
	*gatewayURL = gateway

	grpcTarget, err := grpcGatewayTarget(*gatewayURL)
	if err != nil {
		log.Fatalf("gateway target: %v", err)
	}

	grpcClient, err := transport.NewSecureGRPCClient(context.Background(), grpcTarget, *certPath, *keyPath, *caPath)
	if err != nil {
		log.Fatalf("configure grpc client: %v", err)
	}
	defer grpcClient.Close()

	sample, err := buildSampleEvent()
	if err != nil {
		log.Fatalf("build sample event: %v", err)
	}

	ev, err := event.FromJSON(sample)
	if err != nil {
		log.Fatalf("parse sample event: %v", err)
	}
	msg := transport.EventToEnvelope(ev)
	if err := grpcClient.Send(msg); err != nil {
		var key []byte
		secretPath := resolveVaultSecretPath()
		if b, errv := auth.GetKeyFromVault(secretPath); errv == nil {
			key = b
			fmt.Println("obtained buffer key from Vault")
		} else {
			key = make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				log.Fatalf("keygen: %v", err)
			}
			if errw := auth.WriteKeyToVault(secretPath, key); errw == nil {
				fmt.Println("generated key written to Vault")
			} else {
				dir := resolveDataDir()
				keyPath := filepath.Join(dir, "buffer.key")
				if err := os.MkdirAll(dir, 0o700); err == nil {
					_ = os.WriteFile(keyPath, []byte(hex.EncodeToString(key)), 0o600)
				}
			}
		}
		dir := resolveDataDir()
		if err := buffer.WriteEncryptedAppend(dir, "buffer.enc", key, []byte(sample)); err != nil {
			log.Fatalf("buffer write failed: %v", err)
		}
		fmt.Println("gateway unavailable — event buffered encrypted to ./data/buffer.enc")
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			flushGRPCBufferLoop(ctx, grpcTarget, filepath.Join(dir, "buffer.enc"), key)
		}()
		time.Sleep(10 * time.Second)
		cancel()
		wg.Wait()
		return
	}
	fmt.Printf("grpc gateway accepted event: %s\n", ev.EventID)
}

// flushBufferLoop is kept for compatibility with the legacy HTTP-based tests and existing code paths.
func flushBufferLoop(ctx context.Context, client *http.Client, bufferPath string, key []byte, gatewayURL string) {
	interval := 30 * time.Second
	if s := os.Getenv("BUFFER_FLUSH_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			interval = d
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := attemptFlush(bufferPath, key, client, gatewayURL); err != nil {
				log.Printf("flush attempt error: %v", err)
			}
		}
	}
}

func flushGRPCBufferLoop(ctx context.Context, grpcTarget, bufferPath string, key []byte) {
	interval := 30 * time.Second
	if s := os.Getenv("BUFFER_FLUSH_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			interval = d
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := attemptGRPCFlush(grpcTarget, bufferPath, key); err != nil {
				log.Printf("flush attempt error: %v", err)
			}
		}
	}
}

func attemptFlush(bufferPath string, key []byte, client *http.Client, gatewayURL string) error {
	rawLines, err := buffer.ReadRawLines(bufferPath)
	if err != nil {
		return err
	}
	if len(rawLines) == 0 {
		return nil
	}
	remaining := make([]string, 0, len(rawLines))
	pts, err := buffer.ReadAndDecryptAll(bufferPath, key)
	if err != nil {
		return err
	}
	if len(pts) != len(rawLines) {
		return fmt.Errorf("mismatch decrypted vs raw lines")
	}
	for i, pt := range pts {
		ok := sendWithRetry(client, gatewayURL, pt, 3)
		if !ok {
			remaining = append(remaining, rawLines[i])
		}
		if ok {
			_ = storage.ClickHouseWriteMock("./data", "clickhouse_mock.jsonl", pt)
		}
	}
	if len(remaining) == 0 {
		_ = os.Remove(bufferPath)
		return nil
	}
	return buffer.OverwriteRawLines(bufferPath, remaining)
}

func attemptGRPCFlush(grpcTarget, bufferPath string, key []byte) error {
	rawLines, err := buffer.ReadRawLines(bufferPath)
	if err != nil {
		return err
	}
	if len(rawLines) == 0 {
		return nil
	}
	pts, err := buffer.ReadAndDecryptAll(bufferPath, key)
	if err != nil {
		return err
	}
	if len(pts) != len(rawLines) {
		return fmt.Errorf("mismatch decrypted vs raw lines")
	}
	remaining := make([]string, 0, len(rawLines))
	for i, pt := range pts {
		ev, err := event.FromJSON([]byte(pt))
		if err != nil {
			remaining = append(remaining, rawLines[i])
			continue
		}
		client, err := transport.NewSecureGRPCClient(context.Background(), grpcTarget, *certPath, *keyPath, *caPath)
		if err != nil {
			return err
		}
		err = client.Send(transport.EventToEnvelope(ev))
		_ = client.Close()
		if err != nil {
			remaining = append(remaining, rawLines[i])
			continue
		}
		_ = storage.ClickHouseWriteMock("./data", "clickhouse_mock.jsonl", pt)
	}
	if len(remaining) == 0 {
		_ = os.Remove(bufferPath)
		return nil
	}
	return buffer.OverwriteRawLines(bufferPath, remaining)
}

func buildSampleEvent() ([]byte, error) {
	e := event.Event{
		EventID:   fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SiteID:    resolveSiteID(),
		AgentID:   resolveAgentID(),
		EventType: "auth.failure",
		Severity:  "medium",
		Host:      "srv-01",
		Raw:       "failed password",
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func newHTTPClient(certPath, keyPath, caPath string) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
	}

	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		if caPath != "" {
			ca, err := os.ReadFile(caPath)
			if err != nil {
				return nil, fmt.Errorf("read ca: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return nil, fmt.Errorf("parse ca certificate")
			}
			transport.TLSClientConfig.RootCAs = pool
			transport.TLSClientConfig.InsecureSkipVerify = false
		}
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func grpcGatewayTarget(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Host != "" {
		return parsed.Host, nil
	}
	return rawURL, nil
}

func shouldFallbackGatewayStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	}
	return statusCode >= http.StatusInternalServerError
}

func sendWithRetry(client *http.Client, url string, body []byte, maxRetries int) bool {
	var attempt int
	for {
		attempt++
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
		if err != nil {
			cancel()
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		cancel()
		if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return true
		}
		if attempt >= maxRetries {
			return false
		}
		backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
		time.Sleep(backoff)
	}
}
