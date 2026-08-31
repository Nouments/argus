package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/buffer"
	"github.com/Nouments/argus/apps/agent/internal/event"
)

func TestBuildSampleEvent(t *testing.T) {
	data, err := buildSampleEvent()
	if err != nil {
		t.Fatalf("buildSampleEvent() error: %v", err)
	}

	parsed, err := event.FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON() error: %v", err)
	}
	if parsed.EventID == "" || parsed.Raw == "" {
		t.Fatal("sample event missing required fields")
	}
}

func TestSendWithRetry(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	ok := sendWithRetry(server.Client(), server.URL, []byte(`{"event_id":"e-1","timestamp":"2026-08-30T00:00:00Z","site_id":"site-a","agent_id":"agent-01","event_type":"auth.failure","severity":"medium","host":"srv-01","raw":"failed password"}`), 3)
	if !ok {
		t.Fatal("sendWithRetry() returned false for transient failure")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected 2 attempts after transient failure, got %d", got)
	}
}

func TestAttemptFlushRemovesBufferedEventAfterSuccess(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir() error: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()

	bufPath := filepath.Join(dir, "buffer.enc")
	payload := []byte(`{"event_id":"e-2","timestamp":"2026-08-30T00:00:00Z","site_id":"site-a","agent_id":"agent-01","event_type":"auth.failure","severity":"medium","host":"srv-01","raw":"login failed"}`)
	if err := buffer.WriteEncryptedAppend(dir, "buffer.enc", key, payload); err != nil {
		t.Fatalf("WriteEncryptedAppend() error: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	if err := attemptFlush(bufPath, key, server.Client(), server.URL); err != nil {
		t.Fatalf("attemptFlush() error: %v", err)
	}

	if _, err := os.Stat(bufPath); !os.IsNotExist(err) {
		t.Fatalf("expected buffer file to be removed after successful flush, stat err=%v", err)
	}

	mockPath := filepath.Join("./data", "clickhouse_mock.jsonl")
	if _, err := os.Stat(mockPath); err != nil {
		t.Fatalf("expected mock ClickHouse append after successful flush, stat err=%v", err)
	}
}

func TestSendWithRetryReturnsFalseWhenMaxRetriesExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer server.Close()

	start := time.Now()
	ok := sendWithRetry(server.Client(), server.URL, []byte(`{"event_id":"e-3","timestamp":"2026-08-30T00:00:00Z","site_id":"site-a","agent_id":"agent-01","event_type":"auth.failure","severity":"medium","host":"srv-01","raw":"bad"}`), 2)
	if ok {
		t.Fatal("sendWithRetry() should fail after max retries")
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second {
		t.Fatalf("expected backoff delay before giving up, got %v", elapsed)
	}
}

func TestResolveDataDirAndVaultSecretPath(t *testing.T) {
	t.Setenv("ARGUS_DATA_DIR", "/tmp/custom-agent-data")
	t.Setenv("BUFFER_DIR", "/tmp/custom-buffer-dir")
	t.Setenv("VAULT_SECRET_PATH", "secret/data/custom")

	if got := resolveDataDir(); got != "/tmp/custom-agent-data" {
		t.Fatalf("resolveDataDir() = %q, want %q", got, "/tmp/custom-agent-data")
	}
	if got := resolveVaultSecretPath(); got != "secret/data/custom" {
		t.Fatalf("resolveVaultSecretPath() = %q, want %q", got, "secret/data/custom")
	}

	t.Setenv("ARGUS_DATA_DIR", "")
	if got := resolveDataDir(); got != "/tmp/custom-buffer-dir" {
		t.Fatalf("resolveDataDir() fallback = %q, want %q", got, "/tmp/custom-buffer-dir")
	}

	t.Setenv("BUFFER_DIR", "")
	t.Setenv("VAULT_SECRET_PATH", "")
	if got := resolveDataDir(); got != "./data" {
		t.Fatalf("resolveDataDir() default = %q, want %q", got, "./data")
	}
	if got := resolveVaultSecretPath(); got != "secret/data/siem/buffer" {
		t.Fatalf("resolveVaultSecretPath() default = %q, want %q", got, "secret/data/siem/buffer")
	}
}

func TestEventValidateRejectsMissingSiteID(t *testing.T) {
	e := event.Event{
		EventID:   "evt-1",
		Timestamp: "2026-08-30T00:00:00Z",
		AgentID:   "agent-01",
		EventType: "auth.failure",
		Severity:  "medium",
		Host:      "srv-01",
		Raw:       "test",
	}
	if err := e.Validate(); err == nil {
		t.Fatal("Validate() should reject event without SiteID")
	}
}

func TestResolveIdentityAndGatewayURL(t *testing.T) {
	t.Setenv("ARGUS_SITE_ID", "site-42")
	t.Setenv("ARGUS_AGENT_ID", "agent-42")
	t.Setenv("ARGUS_GATEWAY_URL", "https://gateway.example.com:8443/ingest")

	if got := resolveSiteID(); got != "site-42" {
		t.Fatalf("resolveSiteID() = %q, want %q", got, "site-42")
	}
	if got := resolveAgentID(); got != "agent-42" {
		t.Fatalf("resolveAgentID() = %q, want %q", got, "agent-42")
	}
	if got, err := resolveGatewayURL(); err != nil || got != "https://gateway.example.com:8443/ingest" {
		t.Fatalf("resolveGatewayURL() = (%q, %v), want (%q, nil)", got, err, "https://gateway.example.com:8443/ingest")
	}

	t.Setenv("ARGUS_SITE_ID", "")
	t.Setenv("ARGUS_AGENT_ID", "")
	t.Setenv("ARGUS_GATEWAY_URL", "")
	if got := resolveSiteID(); got != "site-a" {
		t.Fatalf("resolveSiteID() default = %q, want %q", got, "site-a")
	}
	if got := resolveAgentID(); got != "agent-01" {
		t.Fatalf("resolveAgentID() default = %q, want %q", got, "agent-01")
	}
	if got, err := resolveGatewayURL(); err != nil || got != *gatewayURL {
		t.Fatalf("resolveGatewayURL() default = (%q, %v), want (%q, nil)", got, err, *gatewayURL)
	}
}

func TestGatewayTargetForGRPC(t *testing.T) {
	got, err := grpcGatewayTarget("https://gateway.example.com:8443/ingest")
	if err != nil {
		t.Fatalf("grpcGatewayTarget() error: %v", err)
	}
	if got != "gateway.example.com:8443" {
		t.Fatalf("grpcGatewayTarget() = %q, want %q", got, "gateway.example.com:8443")
	}
}

func TestGatewayStatusShouldFallbackOnlyForTransientFailures(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{name: "success", statusCode: http.StatusOK, want: false},
		{name: "bad_request", statusCode: http.StatusBadRequest, want: false},
		{name: "request_timeout", statusCode: http.StatusRequestTimeout, want: true},
		{name: "too_many_requests", statusCode: http.StatusTooManyRequests, want: true},
		{name: "server_error", statusCode: http.StatusInternalServerError, want: true},
		{name: "gateway_timeout", statusCode: http.StatusGatewayTimeout, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldFallbackGatewayStatus(tc.statusCode); got != tc.want {
				t.Fatalf("shouldFallbackGatewayStatus(%d) = %v, want %v", tc.statusCode, got, tc.want)
			}
		})
	}
}
