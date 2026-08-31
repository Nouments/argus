package ingestion

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/Nouments/argus/pkg/events"
	agentpb "github.com/Nouments/argus/proto/agent"
)

type memoryStore struct {
	items []events.Event
	err   error
}

func (s *memoryStore) SaveEvent(_ context.Context, ev events.Event) error {
	if s.err != nil {
		return s.err
	}
	s.items = append(s.items, ev)
	return nil
}

type memoryProcessor struct {
	items []events.Event
	err   error
}

func (p *memoryProcessor) ProcessEvent(_ context.Context, ev events.Event) error {
	if p.err != nil {
		return p.err
	}
	p.items = append(p.items, ev)
	return nil
}

func validEnvelope() *agentpb.EventEnvelope {
	return &agentpb.EventEnvelope{
		EventId:   "evt-1",
		Timestamp: "2026-08-30T12:00:00Z",
		SiteId:    "site-a",
		AgentId:   "agent-01",
		EventType: "auth.failure",
		Severity:  "high",
		Host:      "srv-01",
		Raw:       "failed password",
	}
}

func TestSubmitEventRunsProcessorsAfterStore(t *testing.T) {
	store := &memoryStore{}
	processor := &memoryProcessor{}
	server := NewServer(store, processor)

	resp, err := server.SubmitEvent(context.Background(), validEnvelope())
	if err != nil {
		t.Fatalf("SubmitEvent() error: %v", err)
	}
	if !resp.GetAccepted() {
		t.Fatal("SubmitEvent() accepted = false")
	}
	if len(store.items) != 1 {
		t.Fatalf("stored events = %d, want 1", len(store.items))
	}
	if len(processor.items) != 1 {
		t.Fatalf("processed events = %d, want 1", len(processor.items))
	}
}

func TestSubmitEventStoresValidEnvelope(t *testing.T) {
	store := &memoryStore{}
	server := NewServer(store)
	server.now = func() time.Time {
		return time.Date(2026, 8, 30, 12, 1, 2, 0, time.UTC)
	}

	resp, err := server.SubmitEvent(context.Background(), validEnvelope())
	if err != nil {
		t.Fatalf("SubmitEvent() error: %v", err)
	}
	if !resp.GetAccepted() {
		t.Fatal("SubmitEvent() accepted = false")
	}
	if len(store.items) != 1 {
		t.Fatalf("stored events = %d, want 1", len(store.items))
	}
	got := store.items[0]
	if got.EventID != "evt-1" {
		t.Fatalf("stored EventID = %q, want evt-1", got.EventID)
	}
	if got.IntegrityHash == "" {
		t.Fatal("SubmitEvent() should compute integrity")
	}
	if got.ReceivedAt != "2026-08-30T12:01:02Z" {
		t.Fatalf("ReceivedAt = %q, want deterministic timestamp", got.ReceivedAt)
	}
}

func TestSubmitEventRejectsInvalidEnvelope(t *testing.T) {
	store := &memoryStore{}
	server := NewServer(store)
	in := validEnvelope()
	in.Timestamp = "not-a-timestamp"

	_, err := server.SubmitEvent(context.Background(), in)
	if err == nil {
		t.Fatal("SubmitEvent() should reject invalid envelope")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("status.Code() = %s, want %s", got, codes.InvalidArgument)
	}
	if len(store.items) != 0 {
		t.Fatal("invalid envelope should not be stored")
	}
}

func TestSubmitEventRequiresStore(t *testing.T) {
	server := NewServer(nil)

	_, err := server.SubmitEvent(context.Background(), validEnvelope())
	if err == nil {
		t.Fatal("SubmitEvent() should require a store")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("status.Code() = %s, want %s", got, codes.FailedPrecondition)
	}
}

func TestValidateBearerToken(t *testing.T) {
	if !validateBearerToken("", "") {
		t.Fatal("empty configured token should allow requests")
	}
	if !validateBearerToken("Bearer super-secret", "super-secret") {
		t.Fatal("configured token should accept matching bearer token")
	}
	if validateBearerToken("Bearer wrong", "super-secret") {
		t.Fatal("configured token should reject wrong bearer token")
	}
	if validateBearerToken("super-secret", "super-secret") {
		t.Fatal("configured token should require Bearer prefix")
	}
}

func TestBearerAuthInterceptor(t *testing.T) {
	interceptor := bearerAuthInterceptor("secret")
	handlerCalled := false
	handler := func(_ context.Context, _ any) (any, error) {
		handlerCalled = true
		return "ok", nil
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer secret"))
	resp, err := interceptor(ctx, nil, nil, handler)
	if err != nil {
		t.Fatalf("interceptor() error: %v", err)
	}
	if resp != "ok" || !handlerCalled {
		t.Fatal("interceptor() should call handler on valid token")
	}

	_, err = interceptor(context.Background(), nil, nil, handler)
	if err == nil {
		t.Fatal("interceptor() should reject missing token")
	}
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("status.Code() = %s, want %s", got, codes.Unauthenticated)
	}
}

func TestBuildServerOptions(t *testing.T) {
	opts, err := buildServerOptions("", "", "")
	if err != nil {
		t.Fatalf("buildServerOptions() plain error: %v", err)
	}
	if len(opts) != 0 {
		t.Fatalf("plain buildServerOptions() returned %d opts, want 0", len(opts))
	}

	_, err = buildServerOptions("server.crt", "", "")
	if err == nil {
		t.Fatal("buildServerOptions() should require cert and key together")
	}
}
