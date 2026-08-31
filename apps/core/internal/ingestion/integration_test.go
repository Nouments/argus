package ingestion

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Nouments/argus/apps/core/internal/storage"
	agentpb "github.com/Nouments/argus/proto/agent"
)

func TestSubmitEventsIntegration(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()
	path := filepath.Join(tmpdir, "events.jsonl")
	store, err := storage.NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore() error: %v", err)
	}
	defer store.Close()

	// start gRPC server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	agentSrv := NewServer(store)
	agentpb.RegisterAgentServiceServer(srv, agentSrv)

	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	// dial
	addr := lis.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := agentpb.NewAgentServiceClient(conn)
	streamCtx, streamCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer streamCancel()
	stream, err := client.SubmitEvents(streamCtx)
	if err != nil {
		t.Fatalf("SubmitEvents create: %v", err)
	}

	msgs := []*agentpb.EventEnvelope{
		{
			EventId:   "evt-1",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SiteId:    "site-1",
			AgentId:   "agent-1",
			EventType: "sys.login",
			Severity:  "low",
			Host:      "host-1",
			Raw:       "payload-1",
		},
		{
			EventId:   "evt-2",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SiteId:    "site-1",
			AgentId:   "agent-1",
			EventType: "sys.login",
			Severity:  "low",
			Host:      "host-1",
			Raw:       "payload-2",
		},
	}

	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("close and recv: %v", err)
	}
	if ack == nil || !ack.GetAccepted() {
		t.Fatalf("unexpected ack: %v", ack)
	}
	if len(ack.GetEventId()) != len(msgs) {
		t.Fatalf("expected %d event ids in ack, got %d", len(msgs), len(ack.GetEventId()))
	}
}
