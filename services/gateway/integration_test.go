package gateway

import (
	"context"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	agentpb "github.com/Nouments/argus/proto/agent"
)

func TestGatewayForwardsToIngestion(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "events.jsonl")
	if err := os.WriteFile(storePath, []byte(""), 0o600); err != nil {
		t.Fatalf("create store file: %v", err)
	}

	// start ingestion server
	ilis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ingest listen: %v", err)
	}
	isrv := grpc.NewServer()
	// register a lightweight ingestion stub that writes event ids to the JSONL store path
	agentpb.RegisterAgentServiceServer(isrv, &ingestStub{path: storePath})
	go func() { _ = isrv.Serve(ilis) }()
	defer isrv.Stop()

	ingestionAddr := ilis.Addr().String()

	// start gateway pointing to ingestion
	os.Setenv("ARGUS_INGESTION_ADDR", ingestionAddr)
	defer os.Unsetenv("ARGUS_INGESTION_ADDR")

	glis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("gateway listen: %v", err)
	}
	gaddr := glis.Addr().String()
	// close temporary listener and let RunGRPCServer bind the same address
	_ = glis.Close()
	// run gateway server in goroutine
	go func() {
		_ = RunGRPCServer(gaddr, "", "", "")
	}()
	// give server a moment to start
	time.Sleep(200 * time.Millisecond)

	// connect to gateway
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, gaddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	client := agentpb.NewAgentServiceClient(conn)

	streamCtx, streamCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer streamCancel()
	stream, err := client.SubmitEvents(streamCtx)
	if err != nil {
		t.Fatalf("SubmitEvents: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	msgs := []*agentpb.EventEnvelope{
		{EventId: "g-1", Timestamp: now, SiteId: "s1", AgentId: "a1", EventType: "sys.ping", Severity: "low", Host: "h1", Raw: "r1"},
		{EventId: "g-2", Timestamp: now, SiteId: "s1", AgentId: "a1", EventType: "sys.ping", Severity: "low", Host: "h1", Raw: "r2"},
	}
	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("close recv: %v", err)
	}
	if ack == nil || !ack.GetAccepted() {
		t.Fatalf("unexpected ack: %v", ack)
	}

	// verify events written to JSONL store
	data, err := ioutil.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "g-1") || !strings.Contains(s, "g-2") {
		t.Fatalf("store missing events: %s", s)
	}
}

// ingestStub is a tiny AgentServiceServer that appends received event ids to a file.
type ingestStub struct {
	agentpb.UnimplementedAgentServiceServer
	path string
}

func (s *ingestStub) SubmitEvent(ctx context.Context, in *agentpb.EventEnvelope) (*agentpb.SubmitEventResponse, error) {
	return &agentpb.SubmitEventResponse{Accepted: true, Message: "ok"}, nil
}

func (s *ingestStub) SubmitEvents(stream agentpb.AgentService_SubmitEventsServer) error {
	var ids []string
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if in == nil {
			continue
		}
		ids = append(ids, in.GetEventId())
	}
	// append ids to file
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, id := range ids {
		if _, err := f.WriteString(id + "\n"); err != nil {
			return err
		}
	}
	ack := &agentpb.SubmitEventAck{Accepted: true, EventId: ids}
	return stream.SendAndClose(ack)
}
