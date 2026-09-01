package transport_test

import (
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Nouments/argus/apps/agent/internal/collector"
	"github.com/Nouments/argus/apps/agent/internal/event"
	"github.com/Nouments/argus/apps/agent/internal/pipeline"
	"github.com/Nouments/argus/apps/agent/internal/transport"
	agentpb "github.com/Nouments/argus/proto/agent"
)

// fakeServer implements the AgentService to capture received envelopes.
type fakeServer struct {
	agentpb.UnimplementedAgentServiceServer
	received int32
}

func (f *fakeServer) SubmitEvent(ctx context.Context, req *agentpb.EventEnvelope) (*agentpb.SubmitEventResponse, error) {
	atomic.AddInt32(&f.received, 1)
	return &agentpb.SubmitEventResponse{Accepted: true, Message: "ok"}, nil
}

func (f *fakeServer) SubmitEvents(stream agentpb.AgentService_SubmitEventsServer) error {
	for {
		_, err := stream.Recv()
		if err != nil {
			// client closed stream
			break
		}
		atomic.AddInt32(&f.received, 1)
	}
	return stream.SendAndClose(&agentpb.SubmitEventAck{Accepted: true})
}

type fakeCollectorImpl struct {
	name string
	raw  []byte
}

func (f *fakeCollectorImpl) Name() string             { return f.name }
func (f *fakeCollectorImpl) Collect() ([]byte, error) { return f.raw, nil }

func TestPipelineToTransportIntegration(t *testing.T) {
	// start local grpc server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	fs := &fakeServer{}
	agentpb.RegisterAgentServiceServer(srv, fs)
	go srv.Serve(lis)
	defer srv.Stop()

	// create a simple pipeline with a fake collector producing a valid event JSON
	e := &event.Event{
		EventID: "e-1", Timestamp: time.Now().UTC().Format(time.RFC3339), SiteID: "site-a", AgentID: "agent-01",
		EventType: "test.event", Severity: "low", Host: "localhost", Raw: "raw", Integrity: "i"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	reg := collector.NewRegistry()
	_ = reg.Register(&fakeCollectorImpl{name: "fake", raw: b})
	p := pipeline.New(reg, nil)

	// create client against server
	client, err := transport.NewGRPCClient(context.Background(), lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	// run pipeline
	items, err := p.Process()
	if err != nil {
		t.Fatalf("pipeline process: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("no payloads from pipeline")
	}

	// convert to envelopes and send as batch
	envelopes := make([]*transport.EventEnvelope, 0, len(items))
	for _, it := range items {
		ev, err := event.FromJSON(it.Raw)
		if err != nil {
			t.Fatalf("from json: %v", err)
		}
		envelopes = append(envelopes, transport.EventToEnvelope(ev))
	}
	if err := client.SendBatch(envelopes); err != nil {
		t.Fatalf("send batch: %v", err)
	}

	// allow server to process
	time.Sleep(200 * time.Millisecond)
	if atomic.LoadInt32(&fs.received) != int32(len(envelopes)) {
		t.Fatalf("server received %d, want %d", fs.received, len(envelopes))
	}
}
