package transport

import (
	"context"
	"net"
	"testing"

	agentpb "github.com/Nouments/argus/proto/agent"
	"google.golang.org/grpc"
)

// testServer implements a minimal AgentService server for testing SubmitEvents.
type testServer struct {
	agentpb.UnimplementedAgentServiceServer
	received int
}

func (s *testServer) SubmitEvents(stream agentpb.AgentService_SubmitEventsServer) error {
	for {
		_, err := stream.Recv()
		if err != nil {
			if err.Error() == "EOF" { // client closed
				break
			}
			return err
		}
		s.received++
	}
	ack := &agentpb.SubmitEventAck{Accepted: true}
	return stream.SendAndClose(ack)
}

func TestSendBatch_Succeeds(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	ts := &testServer{}
	agentpb.RegisterAgentServiceServer(srv, ts)
	go srv.Serve(lis)
	defer srv.Stop()

	target := lis.Addr().String()
	client, err := NewGRPCClient(context.Background(), target, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msgs := []*EventEnvelope{{EventId: "e1"}, {EventId: "e2"}}
	if err := client.SendBatch(msgs); err != nil {
		t.Fatalf("SendBatch failed: %v", err)
	}
}
