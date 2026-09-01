package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	agentpb "github.com/Nouments/argus/proto/agent"
)

// dummy server that verifies authorization metadata contains a valid token
type dummyIngest struct {
	agentpb.UnimplementedAgentServiceServer
}

func (d *dummyIngest) SubmitEvent(ctx context.Context, in *agentpb.EventEnvelope) (*agentpb.SubmitEventResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return &agentpb.SubmitEventResponse{Accepted: false, Message: "no auth"}, nil
	}
	// validate token
	token := vals[0]
	if len(token) > 7 && token[:7] == "Bearer " {
		t := token[7:]
		if _, err := ValidateAccessToken(t); err == nil {
			return &agentpb.SubmitEventResponse{Accepted: true, Message: "ok"}, nil
		}
	}
	return &agentpb.SubmitEventResponse{Accepted: false, Message: "invalid"}, nil
}

func TestEnrollAndGRPCAuth(t *testing.T) {
	os.Setenv("ARGUS_SESSION_SECRET", "test-secret-12345")
	// ensure static gateway token is set to prevent automatic allow
	os.Setenv("ARGUS_GATEWAY_TOKEN", "disabled-static-token")
	// Start HTTP test server with enroll/session/revoke handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", enrollHandler)
	mux.HandleFunc("/session", sessionHandler)
	mux.HandleFunc("/revoke", revokeHandler)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// HTTP client
	client := &http.Client{Timeout: 5 * time.Second}

	// Generate agent id/site
	aid := "agent-" + hex.EncodeToString(randomBytes(4))
	sid := "site-test"

	// Enroll: POST /enroll
	enrollReq := map[string]string{"agent_id": aid, "site_id": sid}
	b := mustJSON(t, enrollReq)
	resp, err := client.Post(ts.URL+"/enroll", "application/json", stringsNewReader(b))
	if err != nil {
		t.Fatalf("enroll request failed: %v", err)
	}
	var er struct {
		EnrollmentToken string `json:"enrollment_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode enroll resp: %v", err)
	}
	if er.EnrollmentToken == "" {
		t.Fatal("empty enrollment token")
	}
	// Exchange for session
	req2, _ := http.NewRequestWithContext(context.Background(), "POST", ts.URL+"/session", nil)
	req2.Header.Set("Authorization", "Bearer "+er.EnrollmentToken)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("session exchange failed: %v", err)
	}
	var pair struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&pair); err != nil {
		t.Fatalf("decode session resp: %v", err)
	}
	if pair.AccessToken == "" {
		t.Fatal("no access token returned")
	}

	// Start a gRPC server expecting Bearer token
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor))
	agentpb.RegisterAgentServiceServer(s, &dummyIngest{})
	go s.Serve(lis)
	defer s.Stop()

	// Dial raw gRPC client and call SubmitEvent with metadata
	connClient, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial grpc: %v", err)
	}
	defer connClient.Close()
	cl := agentpb.NewAgentServiceClient(connClient)
	md := metadata.New(map[string]string{"authorization": "Bearer " + pair.AccessToken})
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	if resp, err := cl.SubmitEvent(ctx, &agentpb.EventEnvelope{EventId: "evt-1"}); err != nil || !resp.GetAccepted() {
		t.Fatalf("grpc SubmitEvent failed: %v resp:%v", err, resp)
	}

	// Now revoke the session using the HTTP endpoint
	reqBody := struct {
		Token string `json:"token"`
	}{Token: pair.AccessToken}
	// marshal and post
	// simple POST
	req, _ := http.NewRequest("POST", ts.URL+"/revoke", stringsNewReader(mustJSON(t, reqBody)))
	req.Header.Set("Content-Type", "application/json")
	respRev, err := client.Do(req)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if respRev.StatusCode >= 300 {
		t.Fatalf("revoke failed: status=%v", respRev.StatusCode)
	}

	// After revocation, client should be rejected. Make a direct gRPC call with metadata to simulate
	// Create a raw gRPC connection and invoke SubmitEvent with metadata
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial raw: %v", err)
	}
	defer conn.Close()
	cl2 := agentpb.NewAgentServiceClient(conn)
	md2 := metadata.New(map[string]string{"authorization": "Bearer " + pair.AccessToken})
	ctx2 := metadata.NewOutgoingContext(context.Background(), md2)
	grpcResp2, grpcErr2 := cl2.SubmitEvent(ctx2, &agentpb.EventEnvelope{EventId: "evt-2"})
	if grpcErr2 == nil && grpcResp2 != nil && grpcResp2.GetAccepted() {
		t.Fatalf("expected rejected after revocation, got accepted")
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return string(b)
}

func stringsNewReader(s string) *strings.Reader { return strings.NewReader(s) }
