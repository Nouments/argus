package gateway

import (
	"context"
	"testing"

	agentpb "github.com/Nouments/argus/proto/agent"
)

func TestSubmitEventAcceptsValidEnvelope(t *testing.T) {
	server := NewServer()
	resp, err := server.SubmitEvent(context.Background(), &agentpb.EventEnvelope{
		EventId:   "evt-1",
		Timestamp: "2026-08-30T00:00:00Z",
		SiteId:    "site-a",
		AgentId:   "agent-01",
		EventType: "auth.failure",
		Severity:  "high",
		Host:      "srv-01",
		Raw:       "failed password",
	})
	if err != nil {
		t.Fatalf("SubmitEvent() returned error: %v", err)
	}
	if !resp.Accepted {
		t.Fatal("SubmitEvent() accepted was false")
	}
}

func TestSubmitEventRejectsMissingRequiredFields(t *testing.T) {
	server := NewServer()
	_, err := server.SubmitEvent(context.Background(), &agentpb.EventEnvelope{EventId: "evt-1"})
	if err == nil {
		t.Fatal("SubmitEvent() should reject incomplete payloads")
	}
}

func TestBuildServerOptionsWithMutualTLS(t *testing.T) {
	certPath := "./testdata/server.crt"
	keyPath := "./testdata/server.key"
	caPath := "./testdata/ca.crt"

	_, err := buildServerOptions(certPath, keyPath, caPath)
	if err == nil {
		t.Fatal("buildServerOptions() should fail when TLS material is missing")
	}

	_, err = buildServerOptions("", "", "")
	if err != nil {
		t.Fatalf("buildServerOptions() should allow plain mode, got error: %v", err)
	}
}

func TestValidateGatewayToken(t *testing.T) {
	t.Setenv("ARGUS_GATEWAY_TOKEN", "")
	if !validateGatewayToken("") {
		t.Fatal("validateGatewayToken() should allow empty token configuration")
	}

	t.Setenv("ARGUS_GATEWAY_TOKEN", "super-secret")
	if !validateGatewayToken("Bearer super-secret") {
		t.Fatal("validateGatewayToken() should accept the configured bearer token")
	}
	if validateGatewayToken("Bearer wrong-token") {
		t.Fatal("validateGatewayToken() should reject a wrong bearer token")
	}
}

func TestEnrollmentAndRefreshSession(t *testing.T) {
	t.Setenv("ARGUS_SESSION_SECRET", "test-secret-key-32-bytes-123456")

	enrollment, err := IssueEnrollmentToken("agent-42", "site-7")
	if err != nil {
		t.Fatalf("IssueEnrollmentToken() error: %v", err)
	}
	claims, err := ValidateAccessToken(enrollment)
	if err != nil {
		t.Fatalf("ValidateAccessToken() on enrollment token error: %v", err)
	}
	if claims.AgentID != "agent-42" || claims.SiteID != "site-7" {
		t.Fatalf("unexpected enrollment claims: %#v", claims)
	}

	session, err := IssueSessionPair("agent-42", "site-7")
	if err != nil {
		t.Fatalf("IssueSessionPair() error: %v", err)
	}
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Fatal("session pair should include access and refresh tokens")
	}

	accessClaims, err := ValidateAccessToken(session.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() on session access token error: %v", err)
	}
	if accessClaims.AgentID != "agent-42" {
		t.Fatalf("unexpected access claims: %#v", accessClaims)
	}

	rotated, err := RotateRefreshToken(session.RefreshToken)
	if err != nil {
		t.Fatalf("RotateRefreshToken() error: %v", err)
	}
	if rotated.AccessToken == "" || rotated.RefreshToken == "" {
		t.Fatal("rotated session should produce fresh tokens")
	}
	if rotated.RefreshToken == session.RefreshToken {
		t.Fatal("refresh token should rotate on refresh")
	}
}
