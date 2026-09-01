package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agentpb "github.com/Nouments/argus/proto/agent"
)

type sessionClaims struct {
	AgentID    string `json:"agent_id"`
	SiteID     string `json:"site_id"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
	SessionID  string `json:"sid"`
	TokenType  string `json:"typ"`
	RefreshKey string `json:"rkey,omitempty"`
}

type sessionPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type refreshRecord struct {
	Token string
	Exp   time.Time
}

// Server implements the agent-to-gateway gRPC contract.
type Server struct {
	agentpb.UnimplementedAgentServiceServer
	mu      sync.RWMutex
	workers int
	refresh map[string]refreshRecord
	// optional ingestion client to forward events
	ingestionClient agentpb.AgentServiceClient
	ingestionConn   *grpc.ClientConn
}

// revokedSessions holds revoked session IDs and optional expiry.
var revokedMu sync.RWMutex
var revokedSessions = make(map[string]time.Time)

// enrollmentTokens stores issued enrollment tokens and expiry; single-use token is removed when consumed.
var enrollMu sync.RWMutex
var enrollmentTokens = make(map[string]time.Time)

// machine registry: map hashed fingerprint -> record
type machineRecord struct {
	AgentID  string
	SiteID   string
	Hostname string
	LastIP   string
	LastSeen time.Time
}

var machinesMu sync.RWMutex
var machineRegistry = make(map[string]machineRecord)

// addEnrollmentToken stores a token issued for enrollment
func addEnrollmentToken(token string, exp time.Time) {
	enrollMu.Lock()
	defer enrollMu.Unlock()
	enrollmentTokens[token] = exp
	// persist
	_ = saveBucketData("enroll", enrollmentTokens)
}

// validateAndConsumeEnrollment checks token exists, not expired and consumes it (single-use)
func validateAndConsumeEnrollment(token string) bool {
	enrollMu.Lock()
	defer enrollMu.Unlock()
	exp, ok := enrollmentTokens[token]
	if !ok {
		return false
	}
	if !exp.IsZero() && time.Now().After(exp) {
		delete(enrollmentTokens, token)
		_ = saveBucketData("enroll", enrollmentTokens)
		return false
	}
	// consume
	delete(enrollmentTokens, token)
	_ = saveBucketData("enroll", enrollmentTokens)
	return true
}

// registerOrUpdateMachine records machine fingerprint info
func registerOrUpdateMachine(fingerprint, agentID, siteID, hostname, ip string) {
	machinesMu.Lock()
	defer machinesMu.Unlock()
	machineRegistry[fingerprint] = machineRecord{AgentID: agentID, SiteID: siteID, Hostname: hostname, LastIP: ip, LastSeen: time.Now()}
	_ = saveBucketData("machines", machineRegistry)
}

// findMachineByFingerprint checks registry
func findMachineByFingerprint(fingerprint string) (machineRecord, bool) {
	machinesMu.RLock()
	defer machinesMu.RUnlock()
	m, ok := machineRegistry[fingerprint]
	return m, ok
}

// RevokeSession revokes the given session id until optional expiry (zero = indefinite).
func RevokeSession(sessionID string, until time.Time) {
	revokedMu.Lock()
	defer revokedMu.Unlock()
	revokedSessions[sessionID] = until
	_ = saveBucketData("revoked", revokedSessions)
}

// IsSessionRevoked checks whether a session is revoked.
func IsSessionRevoked(sessionID string) bool {
	revokedMu.RLock()
	defer revokedMu.RUnlock()
	if exp, ok := revokedSessions[sessionID]; ok {
		if exp.IsZero() {
			return true
		}
		if time.Now().Before(exp) {
			return true
		}
		// expired — cleanup
		go func() {
			revokedMu.Lock()
			delete(revokedSessions, sessionID)
			revokedMu.Unlock()
			_ = saveBucketData("revoked", revokedSessions)
		}()
	}
	return false
}

// NewServer creates a gateway server instance.
func NewServer() *Server {
	// try to load persisted maps if present
	_ = loadBucketData("enroll", &enrollmentTokens)
	_ = loadBucketData("revoked", &revokedSessions)
	_ = loadBucketData("machines", &machineRegistry)
	return &Server{workers: 8, refresh: make(map[string]refreshRecord)}
}

func NewServerWithIngestion(client agentpb.AgentServiceClient, conn *grpc.ClientConn) *Server {
	return &Server{workers: 8, refresh: make(map[string]refreshRecord), ingestionClient: client, ingestionConn: conn}
}

func validateGatewayToken(value string) bool {
	configured := strings.TrimSpace(os.Getenv("ARGUS_GATEWAY_TOKEN"))
	if configured == "" {
		return true
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	prefix := "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return strings.TrimSpace(strings.TrimPrefix(value, prefix)) == configured
}

func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info == nil || info.FullMethod == "" {
		return handler(ctx, req)
	}
	// allow either the static gateway token (for management) or a signed session token
	token := readBearerTokenFromContext(ctx)
	if validateGatewayToken(token) {
		return handler(ctx, req)
	}
	// try to validate as a session/access token (strip optional "Bearer " prefix)
	if strings.HasPrefix(strings.TrimSpace(token), "Bearer ") {
		t := strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
		if claims, err := ValidateAccessToken(t); err == nil {
			// check revocation by session id
			if claims.SessionID != "" && IsSessionRevoked(claims.SessionID) {
				return nil, status.Error(codes.Unauthenticated, "revoked session")
			}
			return handler(ctx, req)
		}
	}
	return nil, status.Error(codes.Unauthenticated, "invalid or missing bearer token")
}

func readBearerTokenFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func base64URL(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func decodeJWTPart(part string) ([]byte, error) {
	if part == "" {
		return nil, fmt.Errorf("empty jwt part")
	}
	if len(part)%4 != 0 {
		part += strings.Repeat("=", 4-len(part)%4)
	}
	return base64.URLEncoding.DecodeString(part)
}

func signPayload(secret string, payload []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write(payload)
	return base64URL(h.Sum(nil))
}

func issueSignedToken(secret string, claims sessionClaims) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerPart := base64URL(headerJSON)
	claimsPart := base64URL(claimsJSON)
	signature := signPayload(secret, []byte(headerPart+"."+claimsPart))
	return headerPart + "." + claimsPart + "." + signature, nil
}

func newSessionNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("nonce-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func ValidateAccessToken(token string) (*sessionClaims, error) {
	secret := strings.TrimSpace(os.Getenv("ARGUS_SESSION_SECRET"))
	if secret == "" {
		secret = "default-session-secret-change-me"
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	headerPart, claimsPart, sigPart := parts[0], parts[1], parts[2]
	expectedSig := signPayload(secret, []byte(headerPart+"."+claimsPart))
	if !hmac.Equal([]byte(expectedSig), []byte(sigPart)) {
		return nil, fmt.Errorf("invalid token signature")
	}
	claimsData, err := decodeJWTPart(claimsPart)
	if err != nil {
		return nil, err
	}
	var claims sessionClaims
	if err := json.Unmarshal(claimsData, &claims); err != nil {
		return nil, err
	}
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}
	return &claims, nil
}

func IssueEnrollmentToken(agentID, siteID string) (string, error) {
	secret := strings.TrimSpace(os.Getenv("ARGUS_SESSION_SECRET"))
	if secret == "" {
		secret = "default-session-secret-change-me"
	}
	claims := sessionClaims{
		AgentID:   agentID,
		SiteID:    siteID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
		SessionID: "enroll-" + agentID + "-" + siteID,
		TokenType: "enrollment",
	}
	token, err := issueSignedToken(secret, claims)
	if err != nil {
		return "", err
	}
	// store as single-use enrollment token
	addEnrollmentToken(token, time.Unix(claims.ExpiresAt, 0))
	return token, nil
}

func IssueSessionPair(agentID, siteID string) (*sessionPair, error) {
	secret := strings.TrimSpace(os.Getenv("ARGUS_SESSION_SECRET"))
	if secret == "" {
		secret = "default-session-secret-change-me"
	}
	now := time.Now()
	sessionID := "sess-" + agentID + "-" + siteID + "-" + newSessionNonce()
	accessClaims := sessionClaims{
		AgentID:   agentID,
		SiteID:    siteID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(15 * time.Minute).Unix(),
		SessionID: sessionID,
		TokenType: "access",
	}
	refreshClaims := sessionClaims{
		AgentID:    agentID,
		SiteID:     siteID,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(7 * 24 * time.Hour).Unix(),
		SessionID:  sessionID,
		TokenType:  "refresh",
		RefreshKey: newSessionNonce(),
	}
	accessToken, err := issueSignedToken(secret, accessClaims)
	if err != nil {
		return nil, err
	}
	refreshToken, err := issueSignedToken(secret, refreshClaims)
	if err != nil {
		return nil, err
	}
	return &sessionPair{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func RotateRefreshToken(refreshToken string) (*sessionPair, error) {
	claims, err := ValidateAccessToken(refreshToken)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "refresh" {
		return nil, fmt.Errorf("token is not a refresh token")
	}
	if claims.SessionID == "" {
		return nil, fmt.Errorf("refresh token missing session id")
	}
	return IssueSessionPair(claims.AgentID, claims.SiteID)
}

// SubmitEvent accepts an event envelope from an agent and validates the minimum payload.
func (s *Server) SubmitEvent(ctx context.Context, in *agentpb.EventEnvelope) (*agentpb.SubmitEventResponse, error) {
	if in == nil {
		return nil, fmt.Errorf("nil event envelope")
	}
	if strings.TrimSpace(in.GetEventId()) == "" {
		return nil, fmt.Errorf("event_id is required")
	}
	if strings.TrimSpace(in.GetSiteId()) == "" {
		return nil, fmt.Errorf("site_id is required")
	}
	if strings.TrimSpace(in.GetAgentId()) == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if strings.TrimSpace(in.GetRaw()) == "" {
		return nil, fmt.Errorf("raw payload is required")
	}
	return &agentpb.SubmitEventResponse{Accepted: true, Message: "event accepted"}, nil
}

// SubmitEvents handles a client-side stream of EventEnvelope messages and replies with a single ack.
func (s *Server) SubmitEvents(stream agentpb.AgentService_SubmitEventsServer) error {
	var ids []string
	// if we have an ingestion client, forward the stream
	if s.ingestionClient != nil {
		clientStream, err := s.ingestionClient.SubmitEvents(stream.Context())
		if err != nil {
			return err
		}
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = clientStream.CloseSend()
				return err
			}
			if strings.TrimSpace(in.GetEventId()) == "" {
				continue
			}
			// forward to ingestion
			if err := clientStream.Send(in); err != nil {
				_ = clientStream.CloseSend()
				return err
			}
			ids = append(ids, in.GetEventId())
		}
		// close client stream and receive ack from ingestion
		ingAck, err := clientStream.CloseAndRecv()
		if err != nil {
			return err
		}
		// return an ack that contains ingestion's accepted flag and the forwarded ids
		ack := &agentpb.SubmitEventAck{Accepted: ingAck.GetAccepted(), EventId: ids}
		return stream.SendAndClose(ack)
	}
	// default: collect ids and ack locally
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			// end of stream
			break
		}
		if err != nil {
			return err
		}
		if strings.TrimSpace(in.GetEventId()) == "" {
			continue
		}
		ids = append(ids, in.GetEventId())
	}
	ack := &agentpb.SubmitEventAck{Accepted: true, EventId: ids}
	return stream.SendAndClose(ack)
}

// buildServerOptions configures gRPC server credentials with mTLS when certificates are available.
func buildServerOptions(certPath, keyPath, caPath string) ([]grpc.ServerOption, error) {
	if certPath == "" && keyPath == "" && caPath == "" {
		return []grpc.ServerOption{}, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("both cert and key are required for TLS")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse CA certificate")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(cfg))}, nil
}

// RunGRPCServer starts a gRPC listener for the agent service.
func RunGRPCServer(addr, certPath, keyPath, caPath string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	opts, err := buildServerOptions(certPath, keyPath, caPath)
	if err != nil {
		_ = listener.Close()
		return err
	}
	// if ARGUS_INGESTION_ADDR is set, create a client to forward events
	ingestionAddr := strings.TrimSpace(os.Getenv("ARGUS_INGESTION_ADDR"))
	var srv *grpc.Server
	if ingestionAddr != "" {
		// dial ingestion
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := grpc.DialContext(ctx, ingestionAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			_ = listener.Close()
			return err
		}
		client := agentpb.NewAgentServiceClient(conn)
		srv = grpc.NewServer(append([]grpc.ServerOption{grpc.UnaryInterceptor(authInterceptor)}, opts...)...)
		agentpb.RegisterAgentServiceServer(srv, NewServerWithIngestion(client, conn))
	} else {
		srv = grpc.NewServer(append([]grpc.ServerOption{grpc.UnaryInterceptor(authInterceptor)}, opts...)...)
		agentpb.RegisterAgentServiceServer(srv, NewServer())
	}
	return srv.Serve(listener)
}
