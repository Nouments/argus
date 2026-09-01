package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/Nouments/argus/apps/agent/internal/event"
	agentpb "github.com/Nouments/argus/proto/agent"
)

// EventEnvelope is the transport-level representation of an event used by gRPC payloads.
type EventEnvelope struct {
	EventId   string
	Timestamp string
	SiteId    string
	AgentId   string
	EventType string
	Severity  string
	Host      string
	Raw       string
	Integrity string
	CreatedAt time.Time
}

// EventToEnvelope converts the canonical application event into a transport envelope.
func EventToEnvelope(ev *event.Event) *EventEnvelope {
	if ev == nil {
		return nil
	}
	return &EventEnvelope{
		EventId:   ev.EventID,
		Timestamp: ev.Timestamp,
		SiteId:    ev.SiteID,
		AgentId:   ev.AgentID,
		EventType: ev.EventType,
		Severity:  ev.Severity,
		Host:      ev.Host,
		Raw:       ev.Raw,
		Integrity: ev.Integrity,
		CreatedAt: time.Now().UTC(),
	}
}

// EnvelopeToEvent converts a transport envelope back to the application event.
func EnvelopeToEvent(msg *EventEnvelope) (*event.Event, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil envelope")
	}
	ev := &event.Event{
		EventID:   msg.EventId,
		Timestamp: msg.Timestamp,
		SiteID:    msg.SiteId,
		AgentID:   msg.AgentId,
		EventType: msg.EventType,
		Severity:  msg.Severity,
		Host:      msg.Host,
		Raw:       msg.Raw,
		Integrity: msg.Integrity,
	}
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	return ev, nil
}

// GRPCClient is a concrete gRPC-backed transport client using the generated proto contract.
type GRPCClient struct {
	conn   *grpc.ClientConn
	client agentpb.AgentServiceClient
	// optional bearer token to attach as outgoing metadata
	bearerToken string
}

// NewGRPCClient creates a gRPC client bound to a target and optional dial options.
func NewGRPCClient(ctx context.Context, target string, opts ...grpc.DialOption) (*GRPCClient, error) {
	if target == "" {
		return nil, fmt.Errorf("empty grpc target")
	}
	conn, err := grpc.DialContext(ctx, target, opts...)
	if err != nil {
		return nil, err
	}
	return &GRPCClient{
		conn:   conn,
		client: agentpb.NewAgentServiceClient(conn),
	}, nil
}

// NewGRPCClientWithBearer creates a gRPC client and configures an outgoing bearer token.
func NewGRPCClientWithBearer(ctx context.Context, target, bearer string, opts ...grpc.DialOption) (*GRPCClient, error) {
	c, err := NewGRPCClient(ctx, target, opts...)
	if err != nil {
		return nil, err
	}
	c.bearerToken = strings.TrimSpace(bearer)
	return c, nil
}

// NewSecureGRPCClient creates a TLS-enabled gRPC client using mTLS when certificates are provided.
func NewSecureGRPCClient(ctx context.Context, target, certPath, keyPath, caPath string) (*GRPCClient, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if certPath != "" || keyPath != "" || caPath != "" {
		if certPath != "" && keyPath != "" {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, fmt.Errorf("load client cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
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
			tlsConfig.RootCAs = pool
		}
		opts = []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}
	}
	return NewGRPCClient(ctx, target, opts...)
}

// Send implements the transport contract by encoding an application envelope into the generated protobuf message.
func (c *GRPCClient) Send(msg *EventEnvelope) error {
	if c == nil || c.client == nil || msg == nil {
		return nil
	}
	// Use a bounded retry with exponential backoff to improve robustness
	var lastErr error
	maxAttempts := 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// build base context and attach authorization metadata when configured
		baseCtx := context.Background()
		if c != nil && strings.TrimSpace(c.bearerToken) != "" {
			baseCtx = metadata.AppendToOutgoingContext(baseCtx, "authorization", "Bearer "+c.bearerToken)
		}
		ctx, cancel := context.WithTimeout(baseCtx, 10*time.Second)
		_, err := c.client.SubmitEvent(ctx, EventEnvelopeToProto(msg))
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		// simple exponential backoff
		backoff := time.Duration(1<<uint(attempt)) * time.Second
		time.Sleep(backoff)
	}
	return lastErr
}

// Close releases the underlying gRPC connection when present.
func (c *GRPCClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// SendBatch sends multiple envelopes using the client-side streaming RPC SubmitEvents.
func (c *GRPCClient) SendBatch(msgs []*EventEnvelope) error {
	if c == nil || c.client == nil || len(msgs) == 0 {
		return nil
	}
	var lastErr error
	maxAttempts := 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		baseCtx := context.Background()
		if c != nil && strings.TrimSpace(c.bearerToken) != "" {
			baseCtx = metadata.AppendToOutgoingContext(baseCtx, "authorization", "Bearer "+c.bearerToken)
		}
		ctx, cancel := context.WithTimeout(baseCtx, 30*time.Second)
		stream, err := c.client.SubmitEvents(ctx)
		if err != nil {
			lastErr = err
			cancel()
			// backoff and retry
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
			continue
		}
		sendErr := error(nil)
		for _, m := range msgs {
			if m == nil {
				continue
			}
			if err := stream.Send(EventEnvelopeToProto(m)); err != nil {
				sendErr = err
				break
			}
		}
		if sendErr != nil {
			_ = stream.CloseSend()
			cancel()
			lastErr = sendErr
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
			continue
		}
		ack, err := stream.CloseAndRecv()
		cancel()
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
			continue
		}
		if ack == nil || !ack.GetAccepted() {
			lastErr = fmt.Errorf("batch not accepted: %v", ack)
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
			continue
		}
		return nil
	}
	return lastErr
}

// EventEnvelopeToProto converts the app envelope into the gRPC contract message.
func EventEnvelopeToProto(msg *EventEnvelope) *agentpb.EventEnvelope {
	if msg == nil {
		return nil
	}
	return &agentpb.EventEnvelope{
		EventId:   msg.EventId,
		Timestamp: msg.Timestamp,
		SiteId:    msg.SiteId,
		AgentId:   msg.AgentId,
		EventType: msg.EventType,
		Severity:  msg.Severity,
		Host:      msg.Host,
		Raw:       msg.Raw,
		Integrity: msg.Integrity,
	}
}

// ProtoEnvelopeToEvent converts the generated proto message back into the app envelope.
func ProtoEnvelopeToEvent(msg *agentpb.EventEnvelope) (*EventEnvelope, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil proto envelope")
	}
	return &EventEnvelope{
		EventId:   msg.GetEventId(),
		Timestamp: msg.GetTimestamp(),
		SiteId:    msg.GetSiteId(),
		AgentId:   msg.GetAgentId(),
		EventType: msg.GetEventType(),
		Severity:  msg.GetSeverity(),
		Host:      msg.GetHost(),
		Raw:       msg.GetRaw(),
		Integrity: msg.GetIntegrity(),
		CreatedAt: time.Now().UTC(),
	}, nil
}

// GatewayTargetFromURL extracts the host:port target suitable for gRPC dialing from a gateway URL.
func GatewayTargetFromURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty gateway URL")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Host != "" {
		return parsed.Host, nil
	}
	return rawURL, nil
}
