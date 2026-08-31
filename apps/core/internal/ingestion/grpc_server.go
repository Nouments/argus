package ingestion

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/Nouments/argus/apps/core/internal/storage"
	"github.com/Nouments/argus/pkg/events"
	agentpb "github.com/Nouments/argus/proto/agent"
)

type Config struct {
	Addr        string
	CertPath    string
	KeyPath     string
	CAPath      string
	BearerToken string
	Store       storage.EventStore
	Processors  []EventProcessor
}

type EventProcessor interface {
	ProcessEvent(context.Context, events.Event) error
}

type Server struct {
	agentpb.UnimplementedAgentServiceServer
	store      storage.EventStore
	processors []EventProcessor
	now        func() time.Time
}

func NewServer(store storage.EventStore, processors ...EventProcessor) *Server {
	return &Server{
		store:      store,
		processors: processors,
		now:        time.Now,
	}
}

func (s *Server) SubmitEvent(ctx context.Context, in *agentpb.EventEnvelope) (*agentpb.SubmitEventResponse, error) {
	if s == nil || s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "event store is not configured")
	}
	ev, err := eventFromEnvelope(in)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if ev.ReceivedAt == "" {
		ev.StampReceivedAt(s.now())
	}
	if err := s.store.SaveEvent(ctx, ev); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	for _, processor := range s.processors {
		if processor == nil {
			continue
		}
		_ = processor.ProcessEvent(ctx, ev)
	}
	return &agentpb.SubmitEventResponse{Accepted: true, Message: "event accepted"}, nil
}

// SubmitEvents handles a client-side stream of EventEnvelope messages and replies with a single ack.
func (s *Server) SubmitEvents(stream agentpb.AgentService_SubmitEventsServer) error {
	if s == nil || s.store == nil {
		return status.Error(codes.FailedPrecondition, "event store is not configured")
	}
	var ids []string
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		ev, err := eventFromEnvelope(in)
		if err != nil {
			// skip invalid envelopes
			continue
		}
		if ev.ReceivedAt == "" {
			ev.StampReceivedAt(s.now())
		}
		if err := s.store.SaveEvent(stream.Context(), ev); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		for _, processor := range s.processors {
			if processor == nil {
				continue
			}
			_ = processor.ProcessEvent(stream.Context(), ev)
		}
		ids = append(ids, ev.EventID)
	}
	ack := &agentpb.SubmitEventAck{Accepted: true, EventId: ids}
	return stream.SendAndClose(ack)
}

func eventFromEnvelope(in *agentpb.EventEnvelope) (events.Event, error) {
	if in == nil {
		return events.Event{}, errors.New("event envelope is nil")
	}
	ev := events.Event{
		EventID:       in.GetEventId(),
		Timestamp:     in.GetTimestamp(),
		SiteID:        in.GetSiteId(),
		AgentID:       in.GetAgentId(),
		EventType:     in.GetEventType(),
		Severity:      in.GetSeverity(),
		Host:          in.GetHost(),
		Raw:           in.GetRaw(),
		IntegrityHash: in.GetIntegrity(),
	}
	ev.EnsureIntegrity()
	if err := ev.Validate(); err != nil {
		return events.Event{}, err
	}
	return ev, nil
}

func RunGRPCServer(ctx context.Context, cfg Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Store == nil {
		return errors.New("event store is required")
	}
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		addr = ":8443"
	}
	opts, err := buildServerOptions(cfg.CertPath, cfg.KeyPath, cfg.CAPath)
	if err != nil {
		return err
	}
	opts = append([]grpc.ServerOption{grpc.UnaryInterceptor(bearerAuthInterceptor(cfg.BearerToken))}, opts...)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	server := grpc.NewServer(opts...)
	agentpb.RegisterAgentServiceServer(server, NewServer(cfg.Store, cfg.Processors...))

	go stopServerOnContext(ctx, server)

	if err := server.Serve(listener); err != nil {
		if errors.Is(err, grpc.ErrServerStopped) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	return nil
}

func stopServerOnContext(ctx context.Context, server *grpc.Server) {
	<-ctx.Done()
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		server.Stop()
	}
}

func buildServerOptions(certPath, keyPath, caPath string) ([]grpc.ServerOption, error) {
	if certPath == "" && keyPath == "" && caPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("both cert and key are required for TLS")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("parse CA certificate")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(cfg))}, nil
}

func bearerAuthInterceptor(configuredToken string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !validateBearerToken(readBearerTokenFromContext(ctx), configuredToken) {
			return nil, status.Error(codes.Unauthenticated, "invalid or missing bearer token")
		}
		return handler(ctx, req)
	}
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

func validateBearerToken(value, configuredToken string) bool {
	configuredToken = strings.TrimSpace(configuredToken)
	if configuredToken == "" {
		return true
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return strings.TrimSpace(strings.TrimPrefix(value, prefix)) == configuredToken
}
