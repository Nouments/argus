package transport

import (
	"context"
	"fmt"
	"time"
)

// DialWithRetry attempts to create a secure gRPC client with retries and exponential backoff.
// If certPath/keyPath/caPath are empty, TLS is not enforced. bearer may be empty.
func DialWithRetry(ctx context.Context, target, bearer, certPath, keyPath, caPath string, maxAttempts int) (*GRPCClient, error) {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// try secure client (it will fall back to insecure if certs empty)
		c, err := NewSecureGRPCClientWithBearer(ctx, target, bearer, certPath, keyPath, caPath)
		if err == nil {
			return c, nil
		}
		lastErr = err
		// simple exponential backoff
		wait := time.Duration(1<<uint(attempt)) * time.Second
		if wait > 30*time.Second {
			wait = 30 * time.Second
		}
		select {
		case <-time.After(wait):
			continue
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		}
	}
	return nil, fmt.Errorf("dial attempts failed: %w", lastErr)
}
