package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Nouments/argus/apps/agent/internal/host"
)

type sessionPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// defaultSessionFile returns a path to store session tokens.
func defaultSessionFile() (string, error) {
	if dir := os.Getenv("ARGUS_STATE_DIR"); dir != "" {
		return filepath.Join(dir, "session.json"), nil
	}
	if cfg, err := os.UserConfigDir(); err == nil && cfg != "" {
		p := filepath.Join(cfg, "argus", "agent", "session.json")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return "", err
		}
		return p, nil
	}
	// fallback to cwd
	return "./session.json", nil
}

// SaveSession writes the session pair to disk.
func SaveSession(p *sessionPair) error {
	if p == nil {
		return errors.New("nil session")
	}
	file, err := defaultSessionFile()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, b, 0o600)
}

// LoadSession loads stored session pair or returns nil if not present.
func LoadSession() (*sessionPair, error) {
	file, err := defaultSessionFile()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var p sessionPair
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.AccessToken == "" {
		return nil, fmt.Errorf("no access token in session file")
	}
	return &p, nil
}

// Enroll performs HTTP enrollment against gatewayURL (base URL, e.g. https://gw:8080).
// It POSTs to /enroll then /session to obtain an access/refresh pair and stores them.
func Enroll(ctx context.Context, client *http.Client, gatewayURL, agentID, siteID string) (*sessionPair, error) {
	if client == nil {
		return nil, errors.New("http client required")
	}
	enrollURL := stringsTrimSuffix(gatewayURL, "/") + "/enroll"
	body := map[string]string{"agent_id": agentID, "site_id": siteID}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", enrollURL, stringsNewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("enroll failed: status %d", resp.StatusCode)
	}
	var er struct {
		EnrollmentToken string `json:"enrollment_token"`
		ExpiresAt       int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return nil, err
	}
	if er.EnrollmentToken == "" {
		return nil, errors.New("empty enrollment token")
	}
	// exchange for session; include machine fingerprint if available
	sessionURL := stringsTrimSuffix(gatewayURL, "/") + "/session"
	fp := ""
	if md, err := host.GetMetadata(); err == nil {
		if f := computeFingerprint(md); f != "" {
			fp = f
		}
	}
	body2 := map[string]string{}
	if fp != "" {
		body2["fingerprint"] = fp
	}
	b2, _ := json.Marshal(body2)
	req2, _ := http.NewRequestWithContext(ctx, "POST", sessionURL, stringsNewReader(string(b2)))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+er.EnrollmentToken)
	resp2, err := client.Do(req2)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		return nil, fmt.Errorf("session exchange failed: status %d", resp2.StatusCode)
	}
	var pair sessionPair
	if err := json.NewDecoder(resp2.Body).Decode(&pair); err != nil {
		return nil, err
	}
	if pair.AccessToken == "" {
		return nil, errors.New("no access token returned")
	}
	if err := SaveSession(&pair); err != nil {
		return &pair, fmt.Errorf("save session failed: %w", err)
	}
	return &pair, nil
}

// computeFingerprint creates a deterministic fingerprint from interface MAC addresses
func computeFingerprint(md *host.HostMetadata) string {
	if md == nil {
		return ""
	}
	var macs []string
	for _, inf := range md.Interfaces {
		if len(inf.HardwareAddr) == 0 {
			continue
		}
		macs = append(macs, inf.HardwareAddr.String())
	}
	if len(macs) == 0 {
		return ""
	}
	sort.Strings(macs)
	joined := strings.Join(macs, ",")
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:])
}

// RefreshSession exchanges a refresh token for a new session pair and persists it.
func RefreshSession(ctx context.Context, client *http.Client, gatewayURL string) (*sessionPair, error) {
	sess, err := LoadSession()
	if err != nil {
		return nil, err
	}
	refreshURL := stringsTrimSuffix(gatewayURL, "/") + "/refresh"
	req, _ := http.NewRequestWithContext(ctx, "POST", refreshURL, nil)
	req.Header.Set("Authorization", "Bearer "+sess.RefreshToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("refresh failed: status %d", resp.StatusCode)
	}
	var pair sessionPair
	if err := json.NewDecoder(resp.Body).Decode(&pair); err != nil {
		return nil, err
	}
	if pair.AccessToken == "" {
		return nil, errors.New("no access token returned")
	}
	if err := SaveSession(&pair); err != nil {
		return &pair, fmt.Errorf("save session failed: %w", err)
	}
	return &pair, nil
}

// StartAutoRefresh runs a background goroutine that refreshes the session before expiry.
// Call cancel on the context to stop the refresher.
func StartAutoRefresh(ctx context.Context, client *http.Client, gatewayURL string) {
	go func() {
		rand.Seed(time.Now().UnixNano())
		const maxFailures = 5
		failures := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			sess, err := LoadSession()
			if err != nil {
				// no session yet
				select {
				case <-time.After(30 * time.Second):
					continue
				case <-ctx.Done():
					return
				}
			}
			// decode refresh expiry (best-effort)
			exp := int64(0)
			parts := strings.Split(sess.RefreshToken, ".")
			if len(parts) >= 2 {
				if decoded, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
					var ck struct {
						ExpiresAt int64 `json:"exp"`
					}
					_ = json.Unmarshal(decoded, &ck)
					exp = ck.ExpiresAt
				}
			}
			var wait time.Duration
			if exp > 0 {
				t := time.Unix(exp, 0).Add(-5 * time.Minute)
				wait = time.Until(t)
				if wait < 0 {
					wait = 0
				}
			} else {
				wait = 12 * time.Hour
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}

			// exponential backoff with jitter
			backoff := 2 * time.Second
			success := false
			for attempt := 1; attempt <= 8; attempt++ {
				_, err := RefreshSession(ctx, client, gatewayURL)
				if err == nil {
					failures = 0
					success = true
					break
				}
				failures++
				fmt.Fprintf(os.Stderr, "refresh attempt %d failed: %v\n", attempt, err)
				jitter := time.Duration(rand.Int63n(1000)) * time.Millisecond
				sleep := backoff + jitter
				select {
				case <-time.After(sleep):
				case <-ctx.Done():
					return
				}
				backoff *= 2
				if backoff > 30*time.Minute {
					backoff = 30 * time.Minute
				}
			}
			if !success && failures >= maxFailures {
				msg := fmt.Sprintf("session refresh failed %d times", failures)
				_ = writeAgentAlert(msg)
				fmt.Fprintf(os.Stderr, "ALERT: %s\n", msg)
			}
			select {
			case <-time.After(1 * time.Minute):
			case <-ctx.Done():
				return
			}
		}
	}()
}

// small helpers to avoid importing strings/io packages at top-level multiple times in generated code
func stringsTrimSuffix(s, suf string) string    { return strings.TrimSuffix(s, suf) }
func stringsNewReader(s string) *strings.Reader { return strings.NewReader(s) }

// writeAgentAlert appends an alert entry to ARGUS_STATE_DIR/alerts.log (JSONL).
func writeAgentAlert(msg string) error {
	dir := os.Getenv("ARGUS_STATE_DIR")
	if dir == "" {
		if cfg, err := os.UserConfigDir(); err == nil && cfg != "" {
			dir = filepath.Join(cfg, "argus", "agent")
		} else {
			dir = "."
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "alerts.log")
	entry := map[string]any{"ts": time.Now().Unix(), "msg": msg}
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}
