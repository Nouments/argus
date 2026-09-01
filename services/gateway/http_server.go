package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type enrollRequest struct {
	AgentID     string `json:"agent_id"`
	SiteID      string `json:"site_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type enrollResponse struct {
	EnrollmentToken string `json:"enrollment_token"`
	ExpiresAt       int64  `json:"expires_at"`
}

// enrollHandler issues a short-lived enrollment token for the requesting agent.
func enrollHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.AgentID) == "" || strings.TrimSpace(req.SiteID) == "" {
		http.Error(w, "agent_id and site_id required", http.StatusBadRequest)
		return
	}
	token, err := IssueEnrollmentToken(req.AgentID, req.SiteID)
	if err != nil {
		http.Error(w, "issue token failed", http.StatusInternalServerError)
		return
	}
	// decode to get expiry (ValidateAccessToken returns claims)
	claims, _ := ValidateAccessToken(token)
	var exp int64
	if claims != nil {
		exp = claims.ExpiresAt
	} else {
		exp = time.Now().Add(30 * time.Minute).Unix()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrollResponse{EnrollmentToken: token, ExpiresAt: exp})
	// audit
	_ = appendAudit("enroll_issued", map[string]any{"agent_id": req.AgentID, "site_id": req.SiteID, "ip": r.RemoteAddr, "expires_at": exp})
}

// sessionHandler accepts an enrollment token in Authorization header and returns an access/refresh pair.
func sessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "missing authorization", http.StatusUnauthorized)
		return
	}
	if !strings.HasPrefix(strings.TrimSpace(auth), "Bearer ") {
		http.Error(w, "invalid authorization format", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	// verify token signature first
	claims, err := ValidateAccessToken(token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if claims.TokenType != "enrollment" {
		http.Error(w, "token is not an enrollment token", http.StatusForbidden)
		return
	}
	// ensure single-use enrollment token stored and not consumed
	if !validateAndConsumeEnrollment(token) {
		http.Error(w, "enrollment token invalid or already used", http.StatusForbidden)
		return
	}
	// optional fingerprint verification from request body
	var body struct {
		Fingerprint string `json:"fingerprint,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// record machine registry
	ip := r.RemoteAddr
	hostname := "unknown"
	// attempt to parse hostname from headers
	if hn := r.Header.Get("X-Hostname"); hn != "" {
		hostname = hn
	}
	if body.Fingerprint != "" {
		registerOrUpdateMachine(body.Fingerprint, claims.AgentID, claims.SiteID, hostname, ip)
	}
	_ = appendAudit("session_issued", map[string]any{"agent_id": claims.AgentID, "site_id": claims.SiteID, "fingerprint": body.Fingerprint, "ip": ip})
	pair, err := IssueSessionPair(claims.AgentID, claims.SiteID)
	if err != nil {
		http.Error(w, "issue session failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pair)
}

type revokeRequest struct {
	SessionID string `json:"session_id,omitempty"`
	Token     string `json:"token,omitempty"`
	Until     int64  `json:"until,omitempty"` // unix seconds
}

// revokeHandler allows revoking a session by session id or by token.
func revokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SessionID == "" && req.Token == "" {
		http.Error(w, "session_id or token required", http.StatusBadRequest)
		return
	}
	var sid string
	if req.SessionID != "" {
		sid = req.SessionID
	} else {
		claims, err := ValidateAccessToken(req.Token)
		if err != nil || claims == nil {
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}
		sid = claims.SessionID
	}
	var until time.Time
	if req.Until > 0 {
		until = time.Unix(req.Until, 0)
	}
	RevokeSession(sid, until)
	_ = appendAudit("session_revoked", map[string]any{"session_id": sid, "until": req.Until, "by_ip": r.RemoteAddr})
	w.WriteHeader(http.StatusNoContent)
}

// refreshHandler accepts a refresh token and returns a rotated session pair.
func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// accept token in Authorization header or body
	auth := r.Header.Get("Authorization")
	var token string
	if strings.HasPrefix(strings.TrimSpace(auth), "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	} else {
		var body struct {
			RefreshToken string `json:"refresh_token,omitempty"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		token = body.RefreshToken
	}
	// optional fingerprint verification
	var fp string
	if hc := r.Header.Get("X-Fingerprint"); hc != "" {
		fp = hc
	} else {
		var body struct {
			Fingerprint string `json:"fingerprint,omitempty"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		fp = body.Fingerprint
	}

	if token == "" {
		http.Error(w, "missing refresh token", http.StatusBadRequest)
		return
	}
	// validate refresh token and optionally check fingerprint matches registered machine
	claims, err := ValidateAccessToken(token)
	if err != nil || claims == nil || claims.TokenType != "refresh" {
		_ = appendAudit("refresh_failed", map[string]any{"reason": "invalid_token", "ip": r.RemoteAddr})
		http.Error(w, "refresh failed", http.StatusUnauthorized)
		return
	}
	if fp != "" {
		if rec, ok := findMachineByFingerprint(fp); !ok || rec.AgentID != claims.AgentID || rec.SiteID != claims.SiteID {
			_ = appendAudit("refresh_failed", map[string]any{"reason": "fingerprint_mismatch", "fingerprint": fp, "agent_id": claims.AgentID})
			http.Error(w, "fingerprint mismatch", http.StatusForbidden)
			return
		}
	}
	pair, err := RotateRefreshToken(token)
	if err != nil {
		_ = appendAudit("refresh_failed", map[string]any{"reason": "rotate_failed", "agent_id": claims.AgentID})
		http.Error(w, "refresh failed", http.StatusUnauthorized)
		return
	}
	_ = appendAudit("session_refreshed", map[string]any{"agent_id": claims.AgentID, "site_id": claims.SiteID, "ip": r.RemoteAddr})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pair)
}

// StartHTTPServer starts a simple HTTP server with enrollment endpoints on the provided address.
func StartHTTPServer(addr string) error {
	if addr == "" {
		addr = ":8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", enrollHandler)
	mux.HandleFunc("/session", sessionHandler)
	mux.HandleFunc("/refresh", refreshHandler)
	return http.ListenAndServe(addr, mux)
}
