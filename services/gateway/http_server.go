package gateway

import (
    "encoding/json"
    "net/http"
    "strings"
    "time"
)

type enrollRequest struct {
    AgentID string `json:"agent_id"`
    SiteID  string `json:"site_id"`
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
    claims, err := ValidateAccessToken(token)
    if err != nil {
        http.Error(w, "invalid token", http.StatusUnauthorized)
        return
    }
    if claims.TokenType != "enrollment" {
        http.Error(w, "token is not an enrollment token", http.StatusForbidden)
        return
    }
    pair, err := IssueSessionPair(claims.AgentID, claims.SiteID)
    if err != nil {
        http.Error(w, "issue session failed", http.StatusInternalServerError)
        return
    }
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
    return http.ListenAndServe(addr, mux)
}
