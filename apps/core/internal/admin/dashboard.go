package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Overview struct {
	Service    string    `json:"service"`
	Healthy    bool      `json:"healthy"`
	Timestamp  string    `json:"timestamp"`
	EventStore string    `json:"event_store"`
	EventCount int       `json:"event_count"`
	AlertCount int       `json:"alert_count"`
	Agents     int       `json:"agents"`
	Alerts     []Alert   `json:"alerts"`
	Uptime     string    `json:"uptime"`
	StartedAt  time.Time `json:"started_at"`
}

type Alert struct {
	AlertID   string `json:"alert_id"`
	RuleName  string `json:"rule_name"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	Host      string `json:"host"`
	EventType string `json:"event_type"`
	CreatedAt string `json:"created_at"`
}

type dashboardServer struct {
	startedAt  time.Time
	eventStore string
	dataDir    string
}

func NewHandler(eventStorePath, dataDir string) http.Handler {
	s := &dashboardServer{
		startedAt:  time.Now().UTC(),
		eventStore: eventStorePath,
		dataDir:    dataDir,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/api/overview", s.overviewHandler)
	mux.HandleFunc("/", s.indexHandler)
	return mux
}

func StartServer(addr, eventStorePath, dataDir string) error {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	handler := NewHandler(eventStorePath, dataDir)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *dashboardServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service":   "argus-core",
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *dashboardServer) overviewHandler(w http.ResponseWriter, r *http.Request) {
	ov := s.snapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ov)
}

func (s *dashboardServer) indexHandler(w http.ResponseWriter, r *http.Request) {
	ov := s.snapshot()
	fmt.Fprintf(w, `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Argus Admin</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #0f172a; color: #e2e8f0; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 20px 0; }
    .card { background: #111827; border: 1px solid #334155; border-radius: 10px; padding: 18px; }
    .label { color: #94a3b8; font-size: 12px; text-transform: uppercase; }
    .value { font-size: 28px; font-weight: bold; margin-top: 8px; }
    .ok { color: #34d399; }
    .warn { color: #fbbf24; }
    table { width: 100%%; border-collapse: collapse; margin-top: 20px; }
    th, td { border-bottom: 1px solid #334155; padding: 10px; text-align: left; }
    a { color: #7dd3fc; }
  </style>
</head>
<body>
  <h1>Argus Admin Dashboard</h1>
  <div class="grid">
    <div class="card"><div class="label">État</div><div class="value %s">%s</div></div>
    <div class="card"><div class="label">Événements</div><div class="value">%d</div></div>
    <div class="card"><div class="label">Alertes</div><div class="value">%d</div></div>
    <div class="card"><div class="label">Uptime</div><div class="value">%s</div></div>
  </div>
  <p>Source: <strong>%s</strong></p>
  <p>API: <a href="/api/overview">/api/overview</a> | <a href="/health">/health</a></p>
  <h2>Alertes récentes</h2>
  <table>
    <thead><tr><th>Règle</th><th>Niveau</th><th>Host</th><th>Créée</th></tr></thead>
    <tbody>%s</tbody>
  </table>
</body>
</html>`, statusClass(ov.Healthy), statusText(ov.Healthy), ov.EventCount, ov.AlertCount, ov.Uptime, ov.EventStore, alertsRows(ov.Alerts))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func (s *dashboardServer) snapshot() Overview {
	eventPath := s.eventStore
	alertPath := filepath.Join(s.dataDir, "alerts.jsonl")
	count := countLines(eventPath)
	alertCount := countLines(alertPath)
	alerts := readRecentAlerts(alertPath, 5)
	return Overview{
		Service:    "argus-core",
		Healthy:    true,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		EventStore: eventPath,
		EventCount: count,
		AlertCount: alertCount,
		Alerts:     alerts,
		Uptime:     time.Since(s.startedAt).Round(time.Second).String(),
		StartedAt:  s.startedAt,
	}
}

func statusClass(healthy bool) string {
	if healthy {
		return "ok"
	}
	return "warn"
}

func statusText(healthy bool) string {
	if healthy {
		return "OK"
	}
	return "WARN"
}

func countLines(path string) int {
	if strings.TrimSpace(path) == "" {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return 0
	}
	return len(strings.Split(text, "\n"))
}

func readRecentAlerts(path string, limit int) []Alert {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		return nil
	}
	out := make([]Alert, 0, len(lines))
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var a Alert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out
}

func alertsRows(alerts []Alert) string {
	if len(alerts) == 0 {
		return "<tr><td colspan=\"4\">Aucune alerte récente</td></tr>"
	}
	rows := make([]string, 0, len(alerts))
	for _, a := range alerts {
		rows = append(rows, fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", escape(a.RuleName), escape(a.Severity), escape(a.Host), escape(a.CreatedAt)))
	}
	return strings.Join(rows, "")
}

func escape(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	value = strings.ReplaceAll(value, "\"", "&quot;")
	return value
}
