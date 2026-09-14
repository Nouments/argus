package storage

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	CHWriteSuccess = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "argus_clickhouse_write_success_total",
		Help: "Total successful ClickHouse write operations",
	}, []string{"result"})
	CHWriteFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "argus_clickhouse_write_fail_total",
		Help: "Total failed ClickHouse write operations",
	}, []string{"error"})
	CHWriteDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "argus_clickhouse_write_duration_seconds",
		Help:    "Duration of ClickHouse write operations",
		Buckets: prometheus.DefBuckets,
	})
	DLQSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "argus_dlq_size",
		Help: "Number of entries currently in the DLQ",
	})
)

func init() {
	prometheus.MustRegister(CHWriteSuccess, CHWriteFailures, CHWriteDuration, DLQSize)
}

// StartMetricsServer starts an HTTP server exposing /metrics on the given addr.
func StartMetricsServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		_ = srv.ListenAndServe()
	}()
	// give server a moment to start
	time.Sleep(10 * time.Millisecond)
	return srv
}
