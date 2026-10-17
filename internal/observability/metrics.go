// Package observability provides Prometheus metrics instrumentation, health probes,
// structured logging correlation, and gated debug profiling (pprof).
package observability

import (
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Jobs Queued & Running Gauges
	JobsQueued = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "surfacewatch",
		Name:      "jobs_queued",
		Help:      "Current count of scan jobs awaiting worker lease",
	})

	JobsRunning = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "surfacewatch",
		Name:      "jobs_running",
		Help:      "Current count of scan jobs actively running across workers",
	})

	// Jobs Completed & Failed Counters
	JobsCompletedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "surfacewatch",
		Name:      "jobs_completed_total",
		Help:      "Total number of successfully executed collector jobs",
	}, []string{"collector"})

	JobsFailedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "surfacewatch",
		Name:      "jobs_failed_total",
		Help:      "Total number of failed collector jobs",
	}, []string{"collector", "transient"})

	// Collector Execution Latency Histogram
	CollectorLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "surfacewatch",
		Name:      "collector_latency_seconds",
		Help:      "Execution duration of passive collectors in seconds",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0},
	}, []string{"collector"})

	// Findings Counter partitioned by severity and finding type
	FindingsDiscoveredTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "surfacewatch",
		Name:      "findings_total",
		Help:      "Total security findings discovered by the pipeline",
	}, []string{"severity", "finding_type"})

	// HTTP API Request Latency Histogram
	APIRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "surfacewatch",
		Name:      "api_request_duration_seconds",
		Help:      "HTTP request latency for REST API endpoints",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "path", "status"})
)

// MetricsHandler serves Prometheus metrics on /metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// ObserveCollector records duration and success of a collector job run.
func ObserveCollector(collectorName string, duration time.Duration, err error, isTransient bool) {
	CollectorLatency.WithLabelValues(collectorName).Observe(duration.Seconds())
	if err == nil {
		JobsCompletedTotal.WithLabelValues(collectorName).Inc()
	} else {
		JobsFailedTotal.WithLabelValues(collectorName, strconv.FormatBool(isTransient)).Inc()
	}
}

// ObserveHTTPRequest records HTTP API latency.
func ObserveHTTPRequest(method, path string, statusCode int, duration time.Duration) {
	APIRequestDuration.WithLabelValues(method, path, strconv.Itoa(statusCode)).Observe(duration.Seconds())
}

// EnvEnablePprof gates debug endpoints in production.
const EnvEnablePprof = "SURFACEWATCH_ENABLE_PPROF"

// RegisterPprof mounts pprof handlers strictly when authorized by the operator via environment flag.
func RegisterPprof(r chi.Router) {
	if os.Getenv(EnvEnablePprof) != "true" {
		return
	}

	r.Route("/debug/pprof", func(pr chi.Router) {
		pr.Get("/", pprof.Index)
		pr.Get("/cmdline", pprof.Cmdline)
		pr.Get("/profile", pprof.Profile)
		pr.Get("/symbol", pprof.Symbol)
		pr.Get("/trace", pprof.Trace)
		pr.Get("/goroutine", pprof.Handler("goroutine").ServeHTTP)
		pr.Get("/heap", pprof.Handler("heap").ServeHTTP)
		pr.Get("/threadcreate", pprof.Handler("threadcreate").ServeHTTP)
		pr.Get("/block", pprof.Handler("block").ServeHTTP)
	})
}
