package observability_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/surfacewatch/surfacewatch/internal/observability"
)

func TestMetricsEndpoint(t *testing.T) {
	// Record test metrics
	observability.JobsQueued.Set(5)
	observability.JobsRunning.Set(2)
	observability.ObserveCollector("test_collector", 250*time.Millisecond, nil, false)
	observability.FindingsDiscoveredTotal.WithLabelValues("CRITICAL", "exposed_aws_key").Inc()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	observability.MetricsHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /metrics, got %d", rec.Code)
	}

	body := rec.Body.String()
	expectedMetrics := []string{
		"surfacewatch_jobs_queued",
		"surfacewatch_jobs_running",
		"surfacewatch_collector_latency_seconds",
		"surfacewatch_findings_total",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("expected /metrics output to contain %q", metric)
		}
	}
}

func TestPprofGating(t *testing.T) {
	// 1. By default (env not set), pprof must NOT be registered
	os.Unsetenv(observability.EnvEnablePprof)
	rDefault := chi.NewRouter()
	observability.RegisterPprof(rDefault)

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	rDefault.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("SECURITY RISK: expected 404 Not Found for /debug/pprof when disabled, got %d", rec.Code)
	}

	// 2. Explicitly enabled: pprof is accessible
	os.Setenv(observability.EnvEnablePprof, "true")
	defer os.Unsetenv(observability.EnvEnablePprof)

	rEnabled := chi.NewRouter()
	observability.RegisterPprof(rEnabled)

	recEnabled := httptest.NewRecorder()
	rEnabled.ServeHTTP(recEnabled, req)

	if recEnabled.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /debug/pprof when explicitly enabled, got %d", recEnabled.Code)
	}
}
