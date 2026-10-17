// Package api sets up HTTP routing, middleware pipeline, and server lifecycle.
package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/surfacewatch/surfacewatch/internal/observability"
	"golang.org/x/time/rate"
)

// RouterConfig defines router options.
type RouterConfig struct {
	MaxBodyBytes int64
	RateLimit    rate.Limit
	Burst        int
	Logger       *slog.Logger
}

// NewRouter builds the Chi multiplexer with security, auth, and business routes.
func NewRouter(app *AppContext, auth *Authenticator, cfg RouterConfig) http.Handler {
	r := chi.NewRouter()

	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 1024 * 1024 // 1MB default
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 60 // 60 requests per second
		cfg.Burst = 120
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// 1. Global Middleware (Security & Observability)
	r.Use(chimw.Recoverer)
	r.Use(RequestID)
	r.Use(SecurityHeaders)
	r.Use(MaxBodySize(cfg.MaxBodyBytes))
	r.Use(StructuredLogger(cfg.Logger))
	r.Use(NewAPIRateLimiter(cfg.RateLimit, cfg.Burst).Middleware)

	// 2. Public Health, Metrics & Readiness Probes
	r.Get("/healthz", HandleHealthz)
	r.Get("/readyz", app.HandleReadyz)
	r.Handle("/metrics", observability.MetricsHandler())
	observability.RegisterPprof(r)

	// 3. Authenticated API Routes (/api/v1)
	r.Route("/api/v1", func(apiRoute chi.Router) {
		apiRoute.Use(auth.Middleware)

		// Assets
		apiRoute.Route("/assets", func(ar chi.Router) {
			ar.With(RequireRole(RoleAdmin)).Post("/", app.HandleCreateAsset)
			ar.With(RequireRole(RoleViewer)).Get("/", app.HandleListAssets)
		})

		// Scans
		apiRoute.Route("/scans", func(sr chi.Router) {
			sr.With(RequireRole(RoleAnalyst)).Post("/", app.HandleCreateScan)
			sr.With(RequireRole(RoleViewer)).Get("/", app.HandleListScans)
		})

		// Findings
		apiRoute.Route("/findings", func(fr chi.Router) {
			fr.With(RequireRole(RoleViewer)).Get("/", app.HandleListFindings)
			fr.With(RequireRole(RoleViewer)).Get("/{id}", app.HandleGetFinding)
			fr.With(RequireRole(RoleAnalyst)).Patch("/{id}/status", app.HandleUpdateFindingStatus)
		})

		// Stats Summary
		apiRoute.With(RequireRole(RoleViewer)).Get("/stats/summary", app.HandleStatsSummary)
	})

	return r
}
