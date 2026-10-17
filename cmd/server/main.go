// Package main is the entrypoint for the SurfaceWatch monitoring backend server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/surfacewatch/surfacewatch/internal/api"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/pipeline"
	"github.com/surfacewatch/surfacewatch/internal/scheduler"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

func main() {
	port := flag.Int("port", 8080, "HTTP server listening port")
	scopePath := flag.String("scope", "scope.yaml", "Path to scope configuration YAML")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	logger.Info("Initializing SurfaceWatch backend", "version", "1.0.0")

	// 1. Load scope allowlist
	sc, err := scope.Load(*scopePath)
	if err != nil {
		logger.Warn("Failed to load scope.yaml, falling back to empty scope", "error", err)
	} else {
		logger.Info("Scope allowlist loaded successfully", "path", *scopePath)
	}

	// 2. Initialize in-memory / storage stores
	jobStore := scheduler.NewMemoryStore()
	findingStore := pipeline.NewMemoryFindingStore()
	cache := pipeline.NewMemoryCache()
	assetStore := api.NewMemoryAssetStore()
	scanStore := api.NewMemoryScanStore()

	// 3. Initialize pipeline & worker pool
	pipe := pipeline.NewPipeline(findingStore, cache, logger)

	collectors := []collector.Collector{
		collector.NewCTCollector(sc, nil),
		collector.NewDNSCollector(sc, nil),
		collector.NewTyposquatCollector(sc, nil),
		collector.NewTLSHeaderCollector(sc, nil, nil),
		collector.NewSecretScanner(sc),
	}

	poolCfg := scheduler.DefaultConfig()
	workerPool := scheduler.NewWorkerPool(poolCfg, jobStore, pipe, collectors, logger)

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	workerPool.Start(rootCtx)

	// 4. Initialize Auth and seed default development keys
	keyStore := api.NewMemoryKeyStore()
	devAdminKey := os.Getenv("SURFACEWATCH_DEV_ADMIN_KEY")
	if devAdminKey == "" {
		devAdminKey = "sw_dev_admin_secret_token_123"
	}
	_ = keyStore.RegisterKey(devAdminKey, "default-tenant", api.RoleAdmin, "Default Dev Admin")
	logger.Info("Seeded dev admin API key", "token", devAdminKey)

	auth := api.NewAuthenticator(keyStore)

	appCtx := &api.AppContext{
		Scope:      sc,
		Scheduler:  jobStore,
		Findings:   findingStore,
		Cache:      cache,
		AssetStore: assetStore,
		ScanStore:  scanStore,
	}

	router := api.NewRouter(appCtx, auth, api.RouterConfig{
		MaxBodyBytes: 1024 * 1024,
		RateLimit:    200,
		Burst:        400,
		Logger:       logger,
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 5. Run HTTP server in background
	go func() {
		logger.Info("SurfaceWatch HTTP server listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server exited unexpectedly", "error", err)
		}
	}()

	// 6. Graceful shutdown on SIGINT / SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutdown signal received: stopping server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	workerPool.Stop()
	logger.Info("SurfaceWatch backend terminated cleanly.")
}
