// Package main provides the root entrypoint for SurfaceWatch.
package main

import (
	"context"
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	logger.Info("Starting SurfaceWatch", "version", "1.0.0")

	sc, err := scope.Load(*scopePath)
	if err != nil {
		logger.Warn("Failed to load scope.yaml, using empty scope", "error", err)
	}

	jobStore := scheduler.NewMemoryStore()
	findingStore := pipeline.NewMemoryFindingStore()
	cache := pipeline.NewMemoryCache()
	assetStore := api.NewMemoryAssetStore()
	scanStore := api.NewMemoryScanStore()

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

	keyStore := api.NewMemoryKeyStore()
	devKey := os.Getenv("SURFACEWATCH_DEV_ADMIN_KEY")
	if devKey == "" {
		devKey = "sw_dev_admin_secret_token_123"
	}
	_ = keyStore.RegisterKey(devKey, "default-tenant", api.RoleAdmin, "Default Admin")

	auth := api.NewAuthenticator(keyStore)
	appCtx := &api.AppContext{
		Scope:      sc,
		Scheduler:  jobStore,
		Findings:   findingStore,
		Cache:      cache,
		AssetStore: assetStore,
		ScanStore:  scanStore,
	}

	router := api.NewRouter(appCtx, auth, api.RouterConfig{Logger: logger})
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: router,
	}

	go func() {
		logger.Info("HTTP server running", "port", *port)
		_ = server.ListenAndServe()
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	workerPool.Stop()
}
