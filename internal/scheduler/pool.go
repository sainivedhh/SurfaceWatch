// Package scheduler implements the concurrent worker pool with graceful shutdown,
// heartbeating, rate limiting, and circuit breaking.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"golang.org/x/time/rate"
)

// PipelineSink receives raw findings from completed collector runs.
type PipelineSink interface {
	ProcessRawFindings(ctx context.Context, scanID uuid.UUID, assetID uuid.UUID, raw []collector.RawFinding) error
}

// Config configures the worker pool behavior.
type Config struct {
	Concurrency        int
	LeaseDuration      time.Duration
	HeartbeatInterval  time.Duration
	PollInterval       time.Duration
	BaseBackoff        time.Duration
	MaxBackoff         time.Duration
	HostRequestsPerSec float64
	HostBurstCapacity  int
}

// DefaultConfig provides recommended defaults.
func DefaultConfig() Config {
	return Config{
		Concurrency       : 4,
		LeaseDuration     : 30 * time.Second,
		HeartbeatInterval : 10 * time.Second,
		PollInterval      : 500 * time.Millisecond,
		BaseBackoff       : 1 * time.Second,
		MaxBackoff        : 60 * time.Second,
		HostRequestsPerSec: 5.0,
		HostBurstCapacity : 10,
	}
}

// WorkerPool coordinates background scan execution across multiple goroutines.
type WorkerPool struct {
	cfg         Config
	store       Store
	collectors  map[string]collector.Collector
	rateLimiter *HostRateLimiter
	breakers    map[string]*CircuitBreaker
	backoff     *BackoffCalculator
	sink        PipelineSink
	logger      *slog.Logger

	workerID    string
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
}

// NewWorkerPool constructs a worker pool instance.
func NewWorkerPool(cfg Config, store Store, sink PipelineSink, collectors []collector.Collector, logger *slog.Logger) *WorkerPool {
	if logger == nil {
		logger = slog.Default()
	}

	colMap := make(map[string]collector.Collector)
	breakers := make(map[string]*CircuitBreaker)
	for _, c := range collectors {
		colMap[c.Name()] = c
		breakers[c.Name()] = NewCircuitBreaker(c.Name(), 5, 30*time.Second)
	}

	return &WorkerPool{
		cfg        : cfg,
		store      : store,
		collectors : colMap,
		rateLimiter: NewHostRateLimiter(rate.Limit(cfg.HostRequestsPerSec), cfg.HostBurstCapacity),
		breakers   : breakers,
		backoff    : NewBackoffCalculator(cfg.BaseBackoff, cfg.MaxBackoff),
		sink       : sink,
		logger     : logger,
		workerID   : fmt.Sprintf("worker-node-%s", uuid.New().String()[:8]),
	}
}

// Start launches the worker goroutines.
func (wp *WorkerPool) Start(parentCtx context.Context) {
	wp.ctx, wp.cancel = context.WithCancel(parentCtx)

	wp.logger.Info("Starting SurfaceWatch worker pool",
		"worker_id", wp.workerID,
		"concurrency", wp.cfg.Concurrency,
		"lease_duration", wp.cfg.LeaseDuration)

	for i := 0; i < wp.cfg.Concurrency; i++ {
		wp.wg.Add(1)
		workerIndex:= i
		go wp.runWorker(workerIndex)
	}
}

// Stop initiates graceful shutdown: stops claiming new jobs and waits for in-flight tasks to finish.
func (wp *WorkerPool) Stop() {
	wp.logger.Info("Shutting down worker pool gracefully: draining active jobs...")
	if wp.cancel != nil {
		wp.cancel()
	}
	wp.wg.Wait()
	wp.logger.Info("Worker pool gracefully stopped: all workers finished.")
}

func (wp *WorkerPool) runWorker(workerIndex int) {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		default:
		}

		// Claim one job with SKIP LOCKED semantics
		jobs, err := wp.store.ClaimJobs(wp.ctx, wp.workerID, 1, wp.cfg.LeaseDuration)
		if err != nil || len(jobs) == 0 {
			// Back off polling
			select {
			case <-wp.ctx.Done():
				return
			case <-time.After(wp.cfg.PollInterval):
				continue
			}
		}

		job := jobs[0]
		wp.executeJob(job)
	}
}

func (wp *WorkerPool) executeJob(job *Job) {
	wp.logger.Info("Claimed job for execution",
		"job_id", job.ID,
		"collector", job.CollectorName,
		"target", job.Target.Value,
		"attempt", job.Attempts)

	col, exists := wp.collectors[job.CollectorName]
	if !exists {
		_ = wp.store.Fail(context.Background(), job.ID, wp.workerID, fmt.Sprintf("collector %q not registered", job.CollectorName), 0, false)
		return
	}

	// Start background heartbeating
	hbCtx, hbCancel := context.WithCancel(wp.ctx)
	defer hbCancel()

	go func() {
		ticker:= time.NewTicker(wp.cfg.HeartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				if err := wp.store.Heartbeat(context.Background(), job.ID, wp.workerID, wp.cfg.LeaseDuration); err != nil {
					wp.logger.Warn("Failed to send job heartbeat", "job_id", job.ID, "error", err)
				}
			}
		}
	}()

	// 1. Per-host token bucket rate limiting: wait until target host is ready
	if err := wp.rateLimiter.Wait(wp.ctx, job.Target.Value); err != nil {
		if wp.ctx.Err() != nil {
			// Worker pool was shut down while waiting for rate limit token
			return
		}
	}

	// 2. Circuit breaker check & execution
	cb := wp.getBreaker(job.CollectorName)
	var rawFindings []collector.RawFinding
	var collectErr error

	cbErr := cb.Execute(func() error {
		rawFindings, collectErr = col.Collect(wp.ctx, job.Target)
		return collectErr
	})

	if cbErr != nil {
		isTrans:= IsTransient(cbErr)
		var retryAfter *time.Duration
		var httpErr *HTTPStatusError
		if errors.As(cbErr, &httpErr) {
			retryAfter = httpErr.RetryAfter
		}
		delay := wp.backoff.Calculate(job.Attempts, retryAfter)

		wp.logger.Warn("Collector execution failed",
			"job_id", job.ID,
			"collector", job.CollectorName,
			"error", cbErr,
			"transient", isTrans,
			"backoff_delay", delay)

		_ = wp.store.Fail(context.Background(), job.ID, wp.workerID, cbErr.Error(), delay, isTrans)
		return
	}

	// 3. Process raw findings through pipeline sink (idempotent upsertion)
	if wp.sink != nil && len(rawFindings) > 0 {
		if err := wp.sink.ProcessRawFindings(context.Background(), job.ScanID, job.Target.ID, rawFindings); err != nil {
			wp.logger.Error("Failed to persist scan findings", "job_id", job.ID, "error", err)
			_ = wp.store.Fail(context.Background(), job.ID, wp.workerID, err.Error(), wp.cfg.BaseBackoff, true)
			return
		}
	}

	// 4. Mark job successfully completed
	if err := wp.store.Complete(context.Background(), job.ID, wp.workerID); err != nil {
		wp.logger.Error("Failed to complete job", "job_id", job.ID, "error", err)
	} else {
		wp.logger.Info("Job completed successfully",
			"job_id", job.ID,
			"findings_count", len(rawFindings))
	}
}

func (wp *WorkerPool) getBreaker(collectorName string) *CircuitBreaker {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	cb, exists := wp.breakers[collectorName]
	if !exists {
		cb = NewCircuitBreaker(collectorName, 5, 30*time.Second)
		wp.breakers[collectorName] = cb
	}
	return cb
}
