package scheduler_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scheduler"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// FakeCollector implements collector.Collector for controlled scheduler testing.
type FakeCollector struct {
	CollectorName string
	Findings      []collector.RawFinding
	Err           error
	CallCount     int32
}

func (f *FakeCollector) Name() string { return f.CollectorName }
func (f *FakeCollector) Collect(ctx context.Context, target model.Asset) ([]collector.RawFinding, error) {
	atomic.AddInt32(&f.CallCount, 1)
	return f.Findings, f.Err
}

// FakeSink records processed findings.
type FakeSink struct {
	mu           sync.Mutex
	findingsList []collector.RawFinding
}

func (s *FakeSink) ProcessRawFindings(ctx context.Context, scanID uuid.UUID, assetID uuid.UUID, raw []collector.RawFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findingsList = append(s.findingsList, raw...)
	return nil
}

func TestStore_LeasingAndLeaseExpiryRecovery(t *testing.T) {
	store := scheduler.NewMemoryStore()
	ctx := context.Background()

	job := &scheduler.Job{
		ID:            uuid.New(),
		TenantID:      "tenant-test",
		CollectorName: "mock_collector",
		MaxAttempts:   3,
		Target: model.Asset{
			ID:    uuid.New(),
			Type:  model.AssetTypeDomain,
			Value: "example.com",
		},
	}

	if err := store.Enqueue(ctx, job); err != nil {
		t.Fatalf("failed to enqueue job: %v", err)
	}

	// Worker 1 claims with very short lease (10ms)
	claimed, err := store.ClaimJobs(ctx, "worker-1", 1, 10*time.Millisecond)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("expected worker-1 to claim 1 job, got %d (err: %v)", len(claimed), err)
	}
	if claimed[0].Attempts != 1 {
		t.Errorf("expected attempts=1, got %d", claimed[0].Attempts)
	}

	// Worker 2 attempts immediate claim while lease is active: should be skipped!
	claimedW2, err := store.ClaimJobs(ctx, "worker-2", 1, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error claiming jobs: %v", err)
	}
	if len(claimedW2) != 0 {
		t.Errorf("expected worker-2 to receive 0 jobs while leased by worker-1, got %d", len(claimedW2))
	}

	// Worker 1 dies (no heartbeat). Sleep to allow lease to expire.
	time.Sleep(25 * time.Millisecond)

	// Worker 2 claims after lease expiry: job recovered!
	claimedAfterExpiry, err := store.ClaimJobs(ctx, "worker-2", 1, 100*time.Millisecond)
	if err != nil || len(claimedAfterExpiry) != 1 {
		t.Fatalf("expected worker-2 to recover expired lease job, got %d (err: %v)", len(claimedAfterExpiry), err)
	}
	if claimedAfterExpiry[0].Attempts != 2 {
		t.Errorf("expected attempts incremented to 2 on lease recovery, got %d", claimedAfterExpiry[0].Attempts)
	}
	if claimedAfterExpiry[0].WorkerID != "worker-2" {
		t.Errorf("expected new lease holder worker-2, got %s", claimedAfterExpiry[0].WorkerID)
	}
}

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	cb := scheduler.NewCircuitBreaker("test_breaker", 3, 50*time.Millisecond)

	if cb.State() != scheduler.StateClosed {
		t.Fatalf("expected initial state Closed, got %s", cb.State())
	}

	// 2 failures: still closed (< 3)
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error { return errors.New("transient error") })
	}
	if cb.State() != scheduler.StateClosed {
		t.Fatalf("expected Closed after 2 failures, got %s", cb.State())
	}

	// 3rd failure: trips Open!
	_ = cb.Execute(func() error { return errors.New("third failure") })
	if cb.State() != scheduler.StateOpen {
		t.Fatalf("expected Open after 3 failures, got %s", cb.State())
	}

	// While Open, execution fails immediately with ErrCircuitOpen without running fn
	ran := false
	err := cb.Execute(func() error {
		ran = true
		return nil
	})
	if ran {
		t.Errorf("expected fn not to run while circuit is open")
	}
	if !errors.Is(err, scheduler.ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}

	// Wait for cooldown to expire
	time.Sleep(60 * time.Millisecond)

	// Half-open trial run succeeds: should reset back to Closed
	err = cb.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("unexpected trial error: %v", err)
	}
	if cb.State() != scheduler.StateClosed {
		t.Errorf("expected circuit to recover to Closed after successful trial, got %s", cb.State())
	}
}

func TestRetry_ExponentialBackoffAndRetryAfter(t *testing.T) {
	backoff := scheduler.NewBackoffCalculator(100*time.Millisecond, 5*time.Second)

	// Test 1: Retry-After header takes absolute precedence
	retryAfter := 30 * time.Second
	delay := backoff.Calculate(1, &retryAfter)
	if delay != 30*time.Second {
		t.Errorf("expected 30s delay honoring Retry-After, got %v", delay)
	}

	// Test 2: Exponential bounds with jitter
	for attempt := 1; attempt <= 4; attempt++ {
		d := backoff.Calculate(attempt, nil)
		if d < 100*time.Millisecond {
			t.Errorf("delay %v below base interval", d)
		}
		if d > 5*time.Second {
			t.Errorf("delay %v exceeded max interval", d)
		}
	}

	// Test 3: Permanent vs Transient classification
	if scheduler.IsTransient(&scope.ErrOutOfScope{Target: "evil.com"}) {
		t.Errorf("ErrOutOfScope must NEVER be classified as transient")
	}
	if scheduler.IsTransient(&scheduler.HTTPStatusError{StatusCode: http.StatusBadRequest}) {
		t.Errorf("HTTP 400 Bad Request must be permanent")
	}
	if !scheduler.IsTransient(&scheduler.HTTPStatusError{StatusCode: http.StatusTooManyRequests}) {
		t.Errorf("HTTP 429 Too Many Requests must be transient")
	}
	if !scheduler.IsTransient(&scheduler.HTTPStatusError{StatusCode: http.StatusServiceUnavailable}) {
		t.Errorf("HTTP 503 must be transient")
	}
}

func TestWorkerPool_GracefulShutdownAndExecution(t *testing.T) {
	store := scheduler.NewMemoryStore()
	sink := &FakeSink{}

	col := &FakeCollector{
		CollectorName: "mock_scanner",
		Findings: []collector.RawFinding{
			{
				FindingType: "test_finding",
				Title:       "Test Finding",
				Severity:    model.SeverityLow,
				EvidenceKey: "test:key",
			},
		},
	}

	cfg := scheduler.Config{
		Concurrency:        2,
		LeaseDuration:      1 * time.Second,
		HeartbeatInterval:  200 * time.Millisecond,
		PollInterval:       10 * time.Millisecond,
		BaseBackoff:        10 * time.Millisecond,
		MaxBackoff:         100 * time.Millisecond,
		HostRequestsPerSec: 100.0,
		HostBurstCapacity:  50,
	}

	pool := scheduler.NewWorkerPool(cfg, store, sink, []collector.Collector{col}, nil)

	// Enqueue 5 jobs
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		job := &scheduler.Job{
			ID:            uuid.New(),
			TenantID:      "tenant-1",
			ScanID:        uuid.New(),
			CollectorName: "mock_scanner",
			Target: model.Asset{
				ID:    uuid.New(),
				Type:  model.AssetTypeDomain,
				Value: "example.com",
			},
		}
		_ = store.Enqueue(ctx, job)
	}

	pool.Start(ctx)

	// Allow workers to execute
	time.Sleep(150 * time.Millisecond)

	// Perform graceful shutdown
	pool.Stop()

	// Verify all jobs were processed
	if atomic.LoadInt32(&col.CallCount) != 5 {
		t.Errorf("expected 5 collector executions, got %d", col.CallCount)
	}

	sink.mu.Lock()
	count := len(sink.findingsList)
	sink.mu.Unlock()

	if count != 5 {
		t.Errorf("expected 5 findings delivered to sink, got %d", count)
	}
}
