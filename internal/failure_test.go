package internal_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/api"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/pipeline"
	"github.com/surfacewatch/surfacewatch/internal/scheduler"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// TestFailureMode_CollectorTimeout verifies behavior when a collector times out.
func TestFailureMode_CollectorTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	timeoutCol := &fakeDelayedCollector{delay: 100 * time.Millisecond}
	target := model.Asset{ID: uuid.New(), Type: model.AssetTypeDomain, Value: "example.com"}

	_, err := timeoutCol.Collect(ctx, target)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

type fakeDelayedCollector struct {
	delay time.Duration
}

func (f *fakeDelayedCollector) Name() string { return "delayed_collector" }
func (f *fakeDelayedCollector) Collect(ctx context.Context, target model.Asset) ([]collector.RawFinding, error) {
	select {
	case <-time.After(f.delay):
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestFailureMode_HTTP429WithRetryAfter verifies exponential backoff honors the Retry-After header.
func TestFailureMode_HTTP429WithRetryAfter(t *testing.T) {
	backoff := scheduler.NewBackoffCalculator(100*time.Millisecond, 10*time.Second)

	retryDuration := 45 * time.Second
	httpErr := &scheduler.HTTPStatusError{
		StatusCode: http.StatusTooManyRequests,
		RetryAfter: &retryDuration,
		Message:    "rate limit exceeded: back off for 45s",
	}

	if !scheduler.IsTransient(httpErr) {
		t.Errorf("expected HTTP 429 to be classified as transient")
	}

	delay := backoff.Calculate(1, httpErr.RetryAfter)
	if delay != 45*time.Second {
		t.Errorf("expected backoff calculator to strictly honor Retry-After 45s, got %v", delay)
	}
}

// TestFailureMode_DuplicateJobExecution verifies idempotency: running a job twice creates no duplicate findings.
func TestFailureMode_DuplicateJobExecution(t *testing.T) {
	findingStore := pipeline.NewMemoryFindingStore()
	pipe := pipeline.NewPipeline(findingStore, pipeline.NewMemoryCache(), nil)

	scanID := uuid.New()
	assetID := uuid.New()
	asset := model.Asset{
		ID:       assetID,
		TenantID: "tenant-idempotent",
		Type:     model.AssetTypeDomain,
		Value:    "idempotent.example.com",
	}

	raw := []collector.RawFinding{
		{
			TargetAsset: asset,
			FindingType: "dangling_cname_takeover",
			Title:       "Dangling CNAME Takeover",
			EvidenceKey: "cname:idempotent.example.com:abandoned.azurewebsites.net",
		},
	}

	// First execution
	_ = pipe.ProcessRawFindings(context.Background(), scanID, assetID, raw)

	// Second execution (duplicate job / retry)
	_ = pipe.ProcessRawFindings(context.Background(), scanID, assetID, raw)

	// Third execution
	_ = pipe.ProcessRawFindings(context.Background(), scanID, assetID, raw)

	findings, _ := findingStore.ListByTenant(context.Background(), "tenant-idempotent", pipeline.Filter{})
	if len(findings) != 1 {
		t.Fatalf("IDEMPOTENCY VIOLATION: expected exactly 1 finding row, got %d", len(findings))
	}

	if findings[0].OccurrenceCount != 3 {
		t.Errorf("expected occurrence count 3, got %d", findings[0].OccurrenceCount)
	}
}

// TestFailureMode_WorkerCrashAndLeaseExpiry verifies un-heartbeated jobs are reclaimed.
func TestFailureMode_WorkerCrashAndLeaseExpiry(t *testing.T) {
	store := scheduler.NewMemoryStore()
	ctx := context.Background()

	job := &scheduler.Job{
		ID:            uuid.New(),
		TenantID:      "tenant-crash",
		CollectorName: "mock",
		MaxAttempts:   3,
		Target:        model.Asset{ID: uuid.New(), Value: "crash.example.com"},
	}
	_ = store.Enqueue(ctx, job)

	// Worker A claims with 20ms lease, then "crashes" (no heartbeat)
	claimedA, _ := store.ClaimJobs(ctx, "worker-a", 1, 20*time.Millisecond)
	if len(claimedA) != 1 {
		t.Fatalf("worker-a failed to claim job")
	}

	time.Sleep(35 * time.Millisecond) // Lease expires

	// Worker B claims
	claimedB, _ := store.ClaimJobs(ctx, "worker-b", 1, 1*time.Second)
	if len(claimedB) != 1 {
		t.Fatalf("worker-b failed to recover expired lease job")
	}
	if claimedB[0].Attempts != 2 {
		t.Errorf("expected attempt 2 after crash recovery, got %d", claimedB[0].Attempts)
	}
}

// TestFailureMode_OversizedRequestBody verifies requests exceeding limit are rejected.
func TestFailureMode_OversizedRequestBody(t *testing.T) {
	keyStore := api.NewMemoryKeyStore()
	_ = keyStore.RegisterKey("admin-key", "tenant-test", api.RoleAdmin, "Admin")
	auth := api.NewAuthenticator(keyStore)

	appCtx := &api.AppContext{
		Scope:      nil,
		Scheduler:  scheduler.NewMemoryStore(),
		Findings:   pipeline.NewMemoryFindingStore(),
		Cache:      pipeline.NewMemoryCache(),
		AssetStore: api.NewMemoryAssetStore(),
		ScanStore:  api.NewMemoryScanStore(),
	}

	// Router capped at 100 bytes
	router := api.NewRouter(appCtx, auth, api.RouterConfig{
		MaxBodyBytes: 100,
	})

	// Send 500 bytes payload
	oversized := `{"type":"domain","value":"` + strings.Repeat("a", 400) + `.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assets", strings.NewReader(oversized))
	req.Header.Set("X-API-Key", "admin-key")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// http.MaxBytesReader causes a Read error, resulting in 400 Bad Request
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 400 or 413 for oversized body, got %d", rec.Code)
	}
}

// TestFailureMode_CursorPaginationEdgeCases verifies cursor boundaries.
func TestFailureMode_CursorPaginationEdgeCases(t *testing.T) {
	findingStore := pipeline.NewMemoryFindingStore()
	ctx := context.Background()

	// Seed 15 findings
	for i := 0; i < 15; i++ {
		f := &model.Finding{
			ID:          uuid.New(),
			TenantID:    "tenant-cursor",
			Fingerprint: fmt.Sprintf("fp-%d", i),
			Title:       fmt.Sprintf("Finding %d", i),
			Status:      model.FindingStatusNew,
		}
		_, _, _ = findingStore.UpsertFinding(ctx, f)
	}

	keyStore := api.NewMemoryKeyStore()
	_ = keyStore.RegisterKey("viewer-key", "tenant-cursor", api.RoleViewer, "Viewer")
	auth := api.NewAuthenticator(keyStore)

	appCtx := &api.AppContext{
		Findings:   findingStore,
		AssetStore: api.NewMemoryAssetStore(),
		ScanStore:  api.NewMemoryScanStore(),
	}
	router := api.NewRouter(appCtx, auth, api.RouterConfig{})

	// 1. Fetch Page 1: limit=10
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings?limit=10", nil)
	req.Header.Set("X-API-Key", "viewer-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("page 1 failed with %d", rec.Code)
	}

	// 2. Fetch Page 2: cursor=10, limit=10 -> should return remaining 5 items and empty next_cursor
	req = httptest.NewRequest(http.MethodGet, "/api/v1/findings?cursor=10&limit=10", nil)
	req.Header.Set("X-API-Key", "viewer-key")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("page 2 failed with %d", rec.Code)
	}

	// 3. Out of bounds cursor: cursor=999 -> should return empty findings array, not crash
	req = httptest.NewRequest(http.MethodGet, "/api/v1/findings?cursor=999&limit=10", nil)
	req.Header.Set("X-API-Key", "viewer-key")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for out-of-bounds cursor, got %d", rec.Code)
	}
}

// TestFailureMode_WebhookPrivateIP verifies SSRF blocks outbound connections to 10.0.0.1 or 127.0.0.1.
func TestFailureMode_WebhookPrivateIP(t *testing.T) {
	dispatcher := api.NewWebhookDispatcher(nil, nil)

	sub := api.WebhookSubscription{
		ID:       uuid.New(),
		TenantID: "tenant-test",
		URL:      "http://127.0.0.1:8080/webhook",
		Secret:   "secret",
	}

	err := dispatcher.DispatchFindingAlert(context.Background(), sub, &model.Finding{})
	if err == nil {
		t.Fatalf("expected SSRF error blocking 127.0.0.1 webhook delivery, got nil")
	}

	// Verify dead letter was recorded
	deadLetters := dispatcher.GetDeadLetters()
	if len(deadLetters) != 1 {
		t.Errorf("expected 1 dead letter entry for blocked SSRF URL, got %d", len(deadLetters))
	}
}

// TestFailureMode_OutOfScopeTargetRefusal verifies collectors refuse out-of-scope assets.
func TestFailureMode_OutOfScopeTargetRefusal(t *testing.T) {
	sc, _ := scope.Parse([]byte("allowlist:\n  domains:\n    - example.com\n"))

	target := model.Asset{
		ID:    uuid.New(),
		Type:  model.AssetTypeDomain,
		Value: "unauthorized.badsite.com",
	}

	err := collector.GuardScope(sc, target)
	if err == nil {
		t.Fatalf("expected ErrOutOfScope, got nil")
	}
	if !scope.IsErrOutOfScope(err) {
		t.Errorf("expected *ErrOutOfScope, got %T: %v", err, err)
	}
}
