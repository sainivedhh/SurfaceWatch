package pipeline_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/pipeline"
)

// FailingCache simulates Redis outage.
type FailingCache struct{}

func (f *FailingCache) Get(ctx context.Context, key string) (string, error) {
	return "", errors.New("connection refused: redis is down")
}
func (f *FailingCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return errors.New("connection refused: redis is down")
}
func (f *FailingCache) Delete(ctx context.Context, key string) error {
	return errors.New("connection refused: redis is down")
}
func (f *FailingCache) IsAvailable() bool { return false }

func TestFingerprint_Deterministic(t *testing.T) {
	fp1 := pipeline.GenerateFingerprint("exposed_aws_key", "my-repo", "config.env:12:hash1")
	fp2 := pipeline.GenerateFingerprint("exposed_aws_key", "my-repo", "config.env:12:hash1")
	fp3 := pipeline.GenerateFingerprint("exposed_aws_key", "my-repo", "config.env:13:hash1")

	if fp1 != fp2 {
		t.Errorf("expected deterministic fingerprints to be identical, got %s != %s", fp1, fp2)
	}
	if fp1 == fp3 {
		t.Errorf("expected different evidence keys to yield different fingerprints")
	}
}

func TestRiskScorer_Formula(t *testing.T) {
	scorer := pipeline.NewRiskScorer()

	// AWS key in repo: 10.0 * 0.85 * 1.0 * 10 = 85.0 -> CRITICAL
	score, sev := scorer.CalculateScore("exposed_aws_key", model.AssetTypeRepo)
	if score < 84.9 || score > 85.1 {
		t.Errorf("expected AWS Key score ~85.0, got %.2f", score)
	}
	if sev != model.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", sev)
	}

	// Dangling CNAME on subdomain: 9.0 * 0.95 * 1.0 * 10 = 85.5 -> CRITICAL
	score, sev = scorer.CalculateScore("dangling_cname_takeover", model.AssetTypeSubdomain)
	if score < 85.4 || score > 85.6 {
		t.Errorf("expected Dangling CNAME score ~85.5, got %.2f", score)
	}
	if sev != model.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", sev)
	}

	// Missing CSP on subdomain: 3.0 * 0.95 * 1.0 * 10 = 28.5 -> LOW
	score, sev = scorer.CalculateScore("missing_csp_header", model.AssetTypeSubdomain)
	if score < 28.4 || score > 28.6 {
		t.Errorf("expected CSP score ~28.5, got %.2f", score)
	}
	if sev != model.SeverityLow {
		t.Errorf("expected SeverityLow, got %s", sev)
	}
}

func TestPipeline_UpsertAndReopen(t *testing.T) {
	store := pipeline.NewMemoryFindingStore()
	pipe := pipeline.NewPipeline(store, pipeline.NewMemoryCache(), nil)

	scanID1 := uuid.New()
	assetID := uuid.New()
	asset := model.Asset{
		ID:       assetID,
		TenantID: "tenant-a",
		Type:     model.AssetTypeSubdomain,
		Value:    "api.example.com",
	}

	raw := []collector.RawFinding{
		{
			TargetAsset: asset,
			FindingType: "dangling_cname_takeover",
			Title:       "Dangling CNAME Takeover",
			EvidenceKey: "cname:api.example.com:target.github.io",
		},
	}

	// 1. Initial Scan: finding created as "new"
	ctx := context.Background()
	if err := pipe.ProcessRawFindings(ctx, scanID1, assetID, raw); err != nil {
		t.Fatalf("first scan failed: %v", err)
	}

	findings, err := store.ListByTenant(ctx, "tenant-a", pipeline.Filter{})
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.Status != model.FindingStatusNew {
		t.Errorf("expected initial status 'new', got %s", f1.Status)
	}
	if f1.OccurrenceCount != 1 {
		t.Errorf("expected occurrence count 1, got %d", f1.OccurrenceCount)
	}

	// 2. Analyst marks finding as "resolved"
	if err := store.UpdateStatus(ctx, f1.ID, model.FindingStatusResolved); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}

	fResolved, _ := store.GetFinding(ctx, f1.ID)
	if fResolved.Status != model.FindingStatusResolved {
		t.Fatalf("expected status 'resolved', got %s", fResolved.Status)
	}

	// 3. Next Scan (scanID2): vulnerability reappears! Pipeline MUST reopen it!
	scanID2 := uuid.New()
	if err := pipe.ProcessRawFindings(ctx, scanID2, assetID, raw); err != nil {
		t.Fatalf("second scan failed: %v", err)
	}

	fReopened, _ := store.GetFinding(ctx, f1.ID)
	if fReopened.Status != model.FindingStatusReopened {
		t.Errorf("expected finding to be automatically 'reopened', got %s", fReopened.Status)
	}
	if fReopened.OccurrenceCount != 2 {
		t.Errorf("expected occurrence count 2, got %d", fReopened.OccurrenceCount)
	}
	if fReopened.ScanID != scanID2 {
		t.Errorf("expected scan_id to update to scanID2")
	}
}

func TestPipeline_RedisDownGracefulDegradation(t *testing.T) {
	store := pipeline.NewMemoryFindingStore()
	// Inject cache that always errors
	pipe := pipeline.NewPipeline(store, &FailingCache{}, nil)

	scanID := uuid.New()
	assetID := uuid.New()
	asset := model.Asset{
		ID:       assetID,
		TenantID: "tenant-b",
		Type:     model.AssetTypeDomain,
		Value:    "example.com",
	}

	raw := []collector.RawFinding{
		{
			TargetAsset: asset,
			FindingType: "expired_tls_certificate",
			Title:       "Expired Certificate",
			EvidenceKey: "cert:expired:1234",
		},
	}

	// Pipeline MUST NOT fail even when Redis is down!
	err := pipe.ProcessRawFindings(context.Background(), scanID, assetID, raw)
	if err != nil {
		t.Errorf("expected graceful degradation when cache fails, got error: %v", err)
	}

	findings, _ := store.ListByTenant(context.Background(), "tenant-b", pipeline.Filter{})
	if len(findings) != 1 {
		t.Errorf("expected finding to be successfully saved to database despite Redis outage, got %d", len(findings))
	}
}

func TestScanDiff(t *testing.T) {
	scanA := uuid.New()
	scanB := uuid.New()

	finding1 := &model.Finding{
		ID:          uuid.New(),
		Fingerprint: "fp-1",
		Title:       "Finding 1 (Unchanged)",
	}
	finding2 := &model.Finding{
		ID:          uuid.New(),
		Fingerprint: "fp-2",
		Title:       "Finding 2 (Fixed in B)",
	}
	finding3 := &model.Finding{
		ID:          uuid.New(),
		Fingerprint: "fp-3",
		Title:       "Finding 3 (New in B)",
	}

	baseFindings := []*model.Finding{finding1, finding2}
	currentFindings := []*model.Finding{finding1, finding3}

	diff := pipeline.ComputeDiff(scanA, scanB, baseFindings, currentFindings)

	if len(diff.New) != 1 || diff.New[0].Fingerprint != "fp-3" {
		t.Errorf("expected 1 new finding (fp-3), got %+v", diff.New)
	}
	if len(diff.Unchanged) != 1 || diff.Unchanged[0].Fingerprint != "fp-1" {
		t.Errorf("expected 1 unchanged finding (fp-1), got %+v", diff.Unchanged)
	}
	if len(diff.Resolved) != 1 || diff.Resolved[0].Fingerprint != "fp-2" {
		t.Errorf("expected 1 resolved finding (fp-2), got %+v", diff.Resolved)
	}
}
