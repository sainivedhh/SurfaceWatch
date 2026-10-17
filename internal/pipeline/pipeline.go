// Package pipeline orchestrates finding lifecycle management, fingerprinting,
// score calculation, and persistence.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
)

// FindingStore defines data persistence for security findings.
type FindingStore interface {
	UpsertFinding(ctx context.Context, f *model.Finding) (*model.Finding, bool, error)
	GetFinding(ctx context.Context, id uuid.UUID) (*model.Finding, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, newStatus model.FindingStatus) error
	ListByScan(ctx context.Context, scanID uuid.UUID) ([]*model.Finding, error)
	ListByTenant(ctx context.Context, tenantID string, filter Filter) ([]*model.Finding, error)
}

// Filter provides querying options for findings.
type Filter struct {
	Severity string
	Status   string
	AssetID  *uuid.UUID
	Limit    int
	Cursor   string
}

// Pipeline orchestrates ingestion from raw findings to enriched, scored, deduplicated records.
type Pipeline struct {
	store  FindingStore
	cache  Cache
	scorer *RiskScorer
	logger *slog.Logger
}

func NewPipeline(store FindingStore, cache Cache, logger *slog.Logger) *Pipeline {
	if cache == nil {
		cache = NewMemoryCache()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Pipeline{
		store:  store,
		cache:  cache,
		scorer: NewRiskScorer(),
		logger: logger,
	}
}

// ProcessRawFindings transforms raw observations into structured findings, calculates
// risk scores, generates fingerprints, and upserts them idempotently.
func (p *Pipeline) ProcessRawFindings(ctx context.Context, scanID uuid.UUID, assetID uuid.UUID, raw []collector.RawFinding) error {
	for _, r := range raw {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		fp := GenerateFingerprint(r.FindingType, r.TargetAsset.Value, r.EvidenceKey)
		score, sev := p.scorer.CalculateScore(r.FindingType, r.TargetAsset.Type)

		now := time.Now().UTC()
		finding := &model.Finding{
			ID:              uuid.New(),
			TenantID:        r.TargetAsset.TenantID,
			ScanID:          scanID,
			AssetID:         assetID,
			Fingerprint:     fp,
			FindingType:     r.FindingType,
			Severity:        sev,
			Score:           score,
			Status:          model.FindingStatusNew,
			Title:           r.Title,
			Description:     r.Description,
			Evidence:        r.Evidence,
			RedactedPreview: r.RedactedPreview,
			SecretHash:      r.SecretHash,
			FirstSeen:       now,
			LastSeen:        now,
			OccurrenceCount: 1,
			CreatedAt:       now,
			UpdatedAt:       now,
		}

		persisted, isNew, err := p.store.UpsertFinding(ctx, finding)
		if err != nil {
			p.logger.Error("Failed to upsert finding", "fingerprint", fp, "error", err)
			return err
		}

		// Invalidate / update cache
		cacheKey := fmt.Sprintf("finding:%s", persisted.ID.String())
		if val, err := json.Marshal(persisted); err == nil {
			_ = p.cache.Set(ctx, cacheKey, string(val), 15*time.Minute)
		}

		if isNew {
			p.logger.Info("New security finding discovered",
				"id", persisted.ID,
				"type", persisted.FindingType,
				"severity", persisted.Severity,
				"score", persisted.Score)
		} else if persisted.Status == model.FindingStatusReopened {
			p.logger.Warn("Resolved security finding has reappeared (reopened)",
				"id", persisted.ID,
				"fingerprint", persisted.Fingerprint,
				"occurrences", persisted.OccurrenceCount)
		}
	}

	return nil
}

// MemoryFindingStore implements FindingStore in-memory for testing.
type MemoryFindingStore struct {
	mu           sync.RWMutex
	findings     map[uuid.UUID]*model.Finding
	fingerprints map[string]uuid.UUID // index: tenant_id:fingerprint -> finding_id
}

func NewMemoryFindingStore() *MemoryFindingStore {
	return &MemoryFindingStore{
		findings:     make(map[uuid.UUID]*model.Finding),
		fingerprints: make(map[string]uuid.UUID),
	}
}

func (m *MemoryFindingStore) UpsertFinding(ctx context.Context, f *model.Finding) (*model.Finding, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idxKey := fmt.Sprintf("%s:%s", f.TenantID, f.Fingerprint)
	existingID, exists := m.fingerprints[idxKey]

	now := time.Now().UTC()

	if exists {
		// Existing finding: update occurrence count, last seen, and reopen if previously resolved
		existing := m.findings[existingID]
		existing.LastSeen = now
		existing.OccurrenceCount++
		existing.ScanID = f.ScanID // update to latest scan
		existing.UpdatedAt = now

		// Reopen resolved findings if they reappear
		if existing.Status == model.FindingStatusResolved {
			existing.Status = model.FindingStatusReopened
		}

		cpy := *existing
		return &cpy, false, nil
	}

	// Brand new finding
	f.CreatedAt = now
	f.UpdatedAt = now
	cpy := *f
	m.findings[f.ID] = &cpy
	m.fingerprints[idxKey] = f.ID
	return &cpy, true, nil
}

func (m *MemoryFindingStore) GetFinding(ctx context.Context, id uuid.UUID) (*model.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	f, ok := m.findings[id]
	if !ok {
		return nil, errors.New("finding not found")
	}
	cpy := *f
	return &cpy, nil
}

func (m *MemoryFindingStore) UpdateStatus(ctx context.Context, id uuid.UUID, newStatus model.FindingStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	f, ok := m.findings[id]
	if !ok {
		return errors.New("finding not found")
	}
	f.Status = newStatus
	f.UpdatedAt = time.Now().UTC()
	return nil
}

func (m *MemoryFindingStore) ListByScan(ctx context.Context, scanID uuid.UUID) ([]*model.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*model.Finding
	for _, f := range m.findings {
		if f.ScanID == scanID {
			cpy := *f
			out = append(out, &cpy)
		}
	}
	return out, nil
}

func (m *MemoryFindingStore) ListByTenant(ctx context.Context, tenantID string, filter Filter) ([]*model.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*model.Finding
	for _, f := range m.findings {
		if f.TenantID != tenantID {
			continue
		}
		if filter.Severity != "" && string(f.Severity) != filter.Severity {
			continue
		}
		if filter.Status != "" && string(f.Status) != filter.Status {
			continue
		}
		if filter.AssetID != nil && f.AssetID != *filter.AssetID {
			continue
		}
		cpy := *f
		out = append(out, &cpy)
	}
	return out, nil
}
