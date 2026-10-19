// Package api provides HTTP handler logic for SurfaceWatch resources.
package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/pipeline"
	"github.com/surfacewatch/surfacewatch/internal/scheduler"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// AppContext holds shared service dependencies for HTTP handlers.
type AppContext struct {
	Scope      *scope.Scope
	Scheduler  scheduler.Store
	Findings   pipeline.FindingStore
	Cache      pipeline.Cache
	AssetStore *MemoryAssetStore
	ScanStore  *MemoryScanStore
}

// MemoryAssetStore manages Asset records with tenant partitioning.
type MemoryAssetStore struct {
	assets map[uuid.UUID]*model.Asset
}

func NewMemoryAssetStore() *MemoryAssetStore {
	return &MemoryAssetStore{assets: make(map[uuid.UUID]*model.Asset)}
}

func (s *MemoryAssetStore) Create(a *model.Asset) {
	s.assets[a.ID] = a
}

func (s *MemoryAssetStore) List(tenantID string) []*model.Asset {
	var out []*model.Asset
	for _, a := range s.assets {
		if a.TenantID == tenantID {
			out = append(out, a)
		}
	}
	return out
}

func (s *MemoryAssetStore) Get(id uuid.UUID, tenantID string) *model.Asset {
	a, ok := s.assets[id]
	if !ok || a.TenantID != tenantID {
		return nil
	}
	return a
}

// MemoryScanStore tracks Scan records with tenant partitioning.
type MemoryScanStore struct {
	scans map[uuid.UUID]*model.Scan
}

func NewMemoryScanStore() *MemoryScanStore {
	return &MemoryScanStore{scans: make(map[uuid.UUID]*model.Scan)}
}

func (s *MemoryScanStore) Create(scan *model.Scan) {
	s.scans[scan.ID] = scan
}

func (s *MemoryScanStore) List(tenantID string) []*model.Scan {
	var out []*model.Scan
	for _, sc := range s.scans {
		if sc.TenantID == tenantID {
			out = append(out, sc)
		}
	}
	return out
}

func (s *MemoryScanStore) Get(id uuid.UUID, tenantID string) *model.Scan {
	sc, ok := s.scans[id]
	if !ok || sc.TenantID != tenantID {
		return nil
	}
	return sc
}

// --- ASSET HANDLERS ---

type CreateAssetRequest struct {
	Type   model.AssetType   `json:"type"`
	Value  string            `json:"value"`
	Labels map[string]string `json:"labels,omitempty"`
}

func (app *AppContext) HandleCreateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := GetTenantID(r.Context())

	var req CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to parse JSON body")
		return
	}

	val := strings.TrimSpace(req.Value)
	if val == "" {
		WriteError(w, http.StatusBadRequest, "VALIDATION_FAILED", "Asset value cannot be empty")
		return
	}

	// Verify asset is authorized in scope allowlist!
	if app.Scope != nil {
		var scopeErr error
		switch req.Type {
		case model.AssetTypeDomain, model.AssetTypeSubdomain:
			scopeErr = app.Scope.CheckDomain(val)
		case model.AssetTypeRepo:
			scopeErr = app.Scope.CheckRepository(val)
		case model.AssetTypeCIDR:
			scopeErr = app.Scope.CheckIP(val)
		}
		if scopeErr != nil {
			WriteError(w, http.StatusUnprocessableEntity, "OUT_OF_SCOPE", scopeErr.Error())
			return
		}
	}

	now := time.Now().UTC()
	asset := &model.Asset{
		ID        : uuid.New(),
		TenantID  : tenantID,
		Type      : req.Type,
		Value     : val,
		Labels    : req.Labels,
		CreatedAt : now,
		UpdatedAt : now,
	}

	app.AssetStore.Create(asset)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(asset)
}

func (app *AppContext) HandleListAssets(w http.ResponseWriter, r *http.Request) {
	tenantID := GetTenantID(r.Context())
	assets := app.AssetStore.List(tenantID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"assets": assets, "count": len(assets)})
}

// --- SCAN HANDLERS ---

type CreateScanRequest struct {
	AssetID uuid.UUID `json:"asset_id"`
}

func (app *AppContext) HandleCreateScan(w http.ResponseWriter, r *http.Request) {
	tenantID := GetTenantID(r.Context())

	var req CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to parse JSON body")
		return
	}

	asset := app.AssetStore.Get(req.AssetID, tenantID)
	if asset == nil {
		WriteError(w, http.StatusNotFound, "ASSET_NOT_FOUND", "Asset does not exist or does not belong to tenant")
		return
	}

	now := time.Now().UTC()
	scan := &model.Scan{
		ID            : uuid.New(),
		TenantID      : tenantID,
		TargetAssetID : asset.ID,
		TargetValue   : asset.Value,
		Status        : model.ScanStatusQueued,
		CreatedAt     : now,
		UpdatedAt     : now,
	}
	app.ScanStore.Create(scan)

	// Enqueue collector jobs for this asset
	collectorsForAsset := []string{}
	switch asset.Type {
	case model.AssetTypeDomain:
		collectorsForAsset = []string{"certificate_transparency", "typosquat_detection", "dns_resolution", "tls_and_headers"}
	case model.AssetTypeSubdomain:
		collectorsForAsset = []string{"dns_resolution", "tls_and_headers"}
	case model.AssetTypeRepo:
		collectorsForAsset = []string{"secret_scanner"}
	}

	for _, colName := range collectorsForAsset {
		job := &scheduler.Job{
			ID            : uuid.New(),
			TenantID      : tenantID,
			ScanID        : scan.ID,
			CollectorName : colName,
			Target        : *asset,
			Status        : scheduler.JobStatusQueued,
			NextRunAt     : now,
		}
		_ = app.Scheduler.Enqueue(r.Context(), job)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(scan)
}

func (app *AppContext) HandleListScans(w http.ResponseWriter, r *http.Request) {
	tenantID := GetTenantID(r.Context())
	scans := app.ScanStore.List(tenantID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"scans": scans, "count": len(scans)})
}

// --- FINDINGS HANDLERS ---

func (app *AppContext) HandleListFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := GetTenantID(r.Context())
	q := r.URL.Query()

	filter := pipeline.Filter{
		Severity : q.Get("severity"),
		Status   : q.Get("status"),
		Cursor   : q.Get("cursor"),
	}

	if limitStr := q.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			filter.Limit = l
		}
	}
	if filter.Limit == 0 {
		filter.Limit = 50
	}

	if assetIDStr := q.Get("asset_id"); assetIDStr != "" {
		if id, err := uuid.Parse(assetIDStr); err == nil {
			filter.AssetID = &id
		}
	}

	findings, err := app.Findings.ListByTenant(r.Context(), tenantID, filter)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to query findings")
		return
	}

	// Simple cursor pagination: use index offset
	cursorOffset := 0
	if filter.Cursor != "" {
		if off, err := strconv.Atoi(filter.Cursor); err == nil && off >= 0 {
			cursorOffset = off
		}
	}

	var pagedFindings []*model.Finding
	nextCursor := ""

	if cursorOffset < len(findings) {
		end := cursorOffset + filter.Limit
		if end >= len(findings) {
			end = len(findings)
		} else {
			nextCursor = strconv.Itoa(end)
		}
		pagedFindings = findings[cursorOffset:end]
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"findings":    pagedFindings,
		"count":       len(pagedFindings),
		"next_cursor": nextCursor,
	})
}

func (app *AppContext) HandleGetFinding(w http.ResponseWriter, r *http.Request) {
	tenantID := GetTenantID(r.Context())
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "INVALID_ID", "Finding ID must be a valid UUID")
		return
	}

	f, err := app.Findings.GetFinding(r.Context(), id)
	if err != nil || f.TenantID != tenantID {
		// Strict multi-tenant isolation: prevent IDOR by returning 404
		WriteError(w, http.StatusNotFound, "NOT_FOUND", "Finding not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(f)
}

type UpdateStatusRequest struct {
	Status model.FindingStatus `json:"status"`
}

func (app *AppContext) HandleUpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := GetTenantID(r.Context())
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "INVALID_ID", "Finding ID must be a valid UUID")
		return
	}

	f, err := app.Findings.GetFinding(r.Context(), id)
	if err != nil || f.TenantID != tenantID {
		WriteError(w, http.StatusNotFound, "NOT_FOUND", "Finding not found")
		return
	}

	var req UpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to parse JSON body")
		return
	}

	if !req.Status.IsValid() {
		WriteError(w, http.StatusBadRequest, "INVALID_STATUS", "Invalid finding status value")
		return
	}

	if err := app.Findings.UpdateStatus(r.Context(), id, req.Status); err != nil {
		WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update status")
		return
	}

	// Return updated finding
	updated, _ := app.Findings.GetFinding(r.Context(), id)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

// --- STATS SUMMARY HANDLER ---

func (app *AppContext) HandleStatsSummary(w http.ResponseWriter, r *http.Request) {
	tenantID := GetTenantID(r.Context())

	assets := app.AssetStore.List(tenantID)
	scans := app.ScanStore.List(tenantID)
	findings, _ := app.Findings.ListByTenant(r.Context(), tenantID, pipeline.Filter{})

	severityCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}

	statusCounts := map[string]int{
		"new":          0,
		"acknowledged": 0,
		"resolved":     0,
		"reopened":     0,
	}

	for _, f := range findings {
		severityCounts[string(f.Severity)]++
		statusCounts[string(f.Status)]++
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"total_assets":    len(assets),
		"total_scans":     len(scans),
		"total_findings":  len(findings),
		"by_severity":     severityCounts,
		"by_status":       statusCounts,
	})
}

// --- HEALTH & READINESS PROBES ---

func HandleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy","uptime":"ok"}`))
}

func (app *AppContext) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	// Check Redis availability if cache exists
	cacheStatus := "healthy"
	if app.Cache != nil && !app.Cache.IsAvailable() {
		cacheStatus = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ready",
		"components": map[string]string{
			"scheduler": "healthy",
			"findings":  "healthy",
			"cache":      cacheStatus,
		},
	})
}
