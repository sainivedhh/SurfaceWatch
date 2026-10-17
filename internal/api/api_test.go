package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/api"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/pipeline"
	"github.com/surfacewatch/surfacewatch/internal/scheduler"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

func setupTestRouter(t *testing.T) (http.Handler, *api.MemoryKeyStore, *api.AppContext) {
	scopeYAML := `
version: "1.0"
allowlist:
  domains:
    - "example.com"
`
	sc, err := scope.Parse([]byte(scopeYAML))
	if err != nil {
		t.Fatalf("failed to parse scope: %v", err)
	}

	keyStore := api.NewMemoryKeyStore()
	_ = keyStore.RegisterKey("admin-key-123", "tenant-alpha", api.RoleAdmin, "Admin Alpha")
	_ = keyStore.RegisterKey("analyst-key-123", "tenant-alpha", api.RoleAnalyst, "Analyst Alpha")
	_ = keyStore.RegisterKey("viewer-key-123", "tenant-alpha", api.RoleViewer, "Viewer Alpha")
	_ = keyStore.RegisterKey("tenant-beta-key", "tenant-beta", api.RoleAdmin, "Admin Beta")

	auth := api.NewAuthenticator(keyStore)

	appCtx := &api.AppContext{
		Scope:      sc,
		Scheduler:  scheduler.NewMemoryStore(),
		Findings:   pipeline.NewMemoryFindingStore(),
		Cache:      pipeline.NewMemoryCache(),
		AssetStore: api.NewMemoryAssetStore(),
		ScanStore:  api.NewMemoryScanStore(),
	}

	router := api.NewRouter(appCtx, auth, api.RouterConfig{
		MaxBodyBytes: 1024 * 1024,
		RateLimit:    100,
		Burst:        200,
	})

	return router, keyStore, appCtx
}

func TestAPI_AuthenticationAndRBAC(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	// 1. Missing API Key: 401 Unauthorized
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized without key, got %d", rec.Code)
	}

	// 2. Viewer trying to POST /api/v1/assets (Admin required): 403 Forbidden
	body := `{"type":"domain","value":"example.com"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/assets", strings.NewReader(body))
	req.Header.Set("X-API-Key", "viewer-key-123")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for Viewer role, got %d", rec.Code)
	}

	// 3. Admin creating asset: 201 Created
	req = httptest.NewRequest(http.MethodPost, "/api/v1/assets", strings.NewReader(body))
	req.Header.Set("X-API-Key", "admin-key-123")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201 Created for Admin role, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestAPI_SecurityHeaders(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing X-Content-Type-Options: nosniff")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing X-Frame-Options: DENY")
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Errorf("missing Strict-Transport-Security header")
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Errorf("missing X-Request-ID header")
	}
}

func TestAPI_ScopeEnforcement(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	// Attempt to register out-of-scope domain
	body := `{"type":"domain","value":"unauthorized-target.org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assets", strings.NewReader(body))
	req.Header.Set("X-API-Key", "admin-key-123")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 Unprocessable Entity for out-of-scope asset, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestAPI_TenantIsolation_IDORDefense(t *testing.T) {
	router, _, appCtx := setupTestRouter(t)

	// Create finding for tenant-alpha
	alphaFinding := &model.Finding{
		ID:          uuid.New(),
		TenantID:    "tenant-alpha",
		ScanID:      uuid.New(),
		Fingerprint: "fp-alpha-secret",
		FindingType: "exposed_aws_key",
		Severity:    model.SeverityCritical,
		Status:      model.FindingStatusNew,
		Title:       "Alpha Critical Key",
	}
	_, _, _ = appCtx.Findings.UpsertFinding(context.Background(), alphaFinding)

	// Tenant Alpha can view their finding
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+alphaFinding.ID.String(), nil)
	req.Header.Set("X-API-Key", "viewer-key-123")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for tenant alpha viewing their own finding, got %d", rec.Code)
	}

	// IDOR Attack: Tenant Beta attempts to view Tenant Alpha's finding
	reqBeta := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+alphaFinding.ID.String(), nil)
	reqBeta.Header.Set("X-API-Key", "tenant-beta-key")
	recBeta := httptest.NewRecorder()
	router.ServeHTTP(recBeta, reqBeta)

	// Must return 404 NOT FOUND (no leak of resource existence across tenant boundaries)
	if recBeta.Code != http.StatusNotFound {
		t.Errorf("IDOR VULNERABILITY: expected 404 Not Found for cross-tenant access attempt, got %d", recBeta.Code)
	}
}

func TestSSRFProtection(t *testing.T) {
	// 1. Static validation checks
	if err := api.ValidateURL("http://127.0.0.1/admin"); err == nil {
		t.Errorf("expected ValidateURL to block 127.0.0.1 loopback")
	}
	if err := api.ValidateURL("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Errorf("expected ValidateURL to block AWS cloud metadata IP")
	}

	// 2. Connect-time verification with fake safe client
	client := api.NewSafeHTTPClient(2 * time.Second)
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:9999/status", nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatalf("expected connect-time error blocking 127.0.0.1, got nil")
	}
	if !strings.Contains(err.Error(), "restricted IP") && !strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("expected SSRF blocked error message, got: %v", err)
	}
}

func TestWebhook_HMACSigningAndDeadLetter(t *testing.T) {
	var receivedSig string
	var receivedBody []byte

	// Spin up fake receiver
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Hub-Signature-256")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		receivedBody = buf.Bytes()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sub := api.WebhookSubscription{
		ID:        uuid.New(),
		TenantID:  "tenant-alpha",
		URL:       ts.URL,
		Secret:    "webhook-super-secret-key",
		Active:    true,
		CreatedAt: time.Now(),
	}

	finding := &model.Finding{
		ID:          uuid.New(),
		Title:       "Test Finding",
		Severity:    model.SeverityHigh,
		Score:       80.0,
		Status:      model.FindingStatusNew,
		Fingerprint: "fp-test-hmac",
	}

	dispatcher := api.NewWebhookDispatcher(ts.Client(), nil)
	err := dispatcher.DispatchFindingAlert(context.Background(), sub, finding)
	if err != nil {
		t.Fatalf("unexpected error dispatching webhook: %v", err)
	}

	// Verify HMAC signature
	expectedSig := "sha256=" + api.ComputeHMAC(receivedBody, sub.Secret)
	if receivedSig != expectedSig {
		t.Errorf("HMAC signature mismatch: got %q, expected %q", receivedSig, expectedSig)
	}

	// Test Dead-Letter Queue on permanent failure
	subFailing := api.WebhookSubscription{
		ID:       uuid.New(),
		TenantID: "tenant-alpha",
		URL:      "http://localhost.unreachable.invalid/webhook",
		Secret:   "secret",
	}

	err = dispatcher.DispatchFindingAlert(context.Background(), subFailing, finding)
	if err == nil {
		t.Errorf("expected failure for unreachable URL")
	}

	deadLetters := dispatcher.GetDeadLetters()
	if len(deadLetters) != 1 {
		t.Errorf("expected 1 entry in dead-letter table, got %d", len(deadLetters))
	}
}
