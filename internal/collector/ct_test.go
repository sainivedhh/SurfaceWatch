package collector_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// FakeHTTPClient mocks HTTP interactions deterministically.
type FakeHTTPClient struct {
	ResponseStatusCode int
	ResponseBody       string
	ResponseHeader     http.Header
	Err                error
}

func (f *FakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	header := f.ResponseHeader
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode: f.ResponseStatusCode,
		Body:       io.NopCloser(bytes.NewBufferString(f.ResponseBody)),
		Header:     header,
		Request:    req,
	}, nil
}

func TestCTCollector_Collect(t *testing.T) {
	scopeYAML := `
version: "1.0"
operator: "test@example.com"
allowlist:
  domains:
    - "example.com"
excludes:
  domains:
    - "excluded.example.com"
`
	sc, err := scope.Parse([]byte(scopeYAML))
	if err != nil {
		t.Fatalf("failed to parse scope: %v", err)
	}

	// Recorded crt.sh fixture response
	crtFixture := `[
  {
    "issuer_ca_id": 16418,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "api.example.com",
    "name_value": "api.example.com\nauth.example.com",
    "id": 12345678,
    "entry_timestamp": "2026-01-01T00:00:00",
    "not_before": "2026-01-01T00:00:00",
    "not_after": "2026-04-01T00:00:00"
  },
  {
    "issuer_ca_id": 16418,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "api.example.com",
    "name_value": "api.example.com\nexcluded.example.com\nattacker.com",
    "id": 12345679,
    "entry_timestamp": "2026-01-02T00:00:00",
    "not_before": "2026-01-02T00:00:00",
    "not_after": "2026-04-02T00:00:00"
  }
]`

	fakeClient := &FakeHTTPClient{
		ResponseStatusCode: 200,
		ResponseBody:       crtFixture,
	}

	ctCol := collector.NewCTCollector(sc, fakeClient)
	asset := model.Asset{
		ID:       uuid.New(),
		TenantID: "tenant-1",
		Type:     model.AssetTypeDomain,
		Value:    "example.com",
	}

	findings, err := ctCol.Collect(context.Background(), asset)
	if err != nil {
		t.Fatalf("unexpected error collecting CT logs: %v", err)
	}

	// Expected discovered subdomains: "api.example.com" and "auth.example.com"
	// "excluded.example.com" is filtered by scope exclusions.
	// "attacker.com" does not belong to example.com.
	// Duplicates are deduplicated.
	if len(findings) != 2 {
		t.Fatalf("expected 2 discovered subdomains, got %d", len(findings))
	}

	foundMap := make(map[string]bool)
	for _, f := range findings {
		foundMap[f.EvidenceKey] = true
		if f.FindingType != "discovered_subdomain" {
			t.Errorf("expected finding type 'discovered_subdomain', got %q", f.FindingType)
		}
	}

	if !foundMap["api.example.com"] {
		t.Errorf("expected 'api.example.com' to be discovered")
	}
	if !foundMap["auth.example.com"] {
		t.Errorf("expected 'auth.example.com' to be discovered")
	}
}

func TestCTCollector_OutOfScope(t *testing.T) {
	scopeYAML := `
version: "1.0"
allowlist:
  domains:
    - "example.com"
`
	sc, _ := scope.Parse([]byte(scopeYAML))
	ctCol := collector.NewCTCollector(sc, &FakeHTTPClient{})

	outOfScopeAsset := model.Asset{
		ID:    uuid.New(),
		Type:  model.AssetTypeDomain,
		Value: "unauthorized-target.org",
	}

	_, err := ctCol.Collect(context.Background(), outOfScopeAsset)
	if err == nil {
		t.Fatalf("expected ErrOutOfScope when scanning unauthorized target, got nil")
	}
	if !scope.IsErrOutOfScope(err) {
		t.Errorf("expected *ErrOutOfScope, got %T: %v", err, err)
	}
}
