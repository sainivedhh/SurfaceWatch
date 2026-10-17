package collector_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// FakeTLSInspector allows testing TLS edge cases without real sockets.
type FakeTLSInspector struct {
	State *collector.TLSState
	Err   error
}

func (f *FakeTLSInspector) InspectTLS(ctx context.Context, host string) (*collector.TLSState, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.State, nil
}

func TestTLSHeaderCollector_WeakTLSAndExpiredCert(t *testing.T) {
	scopeYAML := `
version: "1.0"
allowlist:
  domains:
    - "example.com"
`
	sc, _ := scope.Parse([]byte(scopeYAML))

	expiredTime := time.Now().Add(-48 * time.Hour)
	fakeCert := &x509.Certificate{
		SerialNumber: big.NewInt(9999),
		Subject:      pkix.Name{CommonName: "example.com"},
		Issuer:       pkix.Name{CommonName: "Fake CA"},
		NotBefore:    time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:     expiredTime,
	}

	inspector := &FakeTLSInspector{
		State: &collector.TLSState{
			Version:          tls.VersionTLS10, // Deprecated TLS 1.0
			PeerCertificates: []*x509.Certificate{fakeCert},
		},
	}

	// Fake HTTP response with NO security headers
	fakeClient := &FakeHTTPClient{
		ResponseStatusCode: 200,
		ResponseBody:       "<html>Hello</html>",
		ResponseHeader:     http.Header{},
	}

	col := collector.NewTLSHeaderCollector(sc, fakeClient, inspector)
	target := model.Asset{
		ID:    uuid.New(),
		Type:  model.AssetTypeDomain,
		Value: "example.com",
	}

	findings, err := col.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	findingTypes := make(map[string]bool)
	for _, f := range findings {
		findingTypes[f.FindingType] = true
	}

	expectedTypes := []string{
		"weak_tls_version",
		"expired_tls_certificate",
		"missing_hsts_header",
		"missing_csp_header",
		"missing_x_content_type_options",
		"missing_x_frame_options",
	}

	for _, exp := range expectedTypes {
		if !findingTypes[exp] {
			t.Errorf("expected finding type %q to be reported, but it was missing", exp)
		}
	}
}

func TestTLSHeaderCollector_ValidHeadersAndValidCert(t *testing.T) {
	scopeYAML := `
version: "1.0"
allowlist:
  domains:
    - "example.com"
`
	sc, _ := scope.Parse([]byte(scopeYAML))

	validCert := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject:      pkix.Name{CommonName: "example.com"},
		Issuer:       pkix.Name{CommonName: "Let's Encrypt"},
		NotBefore:    time.Now().Add(-10 * 24 * time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour), // 60 days left
	}

	inspector := &FakeTLSInspector{
		State: &collector.TLSState{
			Version:          tls.VersionTLS13,
			PeerCertificates: []*x509.Certificate{validCert},
		},
	}

	headers := make(http.Header)
	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")

	fakeClient := &FakeHTTPClient{
		ResponseStatusCode: 200,
		ResponseBody:       "ok",
		ResponseHeader:     headers,
	}

	col := collector.NewTLSHeaderCollector(sc, fakeClient, inspector)
	target := model.Asset{
		ID:    uuid.New(),
		Type:  model.AssetTypeDomain,
		Value: "example.com",
	}

	findings, err := col.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 security warnings for fully hardened host, got %d findings: %+v", len(findings), findings)
	}
}
