package scope_test

import (
	"errors"
	"testing"

	"github.com/surfacewatch/surfacewatch/internal/scope"
)

const sampleScopeYAML = `
version: "1.0"
operator: "security-team@example.com"
allowlist:
  domains:
    - "example.com"
    - "authorized-partner.org"
  wildcards:
    - "*.acme-corp.net"
  repositories:
    - "D:\\projects\\SurfaceWatch\\testdata\\safe_repo"
    - "/opt/security/repo"
  cidrs:
    - "192.168.1.0/24"
    - "10.0.0.0/16"
excludes:
  domains:
    - "forbidden.example.com"
    - "topsecret.acme-corp.net"
  repositories:
    - "D:\\projects\\SurfaceWatch\\testdata\\safe_repo\\forbidden_subdir"
`

func TestScope_CheckDomain(t *testing.T) {
	sc, err := scope.Parse([]byte(sampleScopeYAML))
	if err != nil {
		t.Fatalf("unexpected error parsing scope: %v", err)
	}

	tests := []struct {
		name        string
		target      string
		expectAllow bool
	}{
		// Exact authorized domains
		{"exact match root domain", "example.com", true},
		{"exact match partner domain", "authorized-partner.org", true},
		{"exact match with uppercase", "EXAMPLE.COM", true},
		{"exact match mixed case", "Authorized-Partner.Org", true},
		{"exact match with trailing dot", "example.com.", true},
		{"exact match with https prefix", "https://example.com", true},
		{"exact match with http prefix and port", "http://example.com:8443", true},

		// Subdomains of authorized domains
		{"valid subdomain", "api.example.com", true},
		{"valid deep subdomain", "us-east-1.prod.api.example.com", true},
		{"valid subdomain with trailing dot", "api.example.com.", true},
		{"valid wildcard subdomain", "portal.acme-corp.net", true},
		{"valid deep wildcard subdomain", "sso.auth.acme-corp.net", true},

		// Lookalike / spoofing attacks (MUST BE REJECTED)
		{"lookalike prefix", "badexample.com", false},
		{"lookalike hyphenated prefix", "evil-example.com", false},
		{"lookalike suffix", "example.com.attacker.com", false},
		{"lookalike dot suffix attack", "example.com.co", false},
		{"lookalike tld variation", "example.net", false},
		{"lookalike internal prefix", "myexample.com", false},
		{"lookalike acme variation", "fake-acme-corp.net", false},
		{"lookalike acme suffix", "acme-corp.net.malicious.io", false},

		// Excluded domains (MUST BE REJECTED)
		{"explicitly excluded domain", "forbidden.example.com", false},
		{"subdomain of excluded domain", "sub.forbidden.example.com", false},
		{"explicitly excluded wildcard subdomain", "topsecret.acme-corp.net", false},

		// Out of scope domains
		{"completely unrelated domain", "google.com", false},
		{"empty domain", "", false},
		{"whitespace domain", "   ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sc.CheckDomain(tt.target)
			if tt.expectAllow && err != nil {
				t.Errorf("CheckDomain(%q) expected allow, got error: %v", tt.target, err)
			}
			if !tt.expectAllow {
				if err == nil {
					t.Errorf("CheckDomain(%q) expected denial with ErrOutOfScope, got nil", tt.target)
				}
				var outOfScope *scope.ErrOutOfScope
				if !errors.As(err, &outOfScope) {
					t.Errorf("expected error of type *ErrOutOfScope, got %T: %v", err, err)
				}
			}
		})
	}
}

func TestScope_CheckRepository(t *testing.T) {
	sc, err := scope.Parse([]byte(sampleScopeYAML))
	if err != nil {
		t.Fatalf("unexpected error parsing scope: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		expectAllow bool
	}{
		{"exact allowed repo", "/opt/security/repo", true},
		{"file inside allowed repo", "/opt/security/repo/src/main.go", true},
		{"safe subfolder", "D:\\projects\\SurfaceWatch\\testdata\\safe_repo\\pkg", true},
		{"excluded subfolder", "D:\\projects\\SurfaceWatch\\testdata\\safe_repo\\forbidden_subdir\\leak.txt", false},
		{"directory traversal attack", "/opt/security/repo/../../etc/shadow", false},
		{"prefix match boundary attack", "/opt/security/repo-sibling/exploit.go", false},
		{"unrelated directory", "/tmp/unauthorized", false},
		{"empty path", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sc.CheckRepository(tt.path)
			if tt.expectAllow && err != nil {
				t.Errorf("CheckRepository(%q) expected allow, got: %v", tt.path, err)
			}
			if !tt.expectAllow && err == nil {
				t.Errorf("CheckRepository(%q) expected rejection, got allow", tt.path)
			}
		})
	}
}

func TestScope_CheckIP(t *testing.T) {
	sc, err := scope.Parse([]byte(sampleScopeYAML))
	if err != nil {
		t.Fatalf("unexpected error parsing scope: %v", err)
	}

	tests := []struct {
		ip          string
		expectAllow bool
	}{
		{"192.168.1.50", true},
		{"192.168.1.254", true},
		{"10.0.4.12", true},
		{"192.168.2.1", false},
		{"8.8.8.8", false},
		{"not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			err := sc.CheckIP(tt.ip)
			if tt.expectAllow && err != nil {
				t.Errorf("CheckIP(%q) expected allow, got error: %v", tt.ip, err)
			}
			if !tt.expectAllow && err == nil {
				t.Errorf("CheckIP(%q) expected denial, got nil", tt.ip)
			}
		})
	}
}
