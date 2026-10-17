package collector_test

import (
	"context"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// FakeResolver mocks DNS lookups without any real network traffic.
type FakeResolver struct {
	HostMap  map[string][]string
	CNAMEMap map[string]string
	ErrorMap map[string]error
}

func (f *FakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if err, ok := f.ErrorMap[host]; ok {
		return nil, err
	}
	if ips, ok := f.HostMap[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Err: "no such host", Name: host}
}

func (f *FakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if cname, ok := f.CNAMEMap[host]; ok {
		return cname, nil
	}
	return host, nil
}

func TestDNSCollector_DanglingCNAME(t *testing.T) {
	scopeYAML := `
version: "1.0"
allowlist:
  domains:
    - "example.com"
`
	sc, _ := scope.Parse([]byte(scopeYAML))

	resolver := &FakeResolver{
		HostMap: map[string][]string{
			"example.com": {"93.184.216.34"},
			// Notice: "myblog.github.io" is NOT in HostMap, simulating NXDOMAIN!
		},
		CNAMEMap: map[string]string{
			"blog.example.com": "myblog.github.io.",
		},
		ErrorMap: map[string]error{
			"myblog.github.io": &net.DNSError{IsNotFound: true, Err: "no such host"},
		},
	}

	col := collector.NewDNSCollector(sc, resolver)
	target := model.Asset{
		ID:    uuid.New(),
		Type:  model.AssetTypeSubdomain,
		Value: "blog.example.com",
	}

	findings, err := col.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error collecting DNS: %v", err)
	}

	var foundTakeover bool
	for _, f := range findings {
		if f.FindingType == "dangling_cname_takeover" {
			foundTakeover = true
			if f.Severity != model.SeverityHigh {
				t.Errorf("expected SeverityHigh for dangling CNAME, got %s", f.Severity)
			}
			if f.Evidence["detected_service"] != "GitHub Pages" {
				t.Errorf("expected detected service 'GitHub Pages', got %v", f.Evidence["detected_service"])
			}
		}
	}

	if !foundTakeover {
		t.Errorf("expected dangling_cname_takeover finding, but none was generated")
	}
}

func TestDNSCollector_LegitimateCNAME(t *testing.T) {
	scopeYAML := `
version: "1.0"
allowlist:
  domains:
    - "example.com"
`
	sc, _ := scope.Parse([]byte(scopeYAML))

	resolver := &FakeResolver{
		HostMap: map[string][]string{
			"app-lb.aws.com": {"1.2.3.4"},
		},
		CNAMEMap: map[string]string{
			"app.example.com": "app-lb.aws.com.",
		},
	}

	col := collector.NewDNSCollector(sc, resolver)
	target := model.Asset{
		ID:    uuid.New(),
		Type:  model.AssetTypeSubdomain,
		Value: "app.example.com",
	}

	findings, err := col.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundNormalCNAME bool
	for _, f := range findings {
		if f.FindingType == "dns_cname_record" {
			foundNormalCNAME = true
			if f.Severity != model.SeverityInfo {
				t.Errorf("expected SeverityInfo for normal CNAME, got %s", f.Severity)
			}
		}
	}
	if !foundNormalCNAME {
		t.Errorf("expected normal dns_cname_record finding, got none")
	}
}
