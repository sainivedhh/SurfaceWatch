// Package collector provides DNS resolution and dangling CNAME takeover detection.
package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// Resolver defines the interface for DNS lookups to allow deterministic mocked responses in tests.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// NetResolver is the production DNS resolver wrapping net.Resolver.
type NetResolver struct {
	resolver *net.Resolver
}

func NewNetResolver() *NetResolver {
	return &NetResolver{resolver: net.DefaultResolver}
}

func (r *NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if !LiveCallsAllowed() {
		return nil, fmt.Errorf("live DNS queries disabled: set %s=true to allow live DNS calls", EnvAllowLiveCalls)
	}
	return r.resolver.LookupHost(ctx, host)
}

func (r *NetResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if !LiveCallsAllowed() {
		return "", fmt.Errorf("live DNS queries disabled: set %s=true to allow live DNS calls", EnvAllowLiveCalls)
	}
	return r.resolver.LookupCNAME(ctx, host)
}

// DNSCollector inspects DNS records and detects dangling CNAMEs (subdomain takeover candidates).
type DNSCollector struct {
	resolver Resolver
	scope    *scope.Scope
}

// NewDNSCollector constructs a DNS collector with an injectable resolver.
func NewDNSCollector(sc *scope.Scope, resolver Resolver) *DNSCollector {
	if resolver == nil {
		resolver = NewNetResolver()
	}
	return &DNSCollector{
		resolver: resolver,
		scope:    sc,
	}
}

func (c *DNSCollector) Name() string {
	return "dns_resolution"
}

// KnownCloudProviders lists common third-party SaaS/Cloud providers prone to CNAME takeover when abandoned.
var KnownCloudProviders = []struct {
	Suffix      string
	ServiceName string
}{
	{".github.io", "GitHub Pages"},
	{".s3-website-", "AWS S3 Website"},
	{".s3.amazonaws.com", "AWS S3 Bucket"},
	{".azurewebsites.net", "Azure App Service"},
	{".cloudapp.net", "Azure CloudApp"},
	{".herokuapp.com", "Heroku App"},
	{".cloudfront.net", "AWS CloudFront"},
	{".myshopify.com", "Shopify Store"},
	{".zendesk.com", "Zendesk Help Center"},
	{".pantheonsite.io", "Pantheon"},
	{".fastly.net", "Fastly CDN"},
	{".surge.sh", "Surge.sh"},
}

func (c *DNSCollector) Collect(ctx context.Context, target model.Asset) ([]RawFinding, error) {
	if err := GuardScope(c.scope, target); err != nil {
		return nil, err
	}

	host := strings.TrimSpace(strings.ToLower(target.Value))
	var findings []RawFinding

	// 1. Check CNAME record
	cname, cnameErr := c.resolver.LookupCNAME(ctx, host)
	cleanCNAME := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(cname)), ".")

	if cnameErr == nil && cleanCNAME != "" && cleanCNAME != host {
		// Subdomain has a CNAME pointer. Now resolve the target CNAME destination.
		targetIPs, targetErr := c.resolver.LookupHost(ctx, cleanCNAME)

		isNXDOMAIN := false
		if targetErr != nil {
			var dnsErr *net.DNSError
			if errors.As(targetErr, &dnsErr) && dnsErr.IsNotFound {
				isNXDOMAIN = true
			} else if strings.Contains(strings.ToLower(targetErr.Error()), "no such host") ||
				strings.Contains(strings.ToLower(targetErr.Error()), "nxdomain") {
				isNXDOMAIN = true
			}
		}

		if isNXDOMAIN || len(targetIPs) == 0 {
			// Identify if the destination is a cloud/SaaS provider known for takeover
			matchedService := "Unknown Cloud Service"
			for _, provider := range KnownCloudProviders {
				if strings.Contains(cleanCNAME, provider.Suffix) {
					matchedService = provider.ServiceName
					break
				}
			}

			findings = append(findings, RawFinding{
				TargetAsset: target,
				FindingType: "dangling_cname_takeover",
				Severity:    model.SeverityHigh,
				Title:       fmt.Sprintf("Dangling CNAME Points to Unclaimed Target: %s -> %s", host, cleanCNAME),
				Description: fmt.Sprintf("Subdomain %s has a CNAME record pointing to %s (%s) which fails to resolve (NXDOMAIN). An external attacker could register the destination resource and hijack traffic.", host, cleanCNAME, matchedService),
				EvidenceKey: fmt.Sprintf("cname:%s:%s", host, cleanCNAME),
				Evidence: map[string]any{
					"host":             host,
					"cname_target":     cleanCNAME,
					"detected_service": matchedService,
					"nxdomain":         true,
					"remediation":      "Remove the orphan CNAME record from DNS or reclaim the destination cloud resource immediately.",
				},
			})
		} else {
			// Legitimate active CNAME
			findings = append(findings, RawFinding{
				TargetAsset: target,
				FindingType: "dns_cname_record",
				Severity:    model.SeverityInfo,
				Title:       fmt.Sprintf("DNS CNAME Record: %s -> %s", host, cleanCNAME),
				Description: fmt.Sprintf("Subdomain %s delegates to canonical name %s", host, cleanCNAME),
				EvidenceKey: fmt.Sprintf("cname_active:%s:%s", host, cleanCNAME),
				Evidence: map[string]any{
					"host":         host,
					"cname_target": cleanCNAME,
					"target_ips":   targetIPs,
				},
			})
		}
	}

	// 2. Resolve A/AAAA records
	ips, err := c.resolver.LookupHost(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			findings = append(findings, RawFinding{
				TargetAsset: target,
				FindingType: "dns_nxdomain",
				Severity:    model.SeverityInfo,
				Title:       fmt.Sprintf("DNS Record Non-Existent (NXDOMAIN): %s", host),
				Description: fmt.Sprintf("The domain %s does not resolve to any active IP address.", host),
				EvidenceKey: fmt.Sprintf("nxdomain:%s", host),
				Evidence: map[string]any{
					"host":  host,
					"error": err.Error(),
				},
			})
		}
	} else if len(ips) > 0 {
		findings = append(findings, RawFinding{
			TargetAsset: target,
			FindingType: "dns_resolution",
			Severity:    model.SeverityInfo,
			Title:       fmt.Sprintf("Resolved DNS IP Addresses for %s", host),
			Description: fmt.Sprintf("Discovered %d IP address(es) for %s", len(ips), host),
			EvidenceKey: fmt.Sprintf("resolved_ips:%s", host),
			Evidence: map[string]any{
				"host": host,
				"ips":  ips,
			},
		})
	}

	return findings, nil
}
