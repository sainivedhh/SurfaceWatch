// Package collector provides Certificate Transparency (CT) log aggregation.
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// HTTPClient abstracts HTTP calls for deterministic testing with mocks/fixtures.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// CTLogEntry matches the JSON structure returned by CT log search aggregators (e.g., crt.sh).
type CTLogEntry struct {
	IssuerCaID     int64  `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
}

// CTCollector queries Certificate Transparency logs to discover exposed subdomains.
type CTCollector struct {
	client    HTTPClient
	scope     *scope.Scope
	baseURL   string
	timeLimit time.Duration
}

// NewCTCollector constructs a Certificate Transparency collector with an injectable HTTP client.
func NewCTCollector(sc *scope.Scope, client HTTPClient) *CTCollector {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &CTCollector{
		client:    client,
		scope:     sc,
		baseURL:   "https://crt.sh",
		timeLimit: 10 * time.Second,
	}
}

// SetBaseURL allows overriding the CT endpoint in tests.
func (c *CTCollector) SetBaseURL(url string) {
	c.baseURL = url
}

func (c *CTCollector) Name() string {
	return "certificate_transparency"
}

func (c *CTCollector) Collect(ctx context.Context, target model.Asset) ([]RawFinding, error) {
	if err := GuardScope(c.scope, target); err != nil {
		return nil, err
	}

	// Safety check: fail safe if live calls are forbidden and client is default
	if _, isDefault := c.client.(*http.Client); isDefault && !LiveCallsAllowed() {
		return nil, fmt.Errorf("live network queries disabled: set %s=true to allow real CT calls", EnvAllowLiveCalls)
	}

	domain := strings.TrimSpace(strings.ToLower(target.Value))
	queryURL := fmt.Sprintf("%s/?q=%s&output=json", c.baseURL, url.QueryEscape("%."+domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct CT request: %w", err)
	}
	req.Header.Set("User-Agent", "SurfaceWatch-Audit/1.0 (+https://github.com/surfacewatch/surfacewatch)")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CT log query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("CT API returned non-200 status: %d (body: %s)", resp.StatusCode, string(body))
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB safety cap
	if err != nil {
		return nil, fmt.Errorf("failed to read CT response body: %w", err)
	}

	var entries []CTLogEntry
	if err := json.Unmarshal(bodyBytes, &entries); err != nil {
		return nil, fmt.Errorf("failed to decode CT JSON response: %w", err)
	}

	// Deduplicate discovered subdomains
	seenSubdomains := make(map[string]struct{})
	var findings []RawFinding

	for _, entry := range entries {
		// NameValue can be multiline when SANs (Subject Alternative Names) are present
		names := strings.Split(entry.NameValue, "\n")
		names = append(names, entry.CommonName)

		for _, rawName := range names {
			cleanName := strings.TrimSpace(strings.ToLower(rawName))
			cleanName = strings.TrimPrefix(cleanName, "*.")
			cleanName = strings.TrimSuffix(cleanName, ".")

			if cleanName == "" || cleanName == domain {
				continue
			}

			// Ensure subdomain actually belongs to the target domain
			if !strings.HasSuffix(cleanName, "."+domain) {
				continue
			}

			// Verify discovered subdomain is allowed by scope
			if c.scope != nil && c.scope.CheckDomain(cleanName) != nil {
				continue
			}

			if _, exists := seenSubdomains[cleanName]; exists {
				continue
			}
			seenSubdomains[cleanName] = struct{}{}

			findings = append(findings, RawFinding{
				TargetAsset: target,
				FindingType: "discovered_subdomain",
				Severity:    model.SeverityInfo,
				Title:       fmt.Sprintf("Discovered Subdomain via CT Logs: %s", cleanName),
				Description: fmt.Sprintf("Certificate Transparency entry indicates certificate issued for %s (Issuer: %s)", cleanName, entry.IssuerName),
				EvidenceKey: cleanName,
				Evidence: map[string]any{
					"subdomain":       cleanName,
					"issuer":          entry.IssuerName,
					"entry_timestamp": entry.EntryTimestamp,
					"not_before":      entry.NotBefore,
					"not_after":       entry.NotAfter,
					"source":          "certificate_transparency",
				},
			})
		}
	}

	return findings, nil
}
