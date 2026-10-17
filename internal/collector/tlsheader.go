// Package collector provides TLS metadata auditing and HTTP security header inspection.
package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// TLSInspector defines an interface for fetching TLS connection state.
type TLSInspector interface {
	InspectTLS(ctx context.Context, host string) (*TLSState, error)
}

// TLSState captures certificate and protocol negotiation details.
type TLSState struct {
	Version            uint16
	CipherSuite        uint16
	PeerCertificates   []*x509.Certificate
	VerifiedChains     [][]*x509.Certificate
	InsecureSkipVerify bool
}

// NetTLSInspector is the production inspector using net/tls.
type NetTLSInspector struct {
	timeout time.Duration
}

func NewNetTLSInspector() *NetTLSInspector {
	return &NetTLSInspector{timeout: 5 * time.Second}
}

func (n *NetTLSInspector) InspectTLS(ctx context.Context, host string) (*TLSState, error) {
	if !LiveCallsAllowed() {
		return nil, fmt.Errorf("live TLS inspection disabled: set %s=true to allow live TLS handshakes", EnvAllowLiveCalls)
	}
	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // we want to inspect even self-signed / expired certs
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", host+":443")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("failed to cast to tls.Conn")
	}
	state := tlsConn.ConnectionState()

	return &TLSState{
		Version:          state.Version,
		CipherSuite:      state.CipherSuite,
		PeerCertificates: state.PeerCertificates,
		VerifiedChains:   state.VerifiedChains,
	}, nil
}

// TLSHeaderCollector performs passive TLS metadata inspection and HTTP security header audits.
type TLSHeaderCollector struct {
	client       HTTPClient
	tlsInspector TLSInspector
	scope        *scope.Scope
}

// NewTLSHeaderCollector constructs a collector with injectable HTTP and TLS transports.
func NewTLSHeaderCollector(sc *scope.Scope, client HTTPClient, inspector TLSInspector) *TLSHeaderCollector {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if inspector == nil {
		inspector = NewNetTLSInspector()
	}
	return &TLSHeaderCollector{
		client:       client,
		tlsInspector: inspector,
		scope:        sc,
	}
}

func (c *TLSHeaderCollector) Name() string {
	return "tls_and_headers"
}

func (c *TLSHeaderCollector) Collect(ctx context.Context, target model.Asset) ([]RawFinding, error) {
	if err := GuardScope(c.scope, target); err != nil {
		return nil, err
	}

	host := strings.TrimSpace(strings.ToLower(target.Value))
	var findings []RawFinding

	// 1. Audit TLS Certificate & Configuration
	tlsState, err := c.tlsInspector.InspectTLS(ctx, host)
	if err == nil && tlsState != nil {
		// Check weak TLS version
		if tlsState.Version < tls.VersionTLS12 {
			findings = append(findings, RawFinding{
				TargetAsset: target,
				FindingType: "weak_tls_version",
				Severity:    model.SeverityHigh,
				Title:       fmt.Sprintf("Deprecated TLS Version In Use on %s", host),
				Description: fmt.Sprintf("Host negotiated TLS version 0x%04x (below TLS 1.2 minimum standard). Vulnerable to protocol downgrade attacks.", tlsState.Version),
				EvidenceKey: fmt.Sprintf("tls_ver:%s", host),
				Evidence: map[string]any{
					"host":        host,
					"tls_version": tlsState.Version,
					"recommend":   "Enforce TLS 1.2 or TLS 1.3 only.",
				},
			})
		}

		// Inspect leaf certificate
		if len(tlsState.PeerCertificates) > 0 {
			leaf := tlsState.PeerCertificates[0]
			now := time.Now()

			// Check expired
			if now.After(leaf.NotAfter) {
				findings = append(findings, RawFinding{
					TargetAsset: target,
					FindingType: "expired_tls_certificate",
					Severity:    model.SeverityHigh,
					Title:       fmt.Sprintf("Expired TLS Certificate on %s", host),
					Description: fmt.Sprintf("Certificate expired on %s (%s ago). Visitors will experience browser trust warnings.", leaf.NotAfter.Format(time.RFC3339), now.Sub(leaf.NotAfter).Round(time.Hour)),
					EvidenceKey: fmt.Sprintf("cert_expired:%s:%s", host, leaf.SerialNumber.String()),
					Evidence: map[string]any{
						"host":          host,
						"issuer":        leaf.Issuer.CommonName,
						"subject":       leaf.Subject.CommonName,
						"not_after":     leaf.NotAfter.Format(time.RFC3339),
						"serial_number": leaf.SerialNumber.String(),
					},
				})
			} else if leaf.NotAfter.Sub(now) < 30*24*time.Hour {
				// Expiring soon (within 30 days)
				daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
				findings = append(findings, RawFinding{
					TargetAsset: target,
					FindingType: "expiring_tls_certificate",
					Severity:    model.SeverityMedium,
					Title:       fmt.Sprintf("TLS Certificate Expiring Soon on %s (%d days remaining)", host, daysLeft),
					Description: fmt.Sprintf("Certificate will expire on %s. Plan renewal promptly to avoid service disruption.", leaf.NotAfter.Format(time.RFC3339)),
					EvidenceKey: fmt.Sprintf("cert_expiring:%s:%s", host, leaf.SerialNumber.String()),
					Evidence: map[string]any{
						"host":           host,
						"days_remaining": daysLeft,
						"not_after":      leaf.NotAfter.Format(time.RFC3339),
						"issuer":         leaf.Issuer.CommonName,
					},
				})
			}

			// Check Self-Signed
			if leaf.Issuer.CommonName == leaf.Subject.CommonName && leaf.Issuer.Organization == nil {
				findings = append(findings, RawFinding{
					TargetAsset: target,
					FindingType: "self_signed_certificate",
					Severity:    model.SeverityMedium,
					Title:       fmt.Sprintf("Self-Signed Certificate Detected on %s", host),
					Description: fmt.Sprintf("Issuer %q matches Subject. Untrusted by standard browser CA bundles.", leaf.Issuer.CommonName),
					EvidenceKey: fmt.Sprintf("self_signed:%s:%s", host, leaf.SerialNumber.String()),
					Evidence: map[string]any{
						"host":    host,
						"subject": leaf.Subject.CommonName,
						"issuer":  leaf.Issuer.CommonName,
					},
				})
			}
		}
	}

	// 2. Audit HTTP Security Headers
	// Build GET request to https://<host>
	reqURL := fmt.Sprintf("https://%s/", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "SurfaceWatch-Audit/1.0 (+https://github.com/surfacewatch/surfacewatch)")
		resp, err := c.client.Do(req)
		if err == nil && resp != nil {
			defer resp.Body.Close()

			headerChecks := []struct {
				headerName  string
				findingType string
				severity    model.Severity
				title       string
				description string
			}{
				{
					headerName:  "Strict-Transport-Security",
					findingType: "missing_hsts_header",
					severity:    model.SeverityMedium,
					title:       fmt.Sprintf("Missing Strict-Transport-Security (HSTS) on %s", host),
					description: "HSTS header prevents SSL stripping and forces browsers to communicate strictly over encrypted HTTPS.",
				},
				{
					headerName:  "Content-Security-Policy",
					findingType: "missing_csp_header",
					severity:    model.SeverityLow,
					title:       fmt.Sprintf("Missing Content-Security-Policy (CSP) on %s", host),
					description: "CSP protects against Cross-Site Scripting (XSS) and arbitrary data injection by restricting authorized script sources.",
				},
				{
					headerName:  "X-Content-Type-Options",
					findingType: "missing_x_content_type_options",
					severity:    model.SeverityLow,
					title:       fmt.Sprintf("Missing X-Content-Type-Options on %s", host),
					description: "Missing 'X-Content-Type-Options: nosniff' permits browsers to MIME-sniff responses away from the declared content-type.",
				},
				{
					headerName:  "X-Frame-Options",
					findingType: "missing_x_frame_options",
					severity:    model.SeverityLow,
					title:       fmt.Sprintf("Missing X-Frame-Options on %s", host),
					description: "Missing clickjacking protection allows malicious sites to frame this domain.",
				},
			}

			for _, check := range headerChecks {
				val := resp.Header.Get(check.headerName)
				if strings.TrimSpace(val) == "" {
					findings = append(findings, RawFinding{
						TargetAsset: target,
						FindingType: check.findingType,
						Severity:    check.severity,
						Title:       check.title,
						Description: check.description,
						EvidenceKey: fmt.Sprintf("header:%s:%s", host, strings.ToLower(check.headerName)),
						Evidence: map[string]any{
							"host":        host,
							"header":      check.headerName,
							"status_code": resp.StatusCode,
							"remediation": fmt.Sprintf("Configure web server to return '%s' header on all HTTPS responses.", check.headerName),
						},
					})
				}
			}
		}
	}

	return findings, nil
}
