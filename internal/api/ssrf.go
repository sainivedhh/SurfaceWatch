// Package api provides SSRF prevention and safe outbound HTTP transports.
package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	ErrSSRFBlocked = errors.New("SSRF protection: outbound request to private/restricted IP blocked")
)

// Private and reserved IP blocks disallowed for outbound webhook dispatch.
var restrictedCIDRs = []*net.IPNet{
	mustCIDR("127.0.0.0/8"),    // IPv4 Loopback
	mustCIDR("10.0.0.0/8"),     // RFC1918 Private
	mustCIDR("172.16.0.0/12"),  // RFC1918 Private
	mustCIDR("192.168.0.0/16"), // RFC1918 Private
	mustCIDR("169.254.0.0/16"), // IPv4 Link-local / AWS & Cloud Metadata (169.254.169.254)
	mustCIDR("100.64.0.0/10"),  // Carrier Grade NAT
	mustCIDR("0.0.0.0/8"),      // Broadcast / Current network
	mustCIDR("::1/128"),        // IPv6 Loopback
	mustCIDR("fc00::/7"),       // IPv6 Unique Local
	mustCIDR("fe80::/10"),      // IPv6 Link-local
}

func mustCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR %s: %v", s, err))
	}
	return ipnet
}

// IsPrivateIP checks if an IP belongs to any loopback, private, or link-local range.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	for _, cidr := range restrictedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// SafeDialContext performs safe DNS resolution and validates the target IP against SSRF blocklists
// AT CONNECT TIME. This prevents DNS rebinding (TOCTOU) attacks where a domain resolves to a public
// IP during validation, but returns 169.254.169.254 or 127.0.0.1 during socket establishment.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Resolve all IP addresses for the hostname
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for host %s", host)
	}

	// Verify all resolved IPs are safe; reject if any IP is private or loopback
	for _, ip := range ips {
		if IsPrivateIP(ip) {
			return nil, fmt.Errorf("%w: target %s resolves to restricted IP %s", ErrSSRFBlocked, host, ip.String())
		}
	}

	// Pin connection strictly to the first verified safe IP
	targetIP := ips[0].String()
	targetAddr := net.JoinHostPort(targetIP, port)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network, targetAddr)
}

// NewSafeHTTPClient returns an http.Client configured with SSRF-safe transport and strict timeouts.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           SafeDialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          50,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("stopped after 3 redirects to prevent redirect loops")
			}
			// Validate redirect destination hostname
			host := req.URL.Hostname()
			ips, err := net.DefaultResolver.LookupIP(req.Context(), "ip", host)
			if err != nil {
				return err
			}
			for _, ip := range ips {
				if IsPrivateIP(ip) {
					return fmt.Errorf("%w: redirect target %s resolves to restricted IP %s", ErrSSRFBlocked, host, ip.String())
				}
			}
			return nil
		},
	}
}

// ValidateURL performs initial static validation on a webhook URL.
func ValidateURL(rawURL string) error {
	u := strings.ToLower(strings.TrimSpace(rawURL))
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return errors.New("webhook URL must have http:// or https:// scheme")
	}
	if strings.Contains(u, "localhost") || strings.Contains(u, "127.0.0.1") || strings.Contains(u, "169.254.169.254") {
		return ErrSSRFBlocked
	}
	return nil
}
