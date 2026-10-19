// Package scope implements authorization guardrails for SurfaceWatch.
// NON-NEGOTIABLE SAFETY: SurfaceWatch MUST ONLY collect data on assets explicitly
// authorized by the operator in scope.yaml. Any collector or worker attempting to
// evaluate an out-of-scope domain, subdomain, IP, or repository will be rejected
// with a typed ErrOutOfScope before any network transport or disk read is initiated.
package scope

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrOutOfScope is returned when an asset or target is not in the authorized scope.
type ErrOutOfScope struct {
	Target string
	Reason string
}

func (e *ErrOutOfScope) Error() string {
	return fmt.Sprintf("target %q is out of authorized scope: %s", e.Target, e.Reason)
}

// Config represents the raw deserialized scope configuration from scope.yaml.
type Config struct {
	Version   string        `yaml:"version"`
	Operator  string        `yaml:"operator"`
	Allowlist AllowlistRule `yaml:"allowlist"`
	Excludes  ExcludeRule   `yaml:"excludes"`
}

// AllowlistRule defines what assets are permitted for passive scanning.
type AllowlistRule struct {
	Domains      []string `yaml:"domains"`      // Root domains (e.g. "example.com")
	Wildcards    []string `yaml:"wildcards"`    // Wildcards (e.g. "*.example.com", "*.corp.local")
	Repositories []string `yaml:"repositories"` // Local directory paths allowed for secret scanning
	CIDRs        []string `yaml:"cidrs"`        // IP CIDR ranges authorized
}

// ExcludeRule defines targets explicitly blacklisted even if they match allowlist patterns.
type ExcludeRule struct {
	Domains      []string `yaml:"domains"`
	Repositories []string `yaml:"repositories"`
}

// Scope is the compiled, fast-lookup authorization engine.
type Scope struct {
	raw          Config
	exactDomains map[string]struct{}
	wildcardSubs []string
	cleanRepos   []string
	excludeDoms  map[string]struct{}
	excludeRepos []string
	parsedCIDRs  []*net.IPNet
}

// Load loads and parses a scope configuration from a YAML file.
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read scope file %q: %w", path, err)
	}
	return Parse(data)
}

// Parse parses and compiles a scope configuration from raw YAML bytes.
func Parse(data []byte) (*Scope, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse scope yaml: %w", err)
	}

	sc := &Scope{
		raw:          cfg,
		exactDomains: make(map[string]struct{}),
		excludeDoms:  make(map[string]struct{}),
	}

	for _, d := range cfg.Allowlist.Domains {
		norm := normalizeHostname(d)
		if norm != "" {
			sc.exactDomains[norm] = struct{}{}
		}
	}

	for _, w := range cfg.Allowlist.Wildcards {
		norm := normalizeHostname(w)
		norm = strings.TrimPrefix(norm, "*.")
		if norm != "" {
			sc.wildcardSubs = append(sc.wildcardSubs, norm)
		}
	}

	for _, r := range cfg.Allowlist.Repositories {
		sc.cleanRepos = append(sc.cleanRepos, cleanPath(r))
	}

	for _, e := range cfg.Excludes.Domains {
		norm := normalizeHostname(e)
		if norm != "" {
			sc.excludeDoms[norm] = struct{}{}
		}
	}

	for _, er := range cfg.Excludes.Repositories {
		sc.excludeRepos = append(sc.excludeRepos, cleanPath(er))
	}

	for _, cidr := range cfg.Allowlist.CIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in scope %q: %w", cidr, err)
		}
		sc.parsedCIDRs = append(sc.parsedCIDRs, ipnet)
	}

	return sc, nil
}

// normalizeHostname strips schemes, ports, trailing dots, and lowercases the domain.
func normalizeHostname(host string) string {
	h := strings.TrimSpace(host)
	if idx := strings.Index(h, "://"); idx != -1 {
		h = h[idx+3:]
	}
	if idx := strings.IndexAny(h, "/?#"); idx != -1 {
		h = h[:idx]
	}
	if strings.Contains(h, ":") && !strings.Contains(h, "]") {
		if hostPart, _, err := net.SplitHostPort(h); err == nil {
			h = hostPart
		}
	}
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// cleanPath normalizes both POSIX and Windows-style paths independent of runner OS.
// Windows drive paths are deliberately kept in Windows form so a Linux runner can
// validate the same scope configuration used on a Windows operator workstation.
func cleanPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if isWindowsPath(path) {
		return strings.ToLower(pathpkgCleanWindows(path))
	}
	return filepath.Clean(path)
}

func isWindowsPath(path string) bool {
	return len(path) >= 3 &&
		((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) &&
		path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}

func pathpkgCleanWindows(path string) string {
	path = strings.ReplaceAll(path, "/", "\\")
	drive := strings.ToLower(path[:2])
	rest := strings.TrimLeft(path[2:], "\\")
	parts := strings.Split(rest, "\\")
	stack := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, strings.ToLower(part))
		}
	}
	if len(stack) == 0 {
		return drive + "\\"
	}
	return drive + "\\" + strings.Join(stack, "\\")
}

// CheckDomain verifies that a target domain or subdomain is strictly inside the scope allowlist.
// It guards against lookalikes (e.g., "evil-example.com" or "example.com.attacker.com"),
// trailing dots, uppercase characters, and explicitly excluded subdomains.
func (s *Scope) CheckDomain(target string) error {
	norm := normalizeHostname(target)
	if norm == "" {
		return &ErrOutOfScope{Target: target, Reason: "empty target hostname"}
	}
	if _, excluded := s.excludeDoms[norm]; excluded {
		return &ErrOutOfScope{Target: target, Reason: "explicitly excluded domain"}
	}
	for exc := range s.excludeDoms {
		if strings.HasSuffix(norm, "."+exc) {
			return &ErrOutOfScope{Target: target, Reason: fmt.Sprintf("subdomain of excluded domain %q", exc)}
		}
	}
	if _, ok := s.exactDomains[norm]; ok {
		return nil
	}
	for root := range s.exactDomains {
		if strings.HasSuffix(norm, "."+root) {
			return nil
		}
	}
	for _, w := range s.wildcardSubs {
		if norm == w || strings.HasSuffix(norm, "."+w) {
			return nil
		}
	}
	return &ErrOutOfScope{Target: target, Reason: "hostname does not match any authorized domain or wildcard rule"}
}

// CheckRepository verifies whether a local directory or repository path is authorized.
func (s *Scope) CheckRepository(path string) error {
	clean := cleanPath(path)
	if clean == "" || clean == "." {
		return &ErrOutOfScope{Target: path, Reason: "empty or relative repository path"}
	}
	for _, exc := range s.excludeRepos {
		if isSubdir(clean, exc) {
			return &ErrOutOfScope{Target: path, Reason: "explicitly excluded directory"}
		}
	}
	for _, allow := range s.cleanRepos {
		if isSubdir(clean, allow) {
			return nil
		}
	}
	return &ErrOutOfScope{Target: path, Reason: "directory path is outside authorized repositories"}
}

// isSubdir checks if child is the same as or inside parent dir. Its inputs must
// already be normalized by cleanPath so Windows and POSIX path boundaries are preserved.
func isSubdir(child, parent string) bool {
	if child == parent {
		return true
	}
	separator := string(filepath.Separator)
	if isWindowsPath(child) && isWindowsPath(parent) {
		separator = "\\"
	}
	parentPrefix := parent
	if !strings.HasSuffix(parentPrefix, separator) {
		parentPrefix += separator
	}
	return strings.HasPrefix(child, parentPrefix)
}

// CheckIP verifies if an IP address belongs to an authorized CIDR.
func (s *Scope) CheckIP(ipStr string) error {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return &ErrOutOfScope{Target: ipStr, Reason: "invalid IP address format"}
	}
	for _, cidr := range s.parsedCIDRs {
		if cidr.Contains(ip) {
			return nil
		}
	}
	return &ErrOutOfScope{Target: ipStr, Reason: "IP address not in authorized CIDRs"}
}

// IsErrOutOfScope is a helper to check if an error is an ErrOutOfScope.
func IsErrOutOfScope(err error) bool {
	var targetErr *ErrOutOfScope
	return errors.As(err, &targetErr)
}
