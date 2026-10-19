// Package collector provides an authorized brand-protection permutation engine
// to detect typosquatting, phishing lookalikes, and combocquatting domains.
package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// PermutationType identifies which algorithm generated the variant domain.
type PermutationType string

const (
	PermOmission      PermutationType = "omission"
	PermRepetition    PermutationType = "repetition"
	PermTransposition PermutationType = "transposition"
	PermAdjacentKey   PermutationType = "adjacent_key"
	PermHomoglyph     PermutationType = "homoglyph"
	PermTLDSwap       PermutationType = "tld_swap"
	PermHyphenation   PermutationType = "hyphenation"
)

// Permutation represents a generated candidate domain.
type Permutation struct {
	Type   PermutationType `json:"type"`
	Domain string          `json:"domain"`
}

// QWERTY keyboard adjacent key map for adjacent_key substitution.
var qwertyNeighbors = map[rune][]rune{
	'a': {'q', 'w', 's', 'z'},
	'b': {'v', 'g', 'h', 'n'},
	'c': {'x', 'd', 'f', 'v'},
	'd': {'s', 'e', 'r', 'f', 'x', 'c'},
	'e': {'w', 's', 'd', 'r'},
	'f': {'d', 'r', 't', 'g', 'c', 'v'},
	'g': {'f', 't', 'y', 'h', 'v', 'b'},
	'h': {'g', 'y', 'u', 'j', 'b', 'n'},
	'i': {'u', 'j', 'k', 'o'},
	'j': {'h', 'u', 'i', 'k', 'n', 'm'},
	'k': {'j', 'i', 'o', 'l', 'm'},
	'l': {'k', 'o', 'p'},
	'm': {'n', 'j', 'k'},
	'n': {'b', 'h', 'j', 'm'},
	'o': {'i', 'k', 'l', 'p'},
	'p': {'o', 'l'},
	'q': {'1', '2', 'w', 'a'},
	'r': {'e', 'd', 'f', 't'},
	's': {'a', 'w', 'e', 'd', 'x', 'z'},
	't': {'r', 'f', 'g', 'y'},
	'u': {'y', 'h', 'j', 'i'},
	'v': {'c', 'f', 'g', 'b'},
	'w': {'q', 'a', 's', 'e'},
	'x': {'z', 's', 'd', 'c'},
	'y': {'t', 'g', 'h', 'u'},
	'z': {'a', 's', 'x'},
}

// Homoglyphs (visual lookalikes common in deceptive phishing and brand abuse).
var homoglyphs = map[rune][]rune{
	'o': {'0'},
	'l': {'1', 'i'},
	'i': {'1', 'l'},
	'e': {'3'},
	'a': {'4', '@'},
	's': {'5'},
	't': {'7'},
	'b': {'8'},
	'g': {'9', 'q'},
}

// Alternative common TLDs for brand surveillance.
var alternativeTLDs = []string{"net", "org", "co", "io", "ai", "biz", "info", "xyz"}

// PermutationEngine generates all classes of domain permutations.
type PermutationEngine struct{}

func NewPermutationEngine() *PermutationEngine {
	return &PermutationEngine{}
}

// SplitDomain separates the domain label from the TLD (e.g., "example.com" -> ("example", "com")).
func SplitDomain(d string) (name string, tld string) {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".")
	lastDot := strings.LastIndex(d, ".")
	if lastDot == -1 {
		return d, ""
	}
	return d[:lastDot], d[lastDot+1:]
}

// GenerateAll creates a deduplicated slice of permutations across all 7 classes.
func (pe *PermutationEngine) GenerateAll(domain string) []Permutation {
	var results []Permutation
	seen := make(map[string]struct{})
	add := func(p Permutation) {
		if _, exists := seen[p.Domain]; !exists && p.Domain != domain {
			seen[p.Domain] = struct{}{}
			results = append(results, p)
		}
	}
	name, tld := SplitDomain(domain)
	if name == "" || tld == "" {
		return results
	}
	for _, p := range pe.GenerateOmissions(name, tld) {
		add(p)
	}
	for _, p := range pe.GenerateRepetitions(name, tld) {
		add(p)
	}
	for _, p := range pe.GenerateTranspositions(name, tld) {
		add(p)
	}
	for _, p := range pe.GenerateAdjacentKeys(name, tld) {
		add(p)
	}
	for _, p := range pe.GenerateHomoglyphs(name, tld) {
		add(p)
	}
	for _, p := range pe.GenerateTLDSwaps(name, tld) {
		add(p)
	}
	for _, p := range pe.GenerateHyphenations(name, tld) {
		add(p)
	}
	return results
}

// GenerateOmissions drops each character once.
func (pe *PermutationEngine) GenerateOmissions(name, tld string) []Permutation {
	runes := []rune(name)
	var perms []Permutation
	if len(runes) <= 1 {
		return perms
	}
	for i := range runes {
		variant := string(runes[:i]) + string(runes[i+1:])
		perms = append(perms, Permutation{Type: PermOmission, Domain: fmt.Sprintf("%s.%s", variant, tld)})
	}
	return perms
}

// GenerateRepetitions duplicates each character once.
func (pe *PermutationEngine) GenerateRepetitions(name, tld string) []Permutation {
	runes := []rune(name)
	var perms []Permutation
	for i := range runes {
		variant := string(runes[:i]) + string(runes[i]) + string(runes[i:])
		perms = append(perms, Permutation{Type: PermRepetition, Domain: fmt.Sprintf("%s.%s", variant, tld)})
	}
	return perms
}

// GenerateTranspositions swaps adjacent characters.
func (pe *PermutationEngine) GenerateTranspositions(name, tld string) []Permutation {
	runes := []rune(name)
	var perms []Permutation
	if len(runes) <= 1 {
		return perms
	}
	for i := 0; i < len(runes)-1; i++ {
		cpy := make([]rune, len(runes))
		copy(cpy, runes)
		cpy[i], cpy[i+1] = cpy[i+1], cpy[i]
		perms = append(perms, Permutation{Type: PermTransposition, Domain: fmt.Sprintf("%s.%s", string(cpy), tld)})
	}
	return perms
}

// GenerateAdjacentKeys substitutes keyboard neighbors.
func (pe *PermutationEngine) GenerateAdjacentKeys(name, tld string) []Permutation {
	runes := []rune(name)
	var perms []Permutation
	for i, r := range runes {
		neighbors, ok := qwertyNeighbors[r]
		if !ok {
			continue
		}
		for _, n := range neighbors {
			cpy := make([]rune, len(runes))
			copy(cpy, runes)
			cpy[i] = n
			perms = append(perms, Permutation{Type: PermAdjacentKey, Domain: fmt.Sprintf("%s.%s", string(cpy), tld)})
		}
	}
	return perms
}

// GenerateHomoglyphs substitutes visually confusing symbols.
func (pe *PermutationEngine) GenerateHomoglyphs(name, tld string) []Permutation {
	runes := []rune(name)
	var perms []Permutation
	for i, r := range runes {
		replacements, ok := homoglyphs[r]
		if !ok {
			continue
		}
		for _, rep := range replacements {
			cpy := make([]rune, len(runes))
			copy(cpy, runes)
			cpy[i] = rep
			perms = append(perms, Permutation{Type: PermHomoglyph, Domain: fmt.Sprintf("%s.%s", string(cpy), tld)})
		}
	}
	return perms
}

// GenerateTLDSwaps swaps the TLD for alternative popular extensions.
func (pe *PermutationEngine) GenerateTLDSwaps(name, tld string) []Permutation {
	var perms []Permutation
	for _, alt := range alternativeTLDs {
		if strings.EqualFold(alt, tld) {
			continue
		}
		perms = append(perms, Permutation{Type: PermTLDSwap, Domain: fmt.Sprintf("%s.%s", name, alt)})
	}
	return perms
}

// GenerateHyphenations inserts a hyphen between adjacent characters.
func (pe *PermutationEngine) GenerateHyphenations(name, tld string) []Permutation {
	runes := []rune(name)
	var perms []Permutation
	if len(runes) <= 1 {
		return perms
	}
	for i := 1; i < len(runes); i++ {
		variant := string(runes[:i]) + "-" + string(runes[i:])
		perms = append(perms, Permutation{Type: PermHyphenation, Domain: fmt.Sprintf("%s.%s", variant, tld)})
	}
	return perms
}

// TyposquatCollector monitors typosquatting permutations and tests for active resolution.
type TyposquatCollector struct {
	resolver Resolver
	engine   *PermutationEngine
	scope    *scope.Scope
}

// NewTyposquatCollector constructs a TyposquatCollector with an injectable resolver.
func NewTyposquatCollector(sc *scope.Scope, resolver Resolver) *TyposquatCollector {
	if resolver == nil {
		resolver = NewNetResolver()
	}
	return &TyposquatCollector{resolver: resolver, engine: NewPermutationEngine(), scope: sc}
}

func (c *TyposquatCollector) Name() string { return "typosquat_detection" }

func (c *TyposquatCollector) Collect(ctx context.Context, target model.Asset) ([]RawFinding, error) {
	if err := GuardScope(c.scope, target); err != nil {
		return nil, err
	}
	domain := strings.TrimSpace(strings.ToLower(target.Value))
	permutations := c.engine.GenerateAll(domain)
	var findings []RawFinding
	for _, perm := range permutations {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Passive DNS resolution check on the lookalike candidate.
		ips, err := c.resolver.LookupHost(ctx, perm.Domain)
		if err == nil && len(ips) > 0 {
			findings = append(findings, RawFinding{
				TargetAsset: target,
				FindingType: "active_typosquat_domain",
				Severity:    model.SeverityMedium,
				Title:       fmt.Sprintf("Active Typosquat Lookalike Detected: %s (%s)", perm.Domain, perm.Type),
				Description: fmt.Sprintf("A %s variation of %s is actively resolving to IP(s): %s. This presents brand impersonation and credential phishing risk.", perm.Type, domain, strings.Join(ips, ", ")),
				EvidenceKey: fmt.Sprintf("typosquat:%s:%s", domain, perm.Domain),
				Evidence: map[string]any{
					"original_domain":  domain,
					"typosquat_domain": perm.Domain,
					"permutation_type": string(perm.Type),
					"resolved_ips":     ips,
					"threat":           "Brand impersonation / phishing",
				},
			})
		}
	}
	return findings, nil
}
