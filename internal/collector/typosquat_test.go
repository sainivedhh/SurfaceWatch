package collector_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

func TestPermutationEngine_Classes(t *testing.T) {
	engine := collector.NewPermutationEngine()
	domain := "example.com"
	name, tld := collector.SplitDomain(domain)

	// 1. Omission
	omissions := engine.GenerateOmissions(name, tld)
	if len(omissions) != len("example") {
		t.Errorf("expected %d omissions, got %d", len("example"), len(omissions))
	}
	// Verify "xample.com" and "exmple.com" exist
	hasXample := false
	for _, p := range omissions {
		if p.Domain == "xample.com" {
			hasXample = true
		}
	}
	if !hasXample {
		t.Errorf("expected 'xample.com' in omissions")
	}

	// 2. Repetition
	repetitions := engine.GenerateRepetitions(name, tld)
	if len(repetitions) != len("example") {
		t.Errorf("expected %d repetitions, got %d", len("example"), len(repetitions))
	}
	hasExxample := false
	for _, p := range repetitions {
		if p.Domain == "exxample.com" {
			hasExxample = true
		}
	}
	if !hasExxample {
		t.Errorf("expected 'exxample.com' in repetitions")
	}

	// 3. Transposition
	transpositions := engine.GenerateTranspositions(name, tld)
	if len(transpositions) != len("example")-1 {
		t.Errorf("expected %d transpositions, got %d", len("example")-1, len(transpositions))
	}
	hasEaxmple := false
	for _, p := range transpositions {
		if p.Domain == "eaxmple.com" {
			hasEaxmple = true
		}
	}
	if !hasEaxmple {
		t.Errorf("expected 'eaxmple.com' in transpositions")
	}

	// 4. AdjacentKey
	adjacentKeys := engine.GenerateAdjacentKeys(name, tld)
	if len(adjacentKeys) == 0 {
		t.Errorf("expected non-zero adjacent keys")
	}

	// 5. Homoglyph
	homoglyphs := engine.GenerateHomoglyphs(name, tld)
	if len(homoglyphs) == 0 {
		t.Errorf("expected homoglyphs for domain containing 'e'")
	}
	// 'e' -> '3', so '3xampl3.com' or '3xample.com'
	has3xample := false
	for _, p := range homoglyphs {
		if p.Domain == "3xample.com" || p.Domain == "exampl3.com" {
			has3xample = true
		}
	}
	if !has3xample {
		t.Errorf("expected homoglyph '3xample.com' or 'exampl3.com'")
	}

	// 6. TLDSwap
	tldSwaps := engine.GenerateTLDSwaps(name, tld)
	if len(tldSwaps) == 0 {
		t.Errorf("expected alternative TLD swaps")
	}
	hasNet := false
	for _, p := range tldSwaps {
		if p.Domain == "example.net" {
			hasNet = true
		}
	}
	if !hasNet {
		t.Errorf("expected 'example.net' in TLD swaps")
	}

	// 7. Hyphenation
	hyphenations := engine.GenerateHyphenations(name, tld)
	if len(hyphenations) != len("example")-1 {
		t.Errorf("expected %d hyphenations, got %d", len("example")-1, len(hyphenations))
	}

	// Generate All total count metrics
	all := engine.GenerateAll(domain)
	t.Logf("Permutation breakdown for %s: omissions=%d, reps=%d, trans=%d, adj=%d, homo=%d, tld=%d, hyph=%d | Total deduplicated: %d",
		domain, len(omissions), len(repetitions), len(transpositions), len(adjacentKeys), len(homoglyphs), len(tldSwaps), len(hyphenations), len(all))

	if len(all) < 20 {
		t.Errorf("expected at least 20 total permutations, got %d", len(all))
	}
}

func TestTyposquatCollector_Collect(t *testing.T) {
	scopeYAML := `
version: "1.0"
allowlist:
  domains:
    - "example.com"
`
	sc, _ := scope.Parse([]byte(scopeYAML))

	// Fake resolver with simulated registered typosquat domain
	resolver := &FakeResolver{
		HostMap: map[string][]string{
			"exxample.com": {"198.51.100.1"},
			"example.net":  {"198.51.100.2"},
		},
	}

	col := collector.NewTyposquatCollector(sc, resolver)
	target := model.Asset{
		ID:    uuid.New(),
		Type:  model.AssetTypeDomain,
		Value: "example.com",
	}

	findings, err := col.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 active typosquat findings, got %d", len(findings))
	}

	foundMap := make(map[string]bool)
	for _, f := range findings {
		foundMap[f.Evidence["typosquat_domain"].(string)] = true
		if f.FindingType != "active_typosquat_domain" {
			t.Errorf("expected active_typosquat_domain finding type, got %s", f.FindingType)
		}
	}

	if !foundMap["exxample.com"] || !foundMap["example.net"] {
		t.Errorf("expected both exxample.com and example.net to be reported as active typosquats")
	}
}
