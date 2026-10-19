// Package collector defines the interface and data types for passive attack-surface
// and leak detection collectors. All network and filesystem operations are abstracted
// behind interfaces so tests run completely offline with synthetic fixtures.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// EnvAllowLiveCalls is the environment variable that must be set to "true"
// for any real network calls to be permitted. By default, live network calls are blocked.
const EnvAllowLiveCalls = "SURFACEWATCH_ALLOW_LIVE_CALLS"

// RawFinding represents an unpersisted observation made by a collector.
// It will be processed, fingerprinted, scored, and deduplicated in the pipeline.
type RawFinding struct {
	TargetAsset     model.Asset            `json:"target_asset"`
	FindingType     string                 `json:"finding_type"`
	Severity        model.Severity         `json:"severity"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	EvidenceKey     string                 `json:"evidence_key"`	// Unique identifier within the asset (e.g. domain, file:line)
	Evidence        map[string]any         `json:"evidence,omitempty"`
	RedactedPreview string                 `json:"redacted_preview,omitempty"`	// Safe redacted snippet
	SecretHash      string                 `json:"secret_hash,omitempty"`	// Salted hash for deduplication
}

// Collector is the pluggable interface implemented by all monitoring engines.
type Collector interface {
	Name() string
	Collect(ctx context.Context, target model.Asset) ([]RawFinding, error)
}

// LiveCallsAllowed checks if the operator has explicitly authorized real network queries.
func LiveCallsAllowed() bool {
	return os.Getenv(EnvAllowLiveCalls) == "true"
}

// SaltedSecretHash computes a SHA-256 hash using an internal salt.
// Raw secrets are NEVER persisted; only this hash and a redacted preview are kept.
const defaultSecretSalt = "surfacewatch_v1_leak_salt_"

func HashSecret(raw string) string {
	h:= sha256.Sum256([]byte(defaultSecretSalt + raw))
	return hex.EncodeToString(h[:])
}

// RedactSecret returns a safe preview showing only prefix and suffix characters.
// Example: "AKIAIOSFODNN7EXAMPLE" -> "AKIA...MPLE"
func RedactSecret(secret string) string {
	runes:= []rune(secret)
	n    := len(runes)
	if n <= 6 {
		return "******"
	}
	prefixLen := 4
	suffixLen := 4
	if n < 12 {
		prefixLen = 2
		suffixLen = 2
	}
	return fmt.Sprintf("%s...REDACTED...%s", string(runes[:prefixLen]), string(runes[n-suffixLen:]))
}

// GuardScope ensures a target asset is in-scope before collector execution.
func GuardScope(sc *scope.Scope, target model.Asset) error {
	if sc == nil {
		return nil
	}
	switch target.Type {
	case model.AssetTypeDomain, model.AssetTypeSubdomain:
		return sc.CheckDomain(target.Value)
	case model.AssetTypeRepo:
		return sc.CheckRepository(target.Value)
	default:
		return nil
	}
}
