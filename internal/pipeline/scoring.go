// Package pipeline handles fingerprinting, risk scoring, state transitions,
// scan diffing, and caching for SurfaceWatch findings.
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/surfacewatch/surfacewatch/internal/model"
)

// GenerateFingerprint produces a deterministic, collision-resistant hash of a finding.
// Fingerprint = SHA-256(finding_type | asset_value | evidence_key)
func GenerateFingerprint(findingType string, assetValue string, evidenceKey string) string {
	raw := strings.ToLower(strings.TrimSpace(findingType)) + "|" +
		strings.ToLower(strings.TrimSpace(assetValue)) + "|" +
		strings.TrimSpace(evidenceKey)

	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// RiskScoring evaluates the severity and numeric score of a finding.
// Formula: Score = Min(100.0, TypeWeight * ExposureFactor * Confidence * 10.0)
type RiskScorer struct{}

func NewRiskScorer() *RiskScorer {
	return &RiskScorer{}
}

// Weights defined for threat types (scale 1.0 to 10.0).
var typeWeights = map[string]float64{
	"exposed_aws_key":                10.0,
	"exposed_github_token":           10.0,
	"exposed_private_key":            10.0,
	"dangling_cname_takeover":        9.0,
	"exposed_db_credential":          9.0,
	"expired_tls_certificate":        7.5,
	"weak_tls_version":               7.0,
	"active_typosquat_domain":        6.0,
	"expiring_tls_certificate":       5.0,
	"self_signed_certificate":        5.0,
	"missing_hsts_header":            4.5,
	"high_entropy_secret":            4.0,
	"missing_csp_header":             3.0,
	"missing_x_content_type_options": 2.5,
	"missing_x_frame_options":        2.5,
	"discovered_subdomain":           1.0,
	"dns_resolution":                 1.0,
	"dns_cname_record":               1.0,
}

// CalculateScore computes numeric score (0-100) and mapped model.Severity.
func (rs *RiskScorer) CalculateScore(findingType string, assetType model.AssetType) (float64, model.Severity) {
	weight, exists := typeWeights[findingType]
	if !exists {
		weight = 2.0 // default fallback
	}

	// Exposure factor based on asset type
	exposure := 1.0
	switch assetType {
	case model.AssetTypeDomain:
		exposure = 1.0
	case model.AssetTypeSubdomain:
		exposure = 0.95
	case model.AssetTypeRepo:
		exposure = 0.85
	case model.AssetTypeCIDR:
		exposure = 0.9
	}

	// Confidence factor: heuristics have slight discount
	confidence := 1.0
	if findingType == "high_entropy_secret" || findingType == "active_typosquat_domain" {
		confidence = 0.85
	}

	rawScore := weight * exposure * confidence * 10.0
	if rawScore > 100.0 {
		rawScore = 100.0
	}
	if rawScore < 0.0 {
		rawScore = 0.0
	}
	rawScore = float64(int(rawScore*100+0.5)) / 100.0

	// Severity bucket mapping
	var sev model.Severity
	switch {
	case rawScore >= 80.0:
		sev = model.SeverityCritical
	case rawScore >= 60.0:
		sev = model.SeverityHigh
	case rawScore >= 35.0:
		sev = model.SeverityMedium
	case rawScore >= 15.0:
		sev = model.SeverityLow
	default:
		sev = model.SeverityInfo
	}

	return rawScore, sev
}
