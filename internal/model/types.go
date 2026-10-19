// Package model defines the core domain models and lifecycle states for SurfaceWatch.
// Every model is designed with multi-tenant isolation, immutable timestamps, and
// typed lifecycle states suitable for enterprise attack-surface management.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AssetType categorizes the digital asset under monitoring.
type AssetType string

const (
	AssetTypeDomain    AssetType = "domain"
	AssetTypeSubdomain AssetType = "subdomain"
	AssetTypeRepo      AssetType = "repo"
	AssetTypeCIDR      AssetType = "cidr"
)

// Asset represents an authorized entity in scope for security monitoring.
type Asset struct {
	ID        uuid.UUID         `json:"id"`
	TenantID  string            `json:"tenant_id"`
	Type      AssetType         `json:"type"`
	Value     string            `json:"value"`	// e.g. "example.com", "sub.example.com", or "/path/to/repo"
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// ScanStatus tracks the execution phase of a security scan.
type ScanStatus string

const (
	ScanStatusQueued    ScanStatus = "queued"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

// Scan represents a scheduled or manual attack-surface assessment run on an asset.
type Scan struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      string     `json:"tenant_id"`
	TargetAssetID uuid.UUID  `json:"target_asset_id"`
	TargetValue   string     `json:"target_value"`
	Status        ScanStatus `json:"status"`
	Summary       string     `json:"summary,omitempty"`
	ErrorMessage  string     `json:"error_message,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// FindingStatus represents the formal lifecycle state of a discovered security finding.
type FindingStatus string

const (
	// FindingStatusNew indicates a newly detected finding awaiting review.
	FindingStatusNew FindingStatus = "new"
	// FindingStatusAcknowledged indicates an analyst has confirmed the finding is valid.
	FindingStatusAcknowledged FindingStatus = "acknowledged"
	// FindingStatusResolved indicates the underlying vulnerability or misconfiguration was remediated.
	FindingStatusResolved FindingStatus = "resolved"
	// FindingStatusReopened indicates a previously resolved finding has reappeared in a subsequent scan.
	FindingStatusReopened FindingStatus = "reopened"
)

// IsValid checks if the status transition is a recognized state.
func (s FindingStatus) IsValid() bool {
	switch s {
	case FindingStatusNew, FindingStatusAcknowledged, FindingStatusResolved, FindingStatusReopened:
		return true
	default:
		return false
	}
}

// Severity classifies the risk level of a finding based on impact and likelihood.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// ParseSeverity safely normalizes and converts a string into a Severity constant.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "INFO":
		return SeverityInfo, nil
	case "LOW":
		return SeverityLow, nil
	case "MEDIUM":
		return SeverityMedium, nil
	case "HIGH":
		return SeverityHigh, nil
	case "CRITICAL":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("unknown severity: %s", s)
	}
}

// Finding represents an actionable security issue discovered on an authorized asset.
// CRITICAL SAFETY RULE: Raw exposed secrets are NEVER stored here or in the database.
// Only a redacted preview and a cryptographically salted hash are retained.
type Finding struct {
	ID              uuid.UUID              `json:"id"`
	TenantID        string                 `json:"tenant_id"`
	ScanID          uuid.UUID              `json:"scan_id"`
	AssetID         uuid.UUID              `json:"asset_id"`
	Fingerprint     string                 `json:"fingerprint"`	// Deterministic hash of (type, asset, evidence key)
	FindingType     string                 `json:"finding_type"`
	Severity        Severity               `json:"severity"`
	Score           float64                `json:"score"`	// Calculated via formula: TypeWeight * Exposure * Confidence
	Status          FindingStatus          `json:"status"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Evidence        map[string]any         `json:"evidence,omitempty"`
	RedactedPreview string                 `json:"redacted_preview,omitempty"`	// Safe representation (e.g., "AKIA...3FQA")
	SecretHash      string                 `json:"secret_hash,omitempty"`	// Salted HMAC/SHA256 for deduplication
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
	OccurrenceCount int                    `json:"occurrence_count"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// EvidenceJSON converts the evidence map to JSON bytes for storage.
func (f *Finding) EvidenceJSON() ([]byte, error) {
	if f.Evidence == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(f.Evidence)
}
