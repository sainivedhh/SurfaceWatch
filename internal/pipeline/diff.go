// Package pipeline provides scan diffing to track security posture evolution over time.
package pipeline

import (
	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/model"
)

// ScanDiff represents the delta between two sequential scans on the same asset.
type ScanDiff struct {
	BaseScanID    uuid.UUID        `json:"base_scan_id"`
	CurrentScanID uuid.UUID        `json:"current_scan_id"`
	New           []*model.Finding `json:"new"`
	Unchanged     []*model.Finding `json:"unchanged"`
	Resolved      []*model.Finding `json:"resolved"`
}

// ComputeDiff calculates the delta between an older base scan and a newer current scan.
func ComputeDiff(baseScanID, currentScanID uuid.UUID, baseFindings, currentFindings []*model.Finding) *ScanDiff {
	diff := &ScanDiff{
		BaseScanID:    baseScanID,
		CurrentScanID: currentScanID,
		New:           make([]*model.Finding, 0),
		Unchanged:     make([]*model.Finding, 0),
		Resolved:      make([]*model.Finding, 0),
	}

	baseMap := make(map[string]*model.Finding)
	for _, f := range baseFindings {
		baseMap[f.Fingerprint] = f
	}

	currentMap := make(map[string]*model.Finding)
	for _, f := range currentFindings {
		currentMap[f.Fingerprint] = f
		if _, existed := baseMap[f.Fingerprint]; existed {
			diff.Unchanged = append(diff.Unchanged, f)
		} else {
			diff.New = append(diff.New, f)
		}
	}

	for fp, oldFinding := range baseMap {
		if _, exists := currentMap[fp]; !exists {
			diff.Resolved = append(diff.Resolved, oldFinding)
		}
	}

	return diff
}
