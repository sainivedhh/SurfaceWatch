package collector_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

func TestSecretScanner_DetectorsAndRedaction(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "surfacewatch_test_repo_*")
	if err != nil {
		t.Fatalf("failed to create temp test repo: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFilePath := filepath.Join(tempDir, "config.env")
	rawContent := `# Development configuration
AWS_KEY=AKIAIOSFODNN77777777
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
DB_URI=postgres://admin:SuperSecretPassword123@db.prod.internal:5432/core
JWT_AUTH=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
HIGH_ENTROPY_TOKEN=xK9#mQ2$vL8!zP4@wR7&yT1*bN5^cV3%
PLACEHOLDER_KEY=AKIA_YOUR_API_KEY_PLACEHOLDER_1234
`
	if err := os.WriteFile(testFilePath, []byte(rawContent), 0600); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	scopeYAML := `
version: "1.0"
allowlist:
  repositories:
    - '` + filepath.ToSlash(tempDir) + `'
`
	sc, err := scope.Parse([]byte(scopeYAML))
	if err != nil {
		t.Fatalf("failed to parse scope: %v", err)
	}

	scanner := collector.NewSecretScanner(sc)
	target := model.Asset{
		ID:    uuid.New(),
		Type:  model.AssetTypeRepo,
		Value: tempDir,
	}

	findings, err := scanner.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error scanning secrets: %v", err)
	}

	foundTypes := make(map[string]int)
	for _, f := range findings {
		foundTypes[f.FindingType]++

		// CRITICAL SAFETY CHECK: Verify raw passwords and keys are NEVER stored unredacted
		if strings.Contains(f.RedactedPreview, "SuperSecretPassword123") {
			t.Errorf("CRITICAL VIOLATION: Raw password found in RedactedPreview: %s", f.RedactedPreview)
		}
		if f.FindingType == "exposed_aws_key" && f.RedactedPreview == "AKIAIOSFODNN7EXAMPLE12" {
			t.Errorf("CRITICAL VIOLATION: Full AWS key found unredacted in RedactedPreview")
		}
		if f.SecretHash == "" {
			t.Errorf("expected salted SecretHash to be populated for finding %s", f.Title)
		}
	}

	// Verify required detectors fired
	expectedFindings := []string{
		"exposed_aws_key",
		"exposed_github_token",
		"exposed_db_credential",
		"exposed_jwt_token",
		"exposed_private_key",
	}

	for _, exp := range expectedFindings {
		if foundTypes[exp] == 0 {
			t.Errorf("expected at least 1 finding of type %q, got 0", exp)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	// Low entropy strings
	lowEntropy := collector.ShannonEntropy("aaaaaaaaaaaaaaaaaaaa")
	if lowEntropy != 0.0 {
		t.Errorf("expected 0 entropy for identical chars, got %.2f", lowEntropy)
	}

	// High entropy random string
	highEntropy := collector.ShannonEntropy("8f7a9c3b1e2d4f6a8c0e2b4d6f8a0c2e")
	if highEntropy < 3.5 {
		t.Errorf("expected entropy > 3.5 for hex token, got %.2f", highEntropy)
	}
}

func TestLuhnCheck(t *testing.T) {
	// Valid Luhn test numbers
	if !collector.LuhnCheck("49927398716") {
		t.Errorf("expected valid Luhn check for 49927398716")
	}
	// Invalid Luhn number
	if collector.LuhnCheck("49927398717") {
		t.Errorf("expected invalid Luhn check for 49927398717")
	}
}
