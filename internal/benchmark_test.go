package internal_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/surfacewatch/surfacewatch/internal/collector"
	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/pipeline"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// BenchmarkTyposquatGenerator measures the throughput of the 7-class permutation engine.
func BenchmarkTyposquatGenerator(b *testing.B) {
	engine := collector.NewPermutationEngine()
	domain := "example-enterprise.com"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = engine.GenerateAll(domain)
	}
}

// BenchmarkFingerprinting measures collision-resistant fingerprint generation.
func BenchmarkFingerprinting(b *testing.B) {
	findingType := "exposed_aws_key"
	assetVal := "prod-api.example.com"
	evidenceKey := "config/production.env:42:AKIAIOSFODNN7EXAMPLE"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = pipeline.GenerateFingerprint(findingType, assetVal, evidenceKey)
	}
}

// BenchmarkSecretScanner measures file scanning across regular expressions and Shannon entropy.
func BenchmarkSecretScanner(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "bench_repo_*")
	if err != nil {
		b.Fatalf("failed to create bench dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testContent := `# Configuration test benchmark
AWS_KEY=AKIAIOSFODNN77777777
GITHUB_PAT=ghp_ABC123DEF456GHI789JKL012MNO345PQR678
DB=postgres://user:SuperSecretPassword123@db.prod.internal:5432/core
JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
NORMAL_LINE=This is a standard log line without any credentials or secrets.
ENTROPY=8f7a9c3b1e2d4f6a8c0e2b4d6f8a0c2e3f4a5b6c7d8e9f0a
`
	filePath := filepath.Join(tempDir, "sample.env")
	if err := os.WriteFile(filePath, []byte(testContent), 0600); err != nil {
		b.Fatalf("failed to write bench file: %v", err)
	}

	sc, _ := scope.Parse([]byte("allowlist:\n  repositories:\n    - '" + filepath.ToSlash(tempDir) + "'\n"))
	scanner := collector.NewSecretScanner(sc)
	target := model.Asset{
		ID:    uuid.New(),
		Type:  model.AssetTypeRepo,
		Value: tempDir,
	}

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = scanner.Collect(ctx, target)
	}
}
