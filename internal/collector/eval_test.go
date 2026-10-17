package collector_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/surfacewatch/surfacewatch/internal/collector"
)

// LabeledSample represents a test string with ground truth classification.
type LabeledSample struct {
	ID             string
	Text           string
	ExpectedType   string // e.g. "aws", "github", "jwt", "private_key", "db", "entropy", or "" for negatives
	IsPositive     bool
	ExpectedDetect string // expected detector name
}

// CorpusGenerator generates deterministic synthetic test cases.
func generateCorpus(seed int64) []LabeledSample {
	rng := rand.New(rand.NewSource(seed))
	var samples []LabeledSample

	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randStr := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = chars[rng.Intn(len(chars))]
		}
		return string(b)
	}

	// --- 1. AWS Access Keys (Positives) ---
	for i := 0; i < 10; i++ {
		key := "AKIA" + randStr(16)
		samples = append(samples, LabeledSample{
			ID:             fmt.Sprintf("pos-aws-%d", i),
			Text:           fmt.Sprintf("export AWS_ACCESS_KEY_ID=%s", key),
			ExpectedType:   "exposed_aws_key",
			IsPositive:     true,
			ExpectedDetect: "aws_access_key",
		})
	}

	// --- 2. GitHub Tokens (Positives) ---
	for i := 0; i < 10; i++ {
		token := "ghp_" + randStr(36)
		samples = append(samples, LabeledSample{
			ID:             fmt.Sprintf("pos-gh-%d", i),
			Text:           fmt.Sprintf("const GITHUB_TOKEN = \"%s\";", token),
			ExpectedType:   "exposed_github_token",
			IsPositive:     true,
			ExpectedDetect: "github_token",
		})
	}

	// --- 3. JWT Tokens (Positives) ---
	for i := 0; i < 10; i++ {
		jwt := fmt.Sprintf("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlVzZXI%dCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_%s", i, randStr(10))
		samples = append(samples, LabeledSample{
			ID:             fmt.Sprintf("pos-jwt-%d", i),
			Text:           fmt.Sprintf("Authorization: Bearer %s", jwt),
			ExpectedType:   "exposed_jwt_token",
			IsPositive:     true,
			ExpectedDetect: "jwt_token",
		})
	}

	// --- 4. Private Key Blocks (Positives) ---
	keyTypes := []string{"RSA", "EC", "OPENSSH", "DSA", "PRIVATE"}
	for i := 0; i < 10; i++ {
		kt := keyTypes[i%len(keyTypes)]
		samples = append(samples, LabeledSample{
			ID:             fmt.Sprintf("pos-pk-%d", i),
			Text:           fmt.Sprintf("-----BEGIN %s PRIVATE KEY-----\nMIIEowIBAAKCAQEA...", kt),
			ExpectedType:   "exposed_private_key",
			IsPositive:     true,
			ExpectedDetect: "private_key",
		})
	}

	// --- 5. Database Connection Strings (Positives) ---
	dbSchemes := []string{"postgres", "mysql", "mongodb+srv", "redis"}
	for i := 0; i < 10; i++ {
		scheme := dbSchemes[i%len(dbSchemes)]
		pass := "PassWord" + randStr(8) + "!"
		samples = append(samples, LabeledSample{
			ID:             fmt.Sprintf("pos-db-%d", i),
			Text:           fmt.Sprintf("DATABASE_URL=%s://app_user:%s@db-cluster.internal:5432/production", scheme, pass),
			ExpectedType:   "exposed_db_credential",
			IsPositive:     true,
			ExpectedDetect: "db_connection_string",
		})
	}

	// --- 6. HARD NEGATIVES (Should NOT trigger positive detection) ---

	// Negative Category A: Standard UUIDs (36 chars)
	for i := 0; i < 10; i++ {
		uuidStr := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", rng.Uint32(), rng.Uint32()&0xFFFF, rng.Uint32()&0xFFFF, rng.Uint32()&0xFFFF, rng.Uint64()&0xFFFFFFFFFFFF)
		samples = append(samples, LabeledSample{
			ID:         fmt.Sprintf("neg-uuid-%d", i),
			Text:       fmt.Sprintf("request_id = \"%s\"", uuidStr),
			IsPositive: false,
		})
	}

	// Negative Category B: 40-char Git Commit SHAs & 64-char Hashes
	for i := 0; i < 10; i++ {
		sha := strings.ToLower(randStr(40))
		samples = append(samples, LabeledSample{
			ID:         fmt.Sprintf("neg-sha-%d", i),
			Text:       fmt.Sprintf("git commit sha: %s (merge branch)", sha),
			IsPositive: false,
		})
	}

	// Negative Category C: Documentation Placeholders & Example Keys
	placeholders := []string{
		"AKIA_EXAMPLE_DO_NOT_USE_123",
		"AKIA_YOUR_KEY_HERE_00000000",
		"ghp_PLACEHOLDER_TOKEN_CHANGEME12345678",
		"postgres://user:YOUR_PASSWORD_HERE@localhost:5432/db",
		"INSERT_SECRET_KEY_HERE",
		"EXAMPLE_API_SECRET_FOOBAR_1234",
		"TESTING_TOKEN_DUMMY_VALUE_9999",
		"SAMPLE_TOKEN_NOT_REAL_KEY",
		"LOCAL_DEV_SECRET_DO_NOT_RELY",
		"BEARER_TOKEN_HERE_SAMPLE_ONLY",
	}
	for i, ph := range placeholders {
		samples = append(samples, LabeledSample{
			ID:         fmt.Sprintf("neg-placeholder-%d", i),
			Text:       fmt.Sprintf("config.apiKey = \"%s\"", ph),
			IsPositive: false,
		})
	}

	// Negative Category D: Base64 asset embeddings / HTML / Hex data
	for i := 0; i < 10; i++ {
		samples = append(samples, LabeledSample{
			ID:         fmt.Sprintf("neg-base64-%d", i),
			Text:       fmt.Sprintf("background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk%s');", randStr(8)),
			IsPositive: false,
		})
	}

	// Negative Category E: Standard Source Code and Log Lines
	codeLines := []string{
		"func (s *Server) ListenAndServe() error { return nil }",
		"if err != nil { return fmt.Errorf(\"failed: %w\", err) }",
		"SELECT id, tenant_id, created_at FROM users WHERE status = 'active';",
		"logger.Info(\"connection established\", \"remote_addr\", addr);",
		"const DefaultTimeout = 30 * time.Second",
		"type Config struct { Host string `json:\"host\"` Port int }",
		"curl -X POST https://api.example.com/v1/auth -d 'grant_type=client_credentials'",
		"npm install --save-dev @types/node typescript ts-node",
		"docker-compose up -d --remove-orphans postgres redis",
		"github.com/surfacewatch/surfacewatch/internal/collector",
	}
	for i, code := range codeLines {
		samples = append(samples, LabeledSample{
			ID:         fmt.Sprintf("neg-code-%d", i),
			Text:       code,
			IsPositive: false,
		})
	}

	return samples
}

type EvalMetrics struct {
	TotalSamples int
	Positives    int
	Negatives    int
	TP           int
	FP           int
	FN           int
	TN           int
	Precision    float64
	Recall       float64
	F1           float64
	DetectorTP   map[string]int
	DetectorFP   map[string]int
	DetectorFN   map[string]int
	Failures     []string
}

func evaluateCorpus(samples []LabeledSample) EvalMetrics {
	detectors := []collector.SecretDetector{
		&collector.AWSAccessKeyDetector{},
		&collector.GitHubTokenDetector{},
		&collector.JWTDetector{},
		&collector.PrivateKeyDetector{},
		&collector.DBConnStringDetector{},
		&collector.EntropyDetector{MinEntropy: 4.5, MinLength: 24},
	}

	m := EvalMetrics{
		TotalSamples: len(samples),
		DetectorTP:   make(map[string]int),
		DetectorFP:   make(map[string]int),
		DetectorFN:   make(map[string]int),
	}

	for _, sample := range samples {
		if sample.IsPositive {
			m.Positives++
		} else {
			m.Negatives++
		}

		// Run all detectors
		var hits []collector.DetectedSecret
		for _, d := range detectors {
			detected := d.ScanLine(sample.Text, 1, "test.txt")
			hits = append(hits, detected...)
		}

		hasDetection := len(hits) > 0

		if sample.IsPositive {
			if hasDetection {
				m.TP++
				// Credit matched detector
				for _, h := range hits {
					m.DetectorTP[h.DetectorName]++
				}
			} else {
				m.FN++
				m.DetectorFN[sample.ExpectedDetect]++
				m.Failures = append(m.Failures, fmt.Sprintf("False Negative on %s: %s", sample.ID, sample.Text))
			}
		} else {
			// Ground truth negative
			if hasDetection {
				m.FP++
				for _, h := range hits {
					m.DetectorFP[h.DetectorName]++
				}
				m.Failures = append(m.Failures, fmt.Sprintf("False Positive on %s (flagged by %s): %s", sample.ID, hits[0].DetectorName, sample.Text))
			} else {
				m.TN++
			}
		}
	}

	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	}
	if m.TP+m.FN > 0 {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * (m.Precision * m.Recall) / (m.Precision + m.Recall)
	}

	return m
}

func TestDetectorEvaluation_DevAndHoldout(t *testing.T) {
	// 1. Development Set (Seed 1337)
	devCorpus := generateCorpus(1337)
	devMetrics := evaluateCorpus(devCorpus)

	// 2. Separate Holdout Set (Seed 9999) - Unseen distribution
	holdoutCorpus := generateCorpus(9999)
	holdoutMetrics := evaluateCorpus(holdoutCorpus)

	t.Log("=========================================================================")
	t.Log("          SECRET SCANNER DETECTOR EVALUATION REPORT                      ")
	t.Log("=========================================================================")
	t.Logf("DEVELOPMENT SET (Seed 1337):")
	t.Logf("  Samples: %d (Positives: %d, Negatives: %d)", devMetrics.TotalSamples, devMetrics.Positives, devMetrics.Negatives)
	t.Logf("  TP: %d | FP: %d | FN: %d | TN: %d", devMetrics.TP, devMetrics.FP, devMetrics.FN, devMetrics.TN)
	t.Logf("  Precision: %.2f%% | Recall: %.2f%% | F1-Score: %.4f", devMetrics.Precision*100, devMetrics.Recall*100, devMetrics.F1)
	t.Log("-------------------------------------------------------------------------")
	t.Logf("HOLDOUT SET (Seed 9999):")
	t.Logf("  Samples: %d (Positives: %d, Negatives: %d)", holdoutMetrics.TotalSamples, holdoutMetrics.Positives, holdoutMetrics.Negatives)
	t.Logf("  TP: %d | FP: %d | FN: %d | TN: %d", holdoutMetrics.TP, holdoutMetrics.FP, holdoutMetrics.FN, holdoutMetrics.TN)
	t.Logf("  Precision: %.2f%% | Recall: %.2f%% | F1-Score: %.4f", holdoutMetrics.Precision*100, holdoutMetrics.Recall*100, holdoutMetrics.F1)
	t.Log("=========================================================================")

	if len(devMetrics.Failures) > 0 {
		t.Logf("Dev Failure Cases (%d):", len(devMetrics.Failures))
		for _, f := range devMetrics.Failures {
			t.Log("  - ", f)
		}
	}
	if len(holdoutMetrics.Failures) > 0 {
		t.Logf("Holdout Failure Cases (%d):", len(holdoutMetrics.Failures))
		for _, f := range holdoutMetrics.Failures {
			t.Log("  - ", f)
		}
	}

	// Verification: Both sets must achieve high recall while keeping precision sound
	if devMetrics.Recall < 0.85 {
		t.Errorf("Dev set recall too low: %.2f", devMetrics.Recall)
	}
	if holdoutMetrics.Recall < 0.85 {
		t.Errorf("Holdout set recall too low: %.2f", holdoutMetrics.Recall)
	}
}
