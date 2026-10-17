// Package collector provides exposed-secret detection for authorized local repositories and directories.
// NON-NEGOTIABLE SAFETY RULE: SurfaceWatch NEVER stores raw secrets.
// Detectors compute a cryptographically salted SHA-256 hash and a safe redacted preview only.
package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/surfacewatch/surfacewatch/internal/model"
	"github.com/surfacewatch/surfacewatch/internal/scope"
)

// SecretDetector is an individual pattern or heuristic rule for discovering credentials.
type SecretDetector interface {
	Name() string
	ScanLine(line string, lineNum int, filePath string) []DetectedSecret
}

// DetectedSecret holds match metadata before wrapping into RawFinding.
type DetectedSecret struct {
	DetectorName    string
	FindingType     string
	Severity        model.Severity
	Title           string
	Description     string
	LineNum         int
	FilePath        string
	RedactedPreview string
	SecretHash      string
}

// Compile regular expressions for known credential formats.
var (
	// AWS Access Key ID (standard 20 chars starting with AKIA)
	reAWSAccessKey = regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)

	// GitHub Personal Access Token (classic ghp_... or fine-grained github_pat_...)
	reGitHubClassicPat     = regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36})\b`)
	reGitHubFineGrainedPat = regexp.MustCompile(`\b(github_pat_[a-zA-Z0-9_]{82})\b`)

	// JSON Web Token (header.payload.signature)
	reJWT = regexp.MustCompile(`\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b`)

	// PEM Private Key Headers (e.g., -----BEGIN RSA PRIVATE KEY----- or -----BEGIN PRIVATE KEY-----)
	rePrivateKey = regexp.MustCompile(`-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)\s+)?(?:PRIVATE\s+)?KEY-----`)

	// Database Connection Strings with embedded credentials
	reDBConnString = regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/(?:[a-zA-Z0-9_.-]+):([^@\s\/]+)@`)

	// Candidate high entropy tokens (base64 or hex-like strings >= 20 chars)
	reEntropyCandidate = regexp.MustCompile(`[a-zA-Z0-9+/=_-]{24,}`)
)

// Common placeholder tokens to suppress false positives in entropy detector.
var allowlistedPlaceholders = []string{
	"EXAMPLE", "PLACEHOLDER", "CHANGEME", "TESTING", "DUMMYKEY",
	"YOUR_API_KEY", "INSERT_KEY_HERE", "SECRET_KEY_HERE", "FOOBAR",
	"1234567890", "ABCDEF123456", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID",
	"SAMPLE_TOKEN", "LOCAL_DEV_SECRET", "BEARER_TOKEN_HERE",
}

// ShannonEntropy calculates the information entropy of a string (in bits per symbol).
// High entropy (> 4.5) indicates cryptographic randomness (e.g. API keys, secrets).
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// LuhnCheck validates credit card numbers and checksummed identifier tokens.
func LuhnCheck(number string) bool {
	// Strip non-digits
	var digits []int
	for _, r := range number {
		if unicode.IsDigit(r) {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 2 {
		return false
	}
	sum := 0
	alternate := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := digits[i]
		if alternate {
			n *= 2
			if n > 9 {
				n = (n % 10) + 1
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

// AWSAccessKeyDetector finds exposed AWS credentials.
type AWSAccessKeyDetector struct{}

func (d *AWSAccessKeyDetector) Name() string { return "aws_access_key" }
func (d *AWSAccessKeyDetector) ScanLine(line string, lineNum int, filePath string) []DetectedSecret {
	var out []DetectedSecret
	matches := reAWSAccessKey.FindAllString(line, -1)
	for _, m := range matches {
		if isPlaceholder(m) {
			continue
		}
		out = append(out, DetectedSecret{
			DetectorName:    d.Name(),
			FindingType:     "exposed_aws_key",
			Severity:        model.SeverityCritical,
			Title:           "Exposed AWS Access Key ID",
			Description:     fmt.Sprintf("AWS Access Key ID discovered in %s:%d. Immediate revocation advised.", filepath.Base(filePath), lineNum),
			LineNum:         lineNum,
			FilePath:        filePath,
			RedactedPreview: RedactSecret(m),
			SecretHash:      HashSecret(m),
		})
	}
	return out
}

// GitHubTokenDetector finds exposed GitHub tokens.
type GitHubTokenDetector struct{}

func (d *GitHubTokenDetector) Name() string { return "github_token" }
func (d *GitHubTokenDetector) ScanLine(line string, lineNum int, filePath string) []DetectedSecret {
	var out []DetectedSecret
	for _, m := range reGitHubClassicPat.FindAllString(line, -1) {
		if isPlaceholder(m) {
			continue
		}
		out = append(out, DetectedSecret{
			DetectorName:    d.Name(),
			FindingType:     "exposed_github_token",
			Severity:        model.SeverityCritical,
			Title:           "Exposed GitHub Personal Access Token",
			Description:     fmt.Sprintf("Classic GitHub PAT detected in %s:%d", filepath.Base(filePath), lineNum),
			LineNum:         lineNum,
			FilePath:        filePath,
			RedactedPreview: RedactSecret(m),
			SecretHash:      HashSecret(m),
		})
	}
	for _, m := range reGitHubFineGrainedPat.FindAllString(line, -1) {
		if isPlaceholder(m) {
			continue
		}
		out = append(out, DetectedSecret{
			DetectorName:    d.Name(),
			FindingType:     "exposed_github_token",
			Severity:        model.SeverityCritical,
			Title:           "Exposed GitHub Fine-Grained Access Token",
			Description:     fmt.Sprintf("Fine-grained GitHub token detected in %s:%d", filepath.Base(filePath), lineNum),
			LineNum:         lineNum,
			FilePath:        filePath,
			RedactedPreview: RedactSecret(m),
			SecretHash:      HashSecret(m),
		})
	}
	return out
}

// JWTDetector finds exposed JSON Web Tokens.
type JWTDetector struct{}

func (d *JWTDetector) Name() string { return "jwt_token" }
func (d *JWTDetector) ScanLine(line string, lineNum int, filePath string) []DetectedSecret {
	var out []DetectedSecret
	matches := reJWT.FindAllString(line, -1)
	for _, m := range matches {
		if isPlaceholder(m) {
			continue
		}
		out = append(out, DetectedSecret{
			DetectorName:    d.Name(),
			FindingType:     "exposed_jwt_token",
			Severity:        model.SeverityHigh,
			Title:           "Exposed JSON Web Token (JWT)",
			Description:     fmt.Sprintf("JWT detected in %s:%d. Exposes potential session tokens or signing claims.", filepath.Base(filePath), lineNum),
			LineNum:         lineNum,
			FilePath:        filePath,
			RedactedPreview: RedactSecret(m),
			SecretHash:      HashSecret(m),
		})
	}
	return out
}

// PrivateKeyDetector identifies embedded cryptographic private keys.
type PrivateKeyDetector struct{}

func (d *PrivateKeyDetector) Name() string { return "private_key" }
func (d *PrivateKeyDetector) ScanLine(line string, lineNum int, filePath string) []DetectedSecret {
	var out []DetectedSecret
	if rePrivateKey.MatchString(line) {
		matchStr := rePrivateKey.FindString(line)
		out = append(out, DetectedSecret{
			DetectorName:    d.Name(),
			FindingType:     "exposed_private_key",
			Severity:        model.SeverityCritical,
			Title:           "Exposed Cryptographic Private Key Header",
			Description:     fmt.Sprintf("Private key block header found in %s:%d. Asymmetric key must be rotated.", filepath.Base(filePath), lineNum),
			LineNum:         lineNum,
			FilePath:        filePath,
			RedactedPreview: matchStr,
			SecretHash:      HashSecret(matchStr + filePath + strconv.Itoa(lineNum)),
		})
	}
	return out
}

// DBConnStringDetector identifies database URIs containing embedded passwords.
type DBConnStringDetector struct{}

func (d *DBConnStringDetector) Name() string { return "db_connection_string" }
func (d *DBConnStringDetector) ScanLine(line string, lineNum int, filePath string) []DetectedSecret {
	var out []DetectedSecret
	matches := reDBConnString.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) >= 2 {
			pass := m[1]
			if isPlaceholder(pass) || pass == "" {
				continue
			}
			fullMatch := m[0]
			out = append(out, DetectedSecret{
				DetectorName:    d.Name(),
				FindingType:     "exposed_db_credential",
				Severity:        model.SeverityHigh,
				Title:           "Database Connection String with Embedded Password",
				Description:     fmt.Sprintf("Connection string containing plaintext credentials in %s:%d", filepath.Base(filePath), lineNum),
				LineNum:         lineNum,
				FilePath:        filePath,
				RedactedPreview: RedactSecret(fullMatch),
				SecretHash:      HashSecret(pass),
			})
		}
	}
	return out
}

// EntropyDetector flags high Shannon entropy strings likely to be unknown API secrets.
type EntropyDetector struct {
	MinEntropy float64
	MinLength  int
}

func (d *EntropyDetector) Name() string { return "high_entropy_secret" }
func (d *EntropyDetector) ScanLine(line string, lineNum int, filePath string) []DetectedSecret {
	var out []DetectedSecret
	candidates := reEntropyCandidate.FindAllString(line, -1)
	for _, cand := range candidates {
		if len(cand) < d.MinLength {
			continue
		}
		if isPlaceholder(cand) {
			continue
		}
		// Skip UUIDs and Git SHAs
		if isUUIDorHexSHA(cand) {
			continue
		}
		e := ShannonEntropy(cand)
		if e >= d.MinEntropy {
			out = append(out, DetectedSecret{
				DetectorName:    d.Name(),
				FindingType:     "high_entropy_secret",
				Severity:        model.SeverityMedium,
				Title:           fmt.Sprintf("High-Entropy Secret Detected (Entropy: %.2f)", e),
				Description:     fmt.Sprintf("High randomness string (entropy %.2f bits) in %s:%d resembles an unclassified credential.", e, filepath.Base(filePath), lineNum),
				LineNum:         lineNum,
				FilePath:        filePath,
				RedactedPreview: RedactSecret(cand),
				SecretHash:      HashSecret(cand),
			})
		}
	}
	return out
}

func isPlaceholder(s string) bool {
	upper := strings.ToUpper(s)
	for _, ph := range allowlistedPlaceholders {
		if strings.Contains(upper, ph) {
			return true
		}
	}
	return false
}

func isUUIDorHexSHA(s string) bool {
	// 32 or 40 or 64 char pure hex (Git commit SHA or md5 or sha256)
	if (len(s) == 32 || len(s) == 40 || len(s) == 64) && isHex(s) {
		return true
	}
	// UUID standard pattern 8-4-4-4-12
	if len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' {
		return true
	}
	return false
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// SecretScanner walks authorized directory paths and evaluates all detectors.
type SecretScanner struct {
	detectors []SecretDetector
	scope     *scope.Scope
}

// NewSecretScanner instantiates the full detector suite.
func NewSecretScanner(sc *scope.Scope) *SecretScanner {
	return &SecretScanner{
		detectors: []SecretDetector{
			&AWSAccessKeyDetector{},
			&GitHubTokenDetector{},
			&JWTDetector{},
			&PrivateKeyDetector{},
			&DBConnStringDetector{},
			&EntropyDetector{MinEntropy: 4.5, MinLength: 24},
		},
		scope: sc,
	}
}

func (s *SecretScanner) Name() string {
	return "secret_scanner"
}

// Binary / large extensions to skip for performance and safety.
var skippedExtensions = map[string]struct{}{
	".exe": {}, ".dll": {}, ".bin": {}, ".png": {}, ".jpg": {}, ".jpeg": {},
	".gif": {}, ".pdf": {}, ".zip": {}, ".tar": {}, ".gz": {}, ".7z": {},
	".mp4": {}, ".mov": {}, ".woff": {}, ".woff2": {}, ".ttf": {},
}

func (s *SecretScanner) Collect(ctx context.Context, target model.Asset) ([]RawFinding, error) {
	if err := GuardScope(s.scope, target); err != nil {
		return nil, err
	}

	rootDir := filepath.Clean(target.Value)
	info, err := os.Stat(rootDir)
	if err != nil {
		return nil, fmt.Errorf("cannot access target repository %q: %w", rootDir, err)
	}

	var findings []RawFinding

	if !info.IsDir() {
		// Single file target
		return s.scanFile(ctx, target, rootDir)
	}

	err = filepath.Walk(rootDir, func(path string, fInfo os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable files gracefully
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Skip hidden directories like .git or vendor
		if fInfo.IsDir() {
			base := fInfo.Name()
			if strings.HasPrefix(base, ".") || base == "node_modules" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip binary extensions and files larger than 5MB
		ext := strings.ToLower(filepath.Ext(path))
		if _, skip := skippedExtensions[ext]; skip || fInfo.Size() > 5*1024*1024 {
			return nil
		}

		fileFindings, _ := s.scanFile(ctx, target, path)
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

func (s *SecretScanner) scanFile(ctx context.Context, target model.Asset, path string) ([]RawFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []RawFinding
	scanner := bufio.NewScanner(io.LimitReader(file, 5*1024*1024))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		line := scanner.Text()

		for _, detector := range s.detectors {
			secrets := detector.ScanLine(line, lineNum, path)
			for _, sec := range secrets {
				findings = append(findings, RawFinding{
					TargetAsset:     target,
					FindingType:     sec.FindingType,
					Severity:        sec.Severity,
					Title:           sec.Title,
					Description:     sec.Description,
					EvidenceKey:     fmt.Sprintf("%s:%d:%s", sec.FilePath, sec.LineNum, sec.SecretHash[:12]),
					RedactedPreview: sec.RedactedPreview,
					SecretHash:      sec.SecretHash,
					Evidence: map[string]any{
						"file_path":        sec.FilePath,
						"line_number":      sec.LineNum,
						"detector":         sec.DetectorName,
						"redacted_preview": sec.RedactedPreview,
						"secret_hash":      sec.SecretHash,
					},
				})
			}
		}
	}

	return findings, scanner.Err()
}
