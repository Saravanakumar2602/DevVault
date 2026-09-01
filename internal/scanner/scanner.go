package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultIgnoredPaths lists standard directory & file names skipped during secret scanning.
var DefaultIgnoredPaths = []string{
	".git",
	".devvault",
	"devvault.db",
	"node_modules",
	"vendor",
	"go.sum",
	"go.mod",
	"scanner.go",
	"scanner_test.go",
}

// Finding represents a single detected secret leak.
type Finding struct {
	FilePath    string
	LineNumber  int
	SecretType  string
	Severity    string
	RedactedVal string
}

// Rule defines a regex matching rule for secret scanner heuristics.
type Rule struct {
	Name       string
	Severity   string
	Regex      *regexp.Regexp
	RedactFunc func(match string) string
}

// Scanner performs secret leak inspection across files and git diffs.
type Scanner struct {
	rules []Rule
}

// NewScanner returns a Scanner populated with heuristic secret rules.
func NewScanner() *Scanner {
	return &Scanner{
		rules: []Rule{
			{
				Name:     "AWS Access Key ID",
				Severity: "HIGH",
				Regex:    regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
				RedactFunc: func(match string) string {
					if len(match) >= 4 {
						return match[:4] + "************"
					}
					return "************"
				},
			},
			{
				Name:     "AWS Secret Access Key",
				Severity: "HIGH",
				Regex:    regexp.MustCompile(`(?i)\b(aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
				RedactFunc: func(match string) string {
					return "AWS_SECRET_KEY=****************************************"
				},
			},
			{
				Name:     "GitHub Personal Access Token",
				Severity: "HIGH",
				Regex:    regexp.MustCompile(`\b(ghp_[A-Za-z0-9_]{36})\b`),
				RedactFunc: func(match string) string {
					if len(match) >= 8 {
						return match[:4] + "..." + match[len(match)-4:]
					}
					return "ghp_************"
				},
			},
			{
				Name:     "Generic Private Key",
				Severity: "HIGH",
				Regex:    regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
				RedactFunc: func(match string) string {
					return "-----BEGIN PRIVATE KEY----- [REDACTED]"
				},
			},
			{
				Name:     "JSON Web Token (JWT)",
				Severity: "HIGH",
				Regex:    regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`),
				RedactFunc: func(match string) string {
					if len(match) >= 6 {
						return match[:3] + "..." + match[len(match)-3:]
					}
					return "JWT_REDACTED"
				},
			},
			{
				Name:     "Configuration / Env Secret Assignment",
				Severity: "HIGH",
				Regex:    regexp.MustCompile(`(?i)\b(API_KEY|SECRET_KEY|DATABASE_URL|AUTH_TOKEN|PASSWORD|PRIVATE_KEY)\s*[:=]\s*["']?([^\s"'#]{8,})["']?`),
				RedactFunc: func(match string) string {
					parts := strings.SplitN(match, "=", 2)
					if len(parts) != 2 {
						parts = strings.SplitN(match, ":", 2)
					}
					if len(parts) == 2 {
						return strings.TrimSpace(parts[0]) + "=************"
					}
					return "SECRET=************"
				},
			},
		},
	}
}

// ShouldSkipPath determines whether a file or directory path should be excluded from scanning.
func ShouldSkipPath(path string) bool {
	clean := filepath.ToSlash(path)
	base := filepath.Base(clean)
	for _, ign := range DefaultIgnoredPaths {
		if base == ign || strings.Contains(clean, "/"+ign+"/") || strings.HasPrefix(clean, ign+"/") {
			return true
		}
	}
	return false
}

// IsBinaryContent inspects byte header to check for binary/null bytes.
func IsBinaryContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	limit := 512
	if len(data) < limit {
		limit = len(data)
	}
	return bytes.IndexByte(data[:limit], 0) != -1
}

// ScanText scans string text content for secret leaks.
func ScanText(filePath, content string) []Finding {
	s := NewScanner()
	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments and redacted preview strings
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.Contains(line, "****") {
			continue
		}

		// 1. Check Regex Rules
		for _, r := range s.rules {
			if match := r.Regex.FindString(line); match != "" {
				findings = append(findings, Finding{
					FilePath:    filePath,
					LineNumber:  lineNum,
					SecretType:  r.Name,
					Severity:    r.Severity,
					RedactedVal: r.RedactFunc(match),
				})
			}
		}

		// 2. Check Shannon Entropy (> 4.5 bits per char on single tokens)
		tokens := strings.Fields(line)
		for _, token := range tokens {
			cleanToken := strings.Trim(token, `"',;:()[]={}`)
			if len(cleanToken) >= 20 && calculateShannonEntropy(cleanToken) > 4.5 {
				// Avoid duplicate findings if already matched by regex rule
				alreadyMatched := false
				for _, f := range findings {
					if f.LineNumber == lineNum {
						alreadyMatched = true
						break
					}
				}
				if !alreadyMatched {
					preview := cleanToken[:4] + "..." + cleanToken[len(cleanToken)-4:]
					findings = append(findings, Finding{
						FilePath:    filePath,
						LineNumber:  lineNum,
						SecretType:  "Possible High Entropy Token (>4.5 bits)",
						Severity:    "MEDIUM",
						RedactedVal: preview,
					})
				}
			}
		}
	}

	return findings
}

// ScanFile scans a single file on disk for secrets.
func ScanFile(filePath string) ([]Finding, error) {
	if ShouldSkipPath(filePath) {
		return nil, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	if IsBinaryContent(data) {
		return nil, nil
	}

	return ScanText(filePath, string(data)), nil
}

// ScanDirectory recursively scans all files in a directory tree.
func ScanDirectory(dirPath string) ([]Finding, error) {
	var findings []Finding

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if ShouldSkipPath(path) {
				return filepath.SkipDir
			}
			return nil
		}

		if ShouldSkipPath(path) {
			return nil
		}

		fileFindings, err := ScanFile(path)
		if err == nil {
			findings = append(findings, fileFindings...)
		}
		return nil
	})

	return findings, err
}

// ScanStagedGitDiff runs git diff --staged to scan staged changes before committing.
func ScanStagedGitDiff() ([]Finding, error) {
	cmd := exec.Command("git", "diff", "--staged", "--name-only")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run git diff: %w", err)
	}

	files := strings.Split(strings.TrimSpace(string(out)), "\n")
	var allFindings []Finding

	for _, f := range files {
		f = strings.TrimSpace(f)
		if f == "" || ShouldSkipPath(f) {
			continue
		}
		findings, err := ScanFile(f)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// InstallPreCommitHook installs an idempotent Git pre-commit hook script.
func InstallPreCommitHook() error {
	gitDir := "."
	hooksDir := filepath.Join(gitDir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	hookScript := `#!/bin/sh
# DevVault Automated Pre-Commit Secret Scanner
# Generated automatically by devvault install-hook

if command -v devvault >/dev/null 2>&1; then
    DEVVAULT_BIN="devvault"
elif [ -f "./devvault.exe" ]; then
    DEVVAULT_BIN="./devvault.exe"
elif [ -f "./devvault" ]; then
    DEVVAULT_BIN="./devvault"
else
    DEVVAULT_BIN="go run ./cmd/devvault"
fi

echo "🔍 Running DevVault pre-commit secret scan..."
$DEVVAULT_BIN scan --staged
if [ $? -ne 0 ]; then
    echo "❌ Commit aborted: DevVault detected secret leak(s) in staged files."
    echo "💡 Fix or unstage sensitive files before committing."
    exit 1
fi
`

	if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
		return fmt.Errorf("failed to write pre-commit hook: %w", err)
	}

	return nil
}

func calculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * (math.Log2(p))
	}

	return entropy
}
