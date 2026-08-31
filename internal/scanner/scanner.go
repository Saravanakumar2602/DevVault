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

type Finding struct {
	Severity    string `json:"severity"` // HIGH, MEDIUM, LOW
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	SecretType  string `json:"secret_type"`
	RedactedVal string `json:"redacted_preview"`
}

type PatternRule struct {
	Name     string
	Severity string
	Pattern  *regexp.Regexp
}

var DefaultRules = []PatternRule{
	{
		Name:     "AWS Access Key ID",
		Severity: "HIGH",
		Pattern:  regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
	},
	{
		Name:     "AWS Secret Access Key",
		Severity: "HIGH",
		Pattern:  regexp.MustCompile(`(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`),
	},
	{
		Name:     "GitHub Personal Access Token",
		Severity: "HIGH",
		Pattern:  regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}`),
	},
	{
		Name:     "Generic Private Key",
		Severity: "HIGH",
		Pattern:  regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE)( PRIVATE)? KEY-----`),
	},
	{
		Name:     "JSON Web Token (JWT)",
		Severity: "HIGH",
		Pattern:  regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
	},
	{
		Name:     "Configuration / Env Secret Assignment",
		Severity: "HIGH",
		Pattern:  regexp.MustCompile(`(?i)(api_key|apikey|secret_key|app_secret|password|passwd|auth_token|jwt_secret|database_url|db_url|conn_str|secret)\s*[:=]\s*["']?([a-zA-Z0-9_/+=\-!@#$%^&*]{8,})["']?`),
	},
}

// CalculateEntropy computes Shannon entropy in bits per character for a given string.
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsBinaryContent checks if a byte slice contains binary/null byte data.
func IsBinaryContent(data []byte) bool {
	checkLen := len(data)
	if checkLen > 512 {
		checkLen = 512
	}
	return bytes.IndexByte(data[:checkLen], 0) != -1
}

// ShouldSkipPath checks if a file path should be ignored by the scanner.
func ShouldSkipPath(path string) bool {
	clean := filepath.ToSlash(path)

	// Ignore .git, .devvault, node_modules, vendor, devvault storage files
	ignoredSubstrings := []string{
		"/.git/", "/.devvault/", "/node_modules/", "/vendor/",
		"devvault.db", "devvault.exe", ".gitignore",
	}

	for _, ign := range ignoredSubstrings {
		if strings.Contains(clean, ign) || strings.HasPrefix(clean, strings.TrimPrefix(ign, "/")) {
			return true
		}
	}

	// Skip binary / archive extensions
	ignoredExts := []string{".exe", ".db", ".zip", ".tar", ".gz", ".png", ".jpg", ".jpeg", ".pdf", ".so", ".dll", ".dylib"}
	ext := strings.ToLower(filepath.Ext(clean))
	for _, ignExt := range ignoredExts {
		if ext == ignExt {
			return true
		}
	}

	return false
}

// RedactSecret returns a safe preview of a secret string without exposing full plaintext.
func RedactSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 6 {
		return "******"
	}
	if strings.HasPrefix(s, "AKIA") || strings.HasPrefix(s, "ASIA") {
		return s[:4] + "************"
	}
	if strings.HasPrefix(s, "ghp_") || strings.HasPrefix(s, "gho_") {
		return s[:4] + "..." + s[len(s)-4:]
	}
	return s[:3] + "..." + s[len(s)-3:]
}

// ScanText scans string text line-by-line and returns detected findings.
func ScanText(filePath string, text string) []Finding {
	if ShouldSkipPath(filePath) {
		return nil
	}

	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNum := 0

	isEnvFile := strings.HasSuffix(filePath, ".env") || strings.Contains(filePath, ".env.")

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Ignore comments and empty lines
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || len(trimmed) == 0 {
			continue
		}

		// 1. Pattern Matching
		for _, rule := range DefaultRules {
			if rule.Pattern.MatchString(line) {
				match := rule.Pattern.FindString(line)
				sev := rule.Severity
				if isEnvFile {
					sev = "HIGH"
				}

				findings = append(findings, Finding{
					Severity:    sev,
					FilePath:    filePath,
					LineNumber:  lineNum,
					SecretType:  rule.Name,
					RedactedVal: RedactSecret(match),
				})
			}
		}

		// 2. High-Entropy Tokens (Shannon Entropy > 4.5 bits/char)
		words := strings.Fields(line)
		for _, word := range words {
			cleanWord := strings.Trim(word, `"',:;=(){}[]<>`)
			// Filter out common false positives (e.g. URLs, standard identifiers)
			if strings.HasPrefix(cleanWord, "http://") || strings.HasPrefix(cleanWord, "https://") {
				continue
			}

			if len(cleanWord) >= 24 && CalculateEntropy(cleanWord) >= 4.5 {
				alreadyFound := false
				for _, f := range findings {
					if f.LineNumber == lineNum {
						alreadyFound = true
						break
					}
				}
				if !alreadyFound {
					findings = append(findings, Finding{
						Severity:    "MEDIUM",
						FilePath:    filePath,
						LineNumber:  lineNum,
						SecretType:  "High Entropy Token (>4.5 bits)",
						RedactedVal: RedactSecret(cleanWord),
					})
				}
			}
		}
	}

	return findings
}

// ScanFile inspects a single file on disk.
func ScanFile(filePath string) ([]Finding, error) {
	if ShouldSkipPath(filePath) {
		return nil, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file '%s': %w", filePath, err)
	}

	if IsBinaryContent(data) {
		return nil, nil
	}

	return ScanText(filePath, string(data)), nil
}

// ScanDirectory recursively scans all files in a directory tree.
func ScanDirectory(dirPath string) ([]Finding, error) {
	var allFindings []Finding

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

		findings, err := ScanFile(path)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}
		return nil
	})

	return allFindings, err
}

// ScanStagedGitDiff scans staged Git diffs via 'git diff --staged -U0'.
func ScanStagedGitDiff() ([]Finding, error) {
	cmd := exec.Command("git", "diff", "--staged", "-U0")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run git diff (ensure current directory is a git repository): %w", err)
	}

	var findings []Finding
	var currentFile string
	lineNum := 0

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			lineNum = 0
			continue
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			lineNum++
			addedLine := strings.TrimPrefix(line, "+")
			if ShouldSkipPath(currentFile) {
				continue
			}
			lineFindings := ScanText(currentFile, addedLine)
			for i := range lineFindings {
				lineFindings[i].LineNumber = lineNum
			}
			findings = append(findings, lineFindings...)
		}
	}

	return findings, nil
}

// InstallPreCommitHook installs a safe and idempotent pre-commit hook into .git/hooks/pre-commit.
func InstallPreCommitHook() error {
	gitHooksDir := filepath.Join(".git", "hooks")
	if _, err := os.Stat(gitHooksDir); os.IsNotExist(err) {
		return fmt.Errorf("current directory is not a Git repository root (.git/hooks directory not found)")
	}

	hookPath := filepath.Join(gitHooksDir, "pre-commit")

	hookMarker := "# DevVault pre-commit secret scanner"
	hookScript := fmt.Sprintf(`#!/bin/sh
%s
devvault scan --staged
if [ $? -ne 0 ]; then
    echo "❌ [DevVault] Secret scanner blocked commit: Potential secret leaks detected!"
    exit 1
fi
`, hookMarker)

	if existingData, err := os.ReadFile(hookPath); err == nil {
		if strings.Contains(string(existingData), hookMarker) {
			return nil
		}
	}

	err := os.WriteFile(hookPath, []byte(hookScript), 0755)
	if err != nil {
		return fmt.Errorf("failed to write git pre-commit hook: %w", err)
	}

	return nil
}
