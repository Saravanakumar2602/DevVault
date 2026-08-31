package scanner

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	FilePath   string `json:"file_path"`
	LineNumber int    `json:"line_number"`
	Rule       string `json:"rule"`
	Match      string `json:"match"`
}

type PatternRule struct {
	Name    string
	Pattern *regexp.Regexp
}

var DefaultRules = []PatternRule{
	{
		Name:    "AWS Access Key ID",
		Pattern: regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
	},
	{
		Name:    "AWS Secret Access Key",
		Pattern: regexp.MustCompile(`(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`),
	},
	{
		Name:    "GitHub Personal Access Token",
		Pattern: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	},
	{
		Name:    "GitHub OAuth Access Token",
		Pattern: regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
	},
	{
		Name:    "Generic Private Key",
		Pattern: regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----`),
	},
	{
		Name:    "JSON Web Token (JWT)",
		Pattern: regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
	},
	{
		Name:    "Generic High-Entropy API Key / Password Assignment",
		Pattern: regexp.MustCompile(`(?i)(api_key|apikey|secret|password|passwd|auth_token)\s*[:=]\s*["']([^"'\s]{8,})["']`),
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

// ScanText scans raw string content line by line and returns detected secrets findings.
func ScanText(filePath string, text string) []Finding {
	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 1. Pattern matching
		for _, rule := range DefaultRules {
			if rule.Pattern.MatchString(line) {
				match := rule.Pattern.FindString(line)
				findings = append(findings, Finding{
					FilePath:   filePath,
					LineNumber: lineNum,
					Rule:       rule.Name,
					Match:      maskSecret(match),
				})
			}
		}

		// 2. Entropy analysis on long random words
		words := strings.Fields(line)
		for _, word := range words {
			cleanWord := strings.Trim(word, `"',:;=(){}[]`)
			if len(cleanWord) >= 20 && CalculateEntropy(cleanWord) >= 4.5 {
				// Avoid duplicate findings if already caught by pattern
				alreadyFound := false
				for _, f := range findings {
					if f.LineNumber == lineNum {
						alreadyFound = true
						break
					}
				}
				if !alreadyFound {
					findings = append(findings, Finding{
						FilePath:   filePath,
						LineNumber: lineNum,
						Rule:       "High Entropy Token (>4.5 bits)",
						Match:      maskSecret(cleanWord),
					})
				}
			}
		}
	}

	return findings
}

// ScanStagedGitDiff scans git staged changes using 'git diff --staged'.
func ScanStagedGitDiff() ([]Finding, error) {
	cmd := exec.Command("git", "diff", "--staged", "-U0")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run git diff: %w", err)
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
			lineFindings := ScanText(currentFile, addedLine)
			for i := range lineFindings {
				lineFindings[i].LineNumber = lineNum
			}
			findings = append(findings, lineFindings...)
		}
	}

	return findings, nil
}

// InstallPreCommitHook installs a git pre-commit hook into the current git repository.
func InstallPreCommitHook() error {
	gitDir := filepath.Join(".git", "hooks")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("current directory is not a git repository root (.git/hooks directory not found)")
	}

	hookPath := filepath.Join(gitDir, "pre-commit")
	hookContent := `#!/bin/sh
# DevVault automated pre-commit secret scanner
devvault scan --staged
if [ $? -ne 0 ]; then
    echo "❌ [DevVault] Secret scanner blocked commit: Potential secrets detected!"
    exit 1
fi
`

	err := os.WriteFile(hookPath, []byte(hookContent), 0755)
	if err != nil {
		return fmt.Errorf("failed to write git pre-commit hook: %w", err)
	}

	return nil
}

func maskSecret(s string) string {
	if len(s) <= 6 {
		return "******"
	}
	return s[:3] + "..." + s[len(s)-3:]
}
