package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"devvault/internal/scanner"
)

func TestFalseNegativesDetection(t *testing.T) {
	testCases := []struct {
		name         string
		content      string
		filePath     string
		expectedRule string
		expectedSev  string
	}{
		{
			name:         "AWS Access Key ID",
			content:      "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
			filePath:     "deploy.env",
			expectedRule: "AWS Access Key ID",
			expectedSev:  "HIGH",
		},
		{
			name:         "GitHub Token",
			content:      "token := \"ghp_123456789012345678901234567890123456\"",
			filePath:     "auth.go",
			expectedRule: "GitHub Personal Access Token",
			expectedSev:  "HIGH",
		},
		{
			name:         "Private Key Header",
			content:      "-----BEGIN RSA PRIVATE KEY-----",
			filePath:     "id_rsa",
			expectedRule: "Generic Private Key",
			expectedSev:  "HIGH",
		},
		{
			name:         "JWT Token",
			content:      "const jwt = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"",
			filePath:     "service.js",
			expectedRule: "JSON Web Token (JWT)",
			expectedSev:  "HIGH",
		},
		{
			name:         "Env Secret Assignment",
			content:      "DATABASE_URL=postgres://admin:SuperSecretPass123!@localhost:5432/mydb",
			filePath:     ".env",
			expectedRule: "Configuration / Env Secret Assignment",
			expectedSev:  "HIGH",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanner.ScanText(tc.filePath, tc.content)
			if len(findings) == 0 {
				t.Fatalf("expected finding for %s, got none", tc.name)
			}

			foundRule := false
			for _, f := range findings {
				if f.SecretType == tc.expectedRule {
					foundRule = true
					if f.Severity != tc.expectedSev {
						t.Errorf("expected severity %s, got %s", tc.expectedSev, f.Severity)
					}
					// Verify secret preview is safely redacted
					if strings.Contains(f.RedactedVal, "SuperSecretPass123!") || strings.Contains(f.RedactedVal, "AKIAIOSFODNN7EXAMPLE") {
						t.Errorf("SECURITY RISK: Redacted preview leaked plaintext secret!")
					}
				}
			}

			if !foundRule {
				t.Errorf("expected finding rule '%s', got findings: %+v", tc.expectedRule, findings)
			}
		})
	}
}

func TestFalsePositivesFiltering(t *testing.T) {
	falsePositives := []struct {
		name     string
		content  string
		filePath string
	}{
		{
			name:     "Commented Code",
			content:  "# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			filePath: "config.py",
		},
		{
			name:     "Standard Code Comment",
			content:  "// AWS keys start with AKIA",
			filePath: "main.go",
		},
		{
			name:     "Standard HTTP URL",
			content:  "const url = \"https://api.github.com/users/octocat/repos\"",
			filePath: "client.js",
		},
		{
			name:     "Redacted Secret String",
			content:  "Preview: AKIA************",
			filePath: "output.txt",
		},
	}

	for _, fp := range falsePositives {
		t.Run(fp.name, func(t *testing.T) {
			findings := scanner.ScanText(fp.filePath, fp.content)
			if len(findings) > 0 {
				t.Errorf("unexpected finding for false positive test '%s': %+v", fp.name, findings)
			}
		})
	}
}

func TestBinaryAndIgnoredPathFiltering(t *testing.T) {
	// Binary content check
	binaryData := []byte{0x7F, 0x45, 0x4C, 0x46, 0x00, 0x01, 0x01, 0x00}
	if !scanner.IsBinaryContent(binaryData) {
		t.Errorf("expected binary content detection for ELF header with null byte")
	}

	textData := []byte("plain text content without null bytes")
	if scanner.IsBinaryContent(textData) {
		t.Errorf("expected false for binary check on plain text")
	}

	// Ignored paths check
	if !scanner.ShouldSkipPath(".git/config") {
		t.Errorf("expected ShouldSkipPath true for .git/config")
	}
	if !scanner.ShouldSkipPath(".devvault/devvault.db") {
		t.Errorf("expected ShouldSkipPath true for devvault.db")
	}
	if scanner.ShouldSkipPath("src/main.go") {
		t.Errorf("expected ShouldSkipPath false for src/main.go")
	}
}

func TestInstallPreCommitHookIdempotency(t *testing.T) {
	tempDir := t.TempDir()
	gitHooks := filepath.Join(tempDir, ".git", "hooks")
	if err := os.MkdirAll(gitHooks, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Change working directory to temp git repo root
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// First installation
	if err := scanner.InstallPreCommitHook(); err != nil {
		t.Fatalf("InstallPreCommitHook failed: %v", err)
	}

	hookFile := filepath.Join(".git", "hooks", "pre-commit")
	content1, err := os.ReadFile(hookFile)
	if err != nil {
		t.Fatalf("ReadFile hook failed: %v", err)
	}

	// Second installation (idempotent run)
	if err := scanner.InstallPreCommitHook(); err != nil {
		t.Fatalf("InstallPreCommitHook second run failed: %v", err)
	}

	content2, err := os.ReadFile(hookFile)
	if err != nil {
		t.Fatalf("ReadFile hook second run failed: %v", err)
	}

	if string(content1) != string(content2) {
		t.Errorf("expected idempotent hook content, content changed after second run")
	}
}
