package scanner_test

import (
	"testing"

	"devvault/internal/scanner"
)

func TestScanTextAWSKey(t *testing.T) {
	text := `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`
	findings := scanner.ScanText("config.py", text)

	if len(findings) == 0 {
		t.Fatalf("expected finding for AWS Access Key, got none")
	}

	if findings[0].Rule != "AWS Access Key ID" {
		t.Errorf("expected rule 'AWS Access Key ID', got '%s'", findings[0].Rule)
	}
}

func TestScanTextJWT(t *testing.T) {
	text := `var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
	findings := scanner.ScanText("app.js", text)

	if len(findings) == 0 {
		t.Fatalf("expected finding for JWT, got none")
	}
}

func TestEntropyCalculation(t *testing.T) {
	// Low entropy
	low := scanner.CalculateEntropy("aaaaaaaaaaaaaaaaaaaa")
	if low != 0.0 {
		t.Errorf("expected entropy 0.0 for uniform string, got %f", low)
	}

	// High entropy
	high := scanner.CalculateEntropy("8f4k29mZpQ1xW7vT3yN6L0bC5aE9rU8o")
	if high < 4.5 {
		t.Errorf("expected high entropy (>4.5), got %f", high)
	}
}
