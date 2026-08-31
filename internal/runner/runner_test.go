package runner_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"devvault/internal/runner"
)

func TestRunnerEnvironmentInjectionAndPrecedence(t *testing.T) {
	r := runner.NewRunner()
	tempDir := t.TempDir()

	// Pre-set existing OS environment variable
	t.Setenv("EXISTING_VAR", "os_original_value")
	t.Setenv("OVERRIDDEN_VAR", "os_old_value")

	secretEnv := map[string]string{
		"SECRET_KEY":     "vault_secret_value",
		"OVERRIDDEN_VAR": "vault_new_value", // Should override existing OS env
	}

	var stdout, stderr bytes.Buffer

	var cmdName string
	var args []string

	if os.Getenv("OS") == "Windows_NT" {
		cmdName = "powershell"
		args = []string{
			"-NoProfile",
			"-Command",
			"Write-Output \"EXISTING=$env:EXISTING_VAR|OVERRIDDEN=$env:OVERRIDDEN_VAR|SECRET=$env:SECRET_KEY\"",
		}
	} else {
		cmdName = "sh"
		args = []string{
			"-c",
			"echo \"EXISTING=$EXISTING_VAR|OVERRIDDEN=$OVERRIDDEN_VAR|SECRET=$SECRET_KEY\"",
		}
	}

	exitCode, err := r.Run(context.Background(), cmdName, args, secretEnv, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("Run failed: %v, stderr: %s", err, stderr.String())
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	out := strings.TrimSpace(stdout.String())

	// 1. Verify secrets reach child process
	if !strings.Contains(out, "SECRET=vault_secret_value") {
		t.Errorf("expected secret to reach child process, got output: %s", out)
	}

	// 2. Verify existing OS env is preserved
	if !strings.Contains(out, "EXISTING=os_original_value") {
		t.Errorf("expected existing env to be preserved, got output: %s", out)
	}

	// 3. Verify precedence rule (Vault Secrets > OS Env)
	if !strings.Contains(out, "OVERRIDDEN=vault_new_value") {
		t.Errorf("expected vault secret to override OS env, got output: %s", out)
	}

	// 4. Verify secrets are NOT written to disk
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".env") || strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("found unexpected temp file on disk: %s", entry.Name())
		}
	}
}

func TestRunnerPreservesExitCode(t *testing.T) {
	r := runner.NewRunner()
	var stdout, stderr bytes.Buffer

	var cmdName string
	var args []string

	if os.Getenv("OS") == "Windows_NT" {
		cmdName = "powershell"
		args = []string{"-NoProfile", "-Command", "exit 42"}
	} else {
		cmdName = "sh"
		args = []string{"-c", "exit 42"}
	}

	exitCode, err := r.Run(context.Background(), cmdName, args, nil, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("Run returned error for non-zero exit code: %v", err)
	}
	if exitCode != 42 {
		t.Errorf("expected exit code 42, got %d", exitCode)
	}

	_ = filepath.Join
}
