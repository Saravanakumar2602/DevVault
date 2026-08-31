package runner_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"devvault/internal/runner"
)

func TestRunnerEnvironmentInjection(t *testing.T) {
	r := runner.NewRunner()

	secretEnv := map[string]string{
		"DEVVAULT_TEST_SECRET_KEY": "SuperSecret123Value!",
	}

	var stdout, stderr bytes.Buffer

	// Use powershell on Windows or env/sh on Unix
	var cmdName string
	var args []string

	if os.Getenv("OS") == "Windows_NT" {
		cmdName = "powershell"
		args = []string{"-NoProfile", "-Command", "Write-Output $env:DEVVAULT_TEST_SECRET_KEY"}
	} else {
		cmdName = "sh"
		args = []string{"-c", "echo $DEVVAULT_TEST_SECRET_KEY"}
	}

	exitCode, err := r.Run(context.Background(), cmdName, args, secretEnv, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("Run failed: %v, stderr: %s", err, stderr.String())
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := strings.TrimSpace(stdout.String())
	if output != "SuperSecret123Value!" {
		t.Errorf("expected stdout 'SuperSecret123Value!', got '%s'", output)
	}
}
