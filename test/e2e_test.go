package test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndToEndCLIFlow(t *testing.T) {
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "devvault.exe")
	dbPath := filepath.Join(tempDir, "devvault", "devvault.db")

	// Compile devvault binary
	buildCmd := exec.Command("go", "build", "-o", binPath, "../cmd/devvault")
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v, output: %s", err, string(out))
	}

	masterPass := "TestMasterSecret123!"

	runCLI := func(args ...string) (string, error) {
		cmd := exec.Command(binPath, args...)
		cmd.Env = append(os.Environ(),
			"DEVVAULT_MASTER_PASSWORD="+masterPass,
			"APPDATA="+tempDir,
			"XDG_CONFIG_HOME="+tempDir,
			"HOME="+tempDir,
			"USERPROFILE="+tempDir,
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		combined := stdout.String() + stderr.String()
		return combined, err
	}

	// 1. Initialize Vault
	out, err := runCLI("init")
	if err != nil {
		t.Fatalf("devvault init failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "DevVault successfully initialized") {
		t.Errorf("unexpected init output: %s", out)
	}

	// 2. Set Secret
	out, err = runCLI("set", "API_KEY", "sk_test_998877665544332211")
	if err != nil {
		t.Fatalf("devvault set failed: %v, output: %s", err, out)
	}

	// 3. Get Secret
	out, err = runCLI("get", "API_KEY")
	if err != nil {
		t.Fatalf("devvault get failed: %v, output: %s", err, out)
	}
	if strings.TrimSpace(out) != "sk_test_998877665544332211" {
		t.Errorf("expected get output 'sk_test_998877665544332211', got '%s'", out)
	}

	// 4. List Secrets (Values must NOT be in output)
	out, err = runCLI("list")
	if err != nil {
		t.Fatalf("devvault list failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "API_KEY") {
		t.Errorf("expected list output to contain API_KEY: %s", out)
	}

	// 5. Profile Create & Use
	out, err = runCLI("profile", "create", "production", "Prod environment")
	if err != nil {
		t.Fatalf("devvault profile create failed: %v, output: %s", err, out)
	}

	out, err = runCLI("profile", "use", "production")
	if err != nil {
		t.Fatalf("devvault profile use failed: %v, output: %s", err, out)
	}

	// Set Secret in Production Profile
	out, err = runCLI("set", "DB_HOST", "prod-db.internal.net")
	if err != nil {
		t.Fatalf("devvault set in prod failed: %v, output: %s", err, out)
	}

	// 6. Test devvault run -- command
	var subCmd string
	var subArgs []string
	if os.Getenv("OS") == "Windows_NT" {
		subCmd = "powershell"
		subArgs = []string{"-NoProfile", "-Command", "Write-Output $env:DB_HOST"}
	} else {
		subCmd = "sh"
		subArgs = []string{"-c", "echo $DB_HOST"}
	}

	runArgs := append([]string{"run", "--", subCmd}, subArgs...)
	out, err = runCLI(runArgs...)
	if err != nil {
		t.Fatalf("devvault run failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "prod-db.internal.net") {
		t.Errorf("expected injected DB_HOST 'prod-db.internal.net', got '%s'", out)
	}

	// 7. Delete Secret with --force
	out, err = runCLI("delete", "DB_HOST", "--force")
	if err != nil {
		t.Fatalf("devvault delete failed: %v, output: %s", err, out)
	}

	_ = dbPath
	_ = context.Background()
}
