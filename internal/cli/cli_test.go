package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"devvault/internal/cli"
)

func TestCLISecretCRUD(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("APPDATA", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("HOME", tempDir)
	t.Setenv("DEVVAULT_MASTER_PASSWORD", "MasterSecret123!")

	// 1. Initialize vault
	buf := new(bytes.Buffer)
	cli.RootCmd.SetOut(buf)
	cli.RootCmd.SetArgs([]string{"init"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("cli init failed: %v", err)
	}

	// 2. Set secret
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"set", "API_KEY", "sk_test_123456789"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("cli set failed: %v", err)
	}
	if !strings.Contains(buf.String(), "stored successfully") {
		t.Errorf("expected success message in set output, got: %s", buf.String())
	}

	// 3. Get secret
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"get", "API_KEY"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("cli get failed: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "sk_test_123456789" {
		t.Errorf("expected get output 'sk_test_123456789', got '%s'", buf.String())
	}

	// 4. List secrets (Values must NEVER be displayed)
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"list"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("cli list failed: %v", err)
	}
	listOutput := buf.String()
	if !strings.Contains(listOutput, "API_KEY") {
		t.Errorf("expected list to display API_KEY, got: %s", listOutput)
	}
	if strings.Contains(listOutput, "sk_test_123456789") {
		t.Errorf("SECURITY RISK: list output contained secret value!")
	}

	// 5. Delete secret with --force flag
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"delete", "API_KEY", "--force"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("cli delete failed: %v", err)
	}
	if !strings.Contains(buf.String(), "deleted") {
		t.Errorf("expected deletion message in delete output, got: %s", buf.String())
	}
}
