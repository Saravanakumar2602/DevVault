package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"devvault/internal/cli"
)

func TestCLIProfileManagementAndIsolation(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("APPDATA", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("HOME", tempDir)
	t.Setenv("DEVVAULT_MASTER_PASSWORD", "MasterSecret123!")

	buf := new(bytes.Buffer)
	cli.RootCmd.SetOut(buf)

	// 1. Initialize vault
	cli.RootCmd.SetArgs([]string{"init"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// 2. Create profiles
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"profile", "create", "development", "Dev Scope"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile create development failed: %v", err)
	}

	buf.Reset()
	cli.RootCmd.SetArgs([]string{"profile", "create", "production", "Prod Scope"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile create production failed: %v", err)
	}

	// 3. Switch active profile to development
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"profile", "use", "development"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile use development failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Switched active profile to 'development'") {
		t.Errorf("unexpected output from profile use: %s", buf.String())
	}

	// 4. Set DATABASE_URL in development profile
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"set", "DATABASE_URL", "postgres://localhost/dev_db"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("set in dev failed: %v", err)
	}

	// 5. Switch active profile to production
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"profile", "use", "production"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile use production failed: %v", err)
	}

	// Set DATABASE_URL in production profile
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"set", "DATABASE_URL", "postgres://prod-cluster/prod_db"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("set in prod failed: %v", err)
	}

	// 6. Verify Secret Isolation via CLI
	// Get in production profile
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"get", "DATABASE_URL"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("get in prod failed: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "postgres://prod-cluster/prod_db" {
		t.Errorf("expected prod DB URL, got: %s", buf.String())
	}

	// Get in development profile via --profile flag override
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"get", "DATABASE_URL", "--profile", "development"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("get in dev override failed: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "postgres://localhost/dev_db" {
		t.Errorf("expected dev DB URL, got: %s", buf.String())
	}

	// 7. Profile listing output contains active marker
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"profile", "list", "--profile", ""})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile list failed: %v", err)
	}
	if !strings.Contains(buf.String(), "* production") {
		t.Errorf("expected active profile marker for production in profile list: %s", buf.String())
	}

	// 8. Delete active profile with --force
	buf.Reset()
	cli.RootCmd.SetArgs([]string{"profile", "delete", "production", "--force"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile delete failed: %v", err)
	}
	if !strings.Contains(buf.String(), "deleted") {
		t.Errorf("expected deletion message, got: %s", buf.String())
	}
}
