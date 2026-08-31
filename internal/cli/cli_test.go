package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"devvault/internal/cli"
)

func TestVersionCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	cli.RootCmd.SetOut(buf)
	cli.RootCmd.SetArgs([]string{"version"})

	err := cli.RootCmd.Execute()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, cli.Version) {
		t.Errorf("expected version output to contain %s, got %s", cli.Version, output)
	}
}

func TestInitCommandNonInteractive(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("APPDATA", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("HOME", tempDir)
	t.Setenv("DEVVAULT_MASTER_PASSWORD", "SuperSecretPass123!")

	buf := new(bytes.Buffer)
	cli.RootCmd.SetOut(buf)
	cli.RootCmd.SetArgs([]string{"init"})

	err := cli.RootCmd.Execute()
	if err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "DevVault successfully initialized") {
		t.Errorf("expected success message in init output, got: %s", output)
	}

	// Verify database file creation
	appDir := filepath.Join(tempDir, "devvault")
	dbFile := filepath.Join(appDir, "devvault.db")

	info, err := os.Stat(dbFile)
	if err != nil {
		t.Fatalf("database file missing: %v", err)
	}

	if info.Size() == 0 {
		t.Errorf("expected non-empty database file")
	}
}
