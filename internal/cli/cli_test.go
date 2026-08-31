package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"devvault/internal/cli"
)

func TestCLISecretCRUD(t *testing.T) {
	cli.ResetFlags()
	tempDir := t.TempDir()
	t.Setenv("APPDATA", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("HOME", tempDir)
	t.Setenv("DEVVAULT_MASTER_PASSWORD", "MasterSecret123!")

	buf := new(bytes.Buffer)
	cli.RootCmd.SetOut(buf)

	cli.RootCmd.SetArgs([]string{"init"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("cli init failed: %v", err)
	}

	buf.Reset()
	cli.RootCmd.SetArgs([]string{"set", "API_KEY", "sk_test_123456789"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("cli set failed: %v", err)
	}
	if !strings.Contains(buf.String(), "stored successfully") {
		t.Errorf("expected success message in set output, got: %s", buf.String())
	}

	buf.Reset()
	cli.RootCmd.SetArgs([]string{"get", "API_KEY"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("cli get failed: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "sk_test_123456789" {
		t.Errorf("expected get output 'sk_test_123456789', got '%s'", buf.String())
	}

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

	buf.Reset()
	cli.RootCmd.SetArgs([]string{"delete", "API_KEY", "--force"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("cli delete failed: %v", err)
	}
	if !strings.Contains(buf.String(), "deleted") {
		t.Errorf("expected deletion message in delete output, got: %s", buf.String())
	}
}

func TestCLIProfileManagementAndIsolation(t *testing.T) {
	cli.ResetFlags()
	tempDir := t.TempDir()
	t.Setenv("APPDATA", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("HOME", tempDir)
	t.Setenv("DEVVAULT_MASTER_PASSWORD", "MasterSecret123!")

	buf := new(bytes.Buffer)
	cli.RootCmd.SetOut(buf)

	cli.RootCmd.SetArgs([]string{"init"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

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

	buf.Reset()
	cli.RootCmd.SetArgs([]string{"profile", "use", "development"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile use development failed: %v", err)
	}

	buf.Reset()
	cli.RootCmd.SetArgs([]string{"set", "DATABASE_URL", "postgres://localhost/dev_db"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("set in dev failed: %v", err)
	}

	buf.Reset()
	cli.RootCmd.SetArgs([]string{"profile", "use", "production"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile use production failed: %v", err)
	}

	buf.Reset()
	cli.RootCmd.SetArgs([]string{"set", "DATABASE_URL", "postgres://prod-cluster/prod_db"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("set in prod failed: %v", err)
	}

	buf.Reset()
	cli.RootCmd.SetArgs([]string{"get", "DATABASE_URL"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("get in prod failed: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "postgres://prod-cluster/prod_db" {
		t.Errorf("expected prod DB URL, got: %s", buf.String())
	}

	buf.Reset()
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"get", "DATABASE_URL", "--profile", "development"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("get in dev override failed: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "postgres://localhost/dev_db" {
		t.Errorf("expected dev DB URL, got: %s", buf.String())
	}

	buf.Reset()
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"profile", "list"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile list failed: %v", err)
	}
	if !strings.Contains(buf.String(), "* production") {
		t.Errorf("expected active profile marker for production in profile list: %s", buf.String())
	}

	buf.Reset()
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"profile", "delete", "production", "--force"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("profile delete failed: %v", err)
	}
}

func TestEncryptedExportAndImportLifecycle(t *testing.T) {
	cli.ResetFlags()
	tempDir := t.TempDir()
	t.Setenv("APPDATA", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("HOME", tempDir)
	t.Setenv("DEVVAULT_MASTER_PASSWORD", "MasterSecret123!")
	t.Setenv("DEVVAULT_BACKUP_PASSPHRASE", "ExportPassphrase456!")

	backupFile := filepath.Join(tempDir, "backup.dv")

	buf := new(bytes.Buffer)
	cli.RootCmd.SetOut(buf)

	// 1. Initialize & populate vault
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"init"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	buf.Reset()
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"set", "STRIPE_SECRET", "sk_live_stripe999"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("set failed: %v", err)
	}

	// 2. Export with export passphrase
	buf.Reset()
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"export", backupFile})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	// Verify plaintext secret is NOT present in exported file
	fileContent, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatalf("ReadFile backup failed: %v", err)
	}
	if strings.Contains(string(fileContent), "sk_live_stripe999") {
		t.Errorf("SECURITY RISK: Plaintext secret found in export file!")
	}

	// 3. Dry-Run Import Validation
	buf.Reset()
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"import", backupFile, "--dry-run"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("import --dry-run failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Dry-Run") {
		t.Errorf("expected dry-run validation message, got: %s", buf.String())
	}

	// 4. Import into fresh vault instance
	freshDir := t.TempDir()
	t.Setenv("APPDATA", freshDir)
	t.Setenv("XDG_CONFIG_HOME", freshDir)
	t.Setenv("HOME", freshDir)
	t.Setenv("DEVVAULT_MASTER_PASSWORD", "FreshMasterSecret123!")

	buf.Reset()
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"init"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("fresh init failed: %v", err)
	}

	buf.Reset()
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"import", backupFile, "--force"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("import into fresh vault failed: %v, output: %s", err, buf.String())
	}

	// Verify imported secret value
	buf.Reset()
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"get", "STRIPE_SECRET"})
	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("get imported secret failed: %v, output: %s", err, buf.String())
	}
	if strings.TrimSpace(buf.String()) != "sk_live_stripe999" {
		t.Errorf("expected imported secret value 'sk_live_stripe999', got: '%s'", buf.String())
	}
}

func TestBackupCorruptedAndIncompatibleVersion(t *testing.T) {
	cli.ResetFlags()
	tempDir := t.TempDir()
	t.Setenv("APPDATA", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("HOME", tempDir)

	buf := new(bytes.Buffer)
	cli.RootCmd.SetOut(buf)

	// 1. Incompatible Version Test
	incompatibleFile := filepath.Join(tempDir, "bad_version.dv")
	os.WriteFile(incompatibleFile, []byte(`{"version": "99.0", "payload": "abc"}`), 0600)

	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"import", incompatibleFile})
	err := cli.RootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "incompatible backup format version") {
		t.Errorf("expected incompatible version error, got %v", err)
	}

	// 2. Corrupted Tampered Ciphertext Test
	corruptedFile := filepath.Join(tempDir, "corrupted.dv")
	corruptedJSON := `{
		"version": "1.0",
		"kdf": {"algorithm": "Argon2id", "salt": "AAAA", "time": 3, "memory": 65536, "threads": 4},
		"cipher": {"algorithm": "AES-256-GCM", "nonce": "AAAA"},
		"payload": "TAMPERED_CIPHERTEXT"
	}`
	os.WriteFile(corruptedFile, []byte(corruptedJSON), 0600)

	t.Setenv("DEVVAULT_BACKUP_PASSPHRASE", "WrongPassphrase!")
	cli.ResetFlags()
	cli.RootCmd.SetArgs([]string{"import", corruptedFile})
	err = cli.RootCmd.Execute()
	if err == nil {
		t.Errorf("expected error when importing corrupted backup, got nil")
	}
}
