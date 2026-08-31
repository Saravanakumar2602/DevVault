package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"devvault/internal/config"
)

func TestGetConfigDir(t *testing.T) {
	dir, err := config.GetConfigDir()
	if err != nil {
		t.Fatalf("GetConfigDir failed: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat config dir failed: %v", err)
	}

	if !info.IsDir() {
		t.Errorf("expected config path to be a directory")
	}
}

func TestGetDBPath(t *testing.T) {
	dbPath, err := config.GetDBPath()
	if err != nil {
		t.Fatalf("GetDBPath failed: %v", err)
	}

	if filepath.Base(dbPath) != config.DBFileName {
		t.Errorf("expected DB filename %s, got %s", config.DBFileName, filepath.Base(dbPath))
	}
}

func TestConfigSaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("APPDATA", tempDir)
	t.Setenv("XDG_CONFIG_HOME", tempDir)
	t.Setenv("HOME", tempDir)

	cfg := &config.AppConfig{
		ActiveProfile: "staging",
	}

	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.ActiveProfile != "staging" {
		t.Errorf("expected active profile 'staging', got '%s'", loaded.ActiveProfile)
	}
}
